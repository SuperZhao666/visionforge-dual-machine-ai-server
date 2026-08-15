"""Rewrite a row-oriented YOLOX detector for stable QNN quantization.

The source detector decodes boxes through a dynamic ``Range``/``ScatterND``
tail and then mixes pixel coordinates with probabilities in one tensor. QNN
W8A16 assigns that mixed tensor one 0..414 quantization domain, which destroys
confidence precision. This adapter branches from the raw detector tensor and
performs the equivalent decode with static grid/stride constants. The mobile
runtime contract remains two FP32 outputs: coordinates and confidences.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, checker, helper, numpy_helper, shape_inference


COORDINATE_OUTPUT = "output_coordinates"
CONFIDENCE_OUTPUT = "output_confidences"
FORBIDDEN_DYNAMIC_DECODE_OPS = frozenset({"Range", "ScatterND"})


@dataclass(frozen=True, slots=True)
class StaticDecodeContract:
    raw_tensor: str
    anchors: int
    classes: int
    model_size: int
    strides: tuple[int, ...]


def static_yolox_grid(
    model_size: int,
    strides: Sequence[int],
) -> tuple[np.ndarray, np.ndarray]:
    """Return YOLOX grid and per-anchor stride tensors in detector row order."""
    if model_size <= 0 or not strides:
        raise ValueError("model_size and strides must be positive")
    grids: list[np.ndarray] = []
    stride_rows: list[np.ndarray] = []
    for stride in strides:
        if stride <= 0 or model_size % stride != 0:
            raise ValueError("Every stride must be a positive divisor of model_size")
        side = model_size // stride
        grid_y, grid_x = np.meshgrid(
            np.arange(side, dtype=np.float32),
            np.arange(side, dtype=np.float32),
            indexing="ij",
        )
        grids.append(np.stack((grid_x, grid_y), axis=-1).reshape(-1, 2))
        stride_rows.append(np.full((side * side, 1), stride, dtype=np.float32))
    return (
        np.concatenate(grids, axis=0)[None, ...],
        np.concatenate(stride_rows, axis=0)[None, ...],
    )


def _int64_initializer(name: str, values: Sequence[int]) -> onnx.TensorProto:
    return numpy_helper.from_array(np.asarray(values, dtype=np.int64), name=name)


def _static_tensor_shape(
    model: onnx.ModelProto,
    tensor_name: str,
) -> tuple[int, ...] | None:
    inferred = shape_inference.infer_shapes(model)
    value_infos = (
        list(inferred.graph.input)
        + list(inferred.graph.output)
        + list(inferred.graph.value_info)
    )
    value_info = next((value for value in value_infos if value.name == tensor_name), None)
    if value_info is None:
        raise ValueError(f"Tensor shape is unavailable: {tensor_name}")
    dimensions = value_info.type.tensor_type.shape.dim
    if not dimensions:
        return None
    if any(not dimension.HasField("dim_value") for dimension in dimensions):
        raise ValueError(f"Tensor must have a static shape: {tensor_name}")
    return tuple(int(dimension.dim_value) for dimension in dimensions)


def _static_graph_output_shape(model: onnx.ModelProto) -> tuple[int, ...]:
    if len(model.graph.output) != 1:
        raise ValueError("Expected exactly one source detector output")
    dimensions = model.graph.output[0].type.tensor_type.shape.dim
    if not dimensions or any(
        not dimension.HasField("dim_value") for dimension in dimensions
    ):
        raise ValueError("Source detector output must have a static shape")
    return tuple(int(dimension.dim_value) for dimension in dimensions)


def _annotate_raw_tensor_shape(
    model: onnx.ModelProto,
    raw_tensor: str,
    expected_shape: tuple[int, ...],
) -> None:
    retained = [value for value in model.graph.value_info if value.name != raw_tensor]
    del model.graph.value_info[:]
    model.graph.value_info.extend(retained)
    model.graph.value_info.append(
        helper.make_tensor_value_info(raw_tensor, TensorProto.FLOAT, expected_shape)
    )


def _prune_graph_to_outputs(model: onnx.ModelProto) -> None:
    required_tensors = {output.name for output in model.graph.output}
    required_nodes: list[onnx.NodeProto] = []
    for node in reversed(model.graph.node):
        if required_tensors.intersection(node.output):
            required_nodes.append(node)
            required_tensors.update(value for value in node.input if value)
    required_nodes.reverse()
    del model.graph.node[:]
    model.graph.node.extend(required_nodes)

    kept_initializers = [
        initializer
        for initializer in model.graph.initializer
        if initializer.name in required_tensors
    ]
    del model.graph.initializer[:]
    model.graph.initializer.extend(kept_initializers)

    initializer_names = {initializer.name for initializer in kept_initializers}
    kept_inputs = [
        graph_input
        for graph_input in model.graph.input
        if graph_input.name in required_tensors
        and graph_input.name not in initializer_names
    ]
    del model.graph.input[:]
    model.graph.input.extend(kept_inputs)

    kept_value_info = [
        value_info
        for value_info in model.graph.value_info
        if value_info.name in required_tensors
    ]
    del model.graph.value_info[:]
    model.graph.value_info.extend(kept_value_info)


def _replace_outputs(
    model: onnx.ModelProto,
    nodes: Sequence[onnx.NodeProto],
    initializers: Sequence[onnx.TensorProto],
    *,
    anchors: int,
    classes: int,
) -> None:
    model.graph.node.extend(nodes)
    model.graph.initializer.extend(initializers)
    del model.graph.output[:]
    model.graph.output.extend(
        [
            helper.make_tensor_value_info(
                COORDINATE_OUTPUT,
                TensorProto.FLOAT,
                [1, 4, anchors],
            ),
            helper.make_tensor_value_info(
                CONFIDENCE_OUTPUT,
                TensorProto.FLOAT,
                [1, classes, anchors],
            ),
        ]
    )


def _static_decode_nodes(
    raw_tensor: str,
    *,
    classes: int,
) -> tuple[list[onnx.NodeProto], list[onnx.TensorProto]]:
    axes = "vf_static_axes"
    steps = "vf_static_steps"
    starts_0 = "vf_static_starts_0"
    starts_2 = "vf_static_starts_2"
    starts_4 = "vf_static_starts_4"
    starts_5 = "vf_static_starts_5"
    ends_2 = "vf_static_ends_2"
    ends_4 = "vf_static_ends_4"
    ends_5 = "vf_static_ends_5"
    ends_classes = "vf_static_ends_classes"
    initializers = [
        _int64_initializer(axes, [2]),
        _int64_initializer(steps, [1]),
        _int64_initializer(starts_0, [0]),
        _int64_initializer(starts_2, [2]),
        _int64_initializer(starts_4, [4]),
        _int64_initializer(starts_5, [5]),
        _int64_initializer(ends_2, [2]),
        _int64_initializer(ends_4, [4]),
        _int64_initializer(ends_5, [5]),
        _int64_initializer(ends_classes, [5 + classes]),
    ]
    nodes = [
        helper.make_node(
            "Slice",
            [raw_tensor, starts_0, ends_2, axes, steps],
            ["vf_static_raw_xy"],
            name="VisionForgeStaticSliceXY",
        ),
        helper.make_node(
            "Slice",
            [raw_tensor, starts_2, ends_4, axes, steps],
            ["vf_static_raw_wh"],
            name="VisionForgeStaticSliceWH",
        ),
        helper.make_node(
            "Slice",
            [raw_tensor, starts_4, ends_5, axes, steps],
            ["vf_static_objectness"],
            name="VisionForgeStaticSliceObjectness",
        ),
        helper.make_node(
            "Slice",
            [raw_tensor, starts_5, ends_classes, axes, steps],
            ["vf_static_classes"],
            name="VisionForgeStaticSliceClasses",
        ),
        helper.make_node(
            "Add",
            ["vf_static_raw_xy", "vf_static_grid"],
            ["vf_static_xy_with_grid"],
            name="VisionForgeStaticAddGrid",
        ),
        helper.make_node(
            "Mul",
            ["vf_static_xy_with_grid", "vf_static_strides"],
            ["vf_static_decoded_xy"],
            name="VisionForgeStaticScaleXY",
        ),
        helper.make_node(
            "Exp",
            ["vf_static_raw_wh"],
            ["vf_static_exp_wh"],
            name="VisionForgeStaticExpWH",
        ),
        helper.make_node(
            "Mul",
            ["vf_static_exp_wh", "vf_static_strides"],
            ["vf_static_decoded_wh"],
            name="VisionForgeStaticScaleWH",
        ),
        helper.make_node(
            "Concat",
            ["vf_static_decoded_xy", "vf_static_decoded_wh"],
            ["vf_static_coordinate_rows"],
            name="VisionForgeStaticCoordinates",
            axis=2,
        ),
        helper.make_node(
            "Mul",
            ["vf_static_objectness", "vf_static_classes"],
            ["vf_static_confidence_rows"],
            name="VisionForgeStaticFuseObjectness",
        ),
        helper.make_node(
            "Transpose",
            ["vf_static_coordinate_rows"],
            [COORDINATE_OUTPUT],
            name="VisionForgeStaticTransposeCoordinates",
            perm=[0, 2, 1],
        ),
        helper.make_node(
            "Transpose",
            ["vf_static_confidence_rows"],
            [CONFIDENCE_OUTPUT],
            name="VisionForgeStaticTransposeConfidences",
            perm=[0, 2, 1],
        ),
    ]
    return nodes, initializers


def create_static_decode_split_model(
    source: Path,
    destination: Path,
    *,
    raw_tensor: str,
    classes: int,
    model_size: int,
    strides: Sequence[int],
) -> StaticDecodeContract:
    """Create the exact static decode graph and return its explicit contract."""
    if not raw_tensor:
        raise ValueError("raw_tensor is required")
    if classes <= 0:
        raise ValueError("classes must be positive")
    normalized_strides = tuple(int(stride) for stride in strides)
    grid, stride_rows = static_yolox_grid(model_size, normalized_strides)
    anchors = int(grid.shape[1])

    model = onnx.load(source)
    node_outputs = {output for node in model.graph.node for output in node.output}
    if raw_tensor not in node_outputs:
        raise ValueError(f"Raw detector tensor is missing: {raw_tensor}")
    raw_shape = _static_tensor_shape(model, raw_tensor)
    expected_shape = (1, anchors, 5 + classes)
    producer = next(
        node for node in model.graph.node if raw_tensor in node.output
    )
    transpose_permutation = next(
        (
            tuple(attribute.ints)
            for attribute in producer.attribute
            if attribute.name == "perm"
        ),
        (),
    )
    if producer.op_type != "Transpose" or transpose_permutation != (0, 2, 1):
        raise ValueError(
            f"Raw detector tensor {raw_tensor} must be produced by "
            "Transpose perm=[0,2,1]"
        )
    if _static_graph_output_shape(model) != expected_shape:
        raise ValueError(
            f"Source detector output must have shape {expected_shape}"
        )
    if raw_shape is not None and raw_shape != expected_shape:
        raise ValueError(
            f"Raw detector tensor {raw_tensor} has shape {raw_shape}; "
            f"expected {expected_shape}"
        )
    if raw_shape is None:
        _annotate_raw_tensor_shape(model, raw_tensor, expected_shape)

    nodes, initializers = _static_decode_nodes(raw_tensor, classes=classes)
    initializers.extend(
        [
            numpy_helper.from_array(grid, name="vf_static_grid"),
            numpy_helper.from_array(stride_rows, name="vf_static_strides"),
        ]
    )
    _replace_outputs(
        model,
        nodes,
        initializers,
        anchors=anchors,
        classes=classes,
    )
    _prune_graph_to_outputs(model)

    forbidden = sorted(
        {node.op_type for node in model.graph.node} & FORBIDDEN_DYNAMIC_DECODE_OPS
    )
    if forbidden:
        raise ValueError(
            "Static decode graph still contains forbidden dynamic operators: "
            + ", ".join(forbidden)
        )
    model.producer_name = "VisionForge QNN static YOLOX adapter"
    model.producer_version = "2"
    model.graph.doc_string = (
        "VisionForge static YOLOX decode: raw [tx,ty,tw,th,obj,classes], "
        "xy=(raw+grid)*stride, wh=exp(raw)*stride, conf=obj*classes"
    )
    checker.check_model(model)
    inferred = shape_inference.infer_shapes(model)
    checker.check_model(inferred)
    destination.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(inferred, destination)
    return StaticDecodeContract(
        raw_tensor=raw_tensor,
        anchors=anchors,
        classes=classes,
        model_size=model_size,
        strides=normalized_strides,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an exact static YOLOX decode for QNN W8A16."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--raw-tensor", required=True)
    parser.add_argument("--classes", type=int, required=True)
    parser.add_argument("--model-size", type=int, required=True)
    parser.add_argument("--strides", type=int, nargs="+", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    contract = create_static_decode_split_model(
        arguments.source,
        arguments.destination,
        raw_tensor=arguments.raw_tensor,
        classes=arguments.classes,
        model_size=arguments.model_size,
        strides=arguments.strides,
    )
    print(
        "QNN_STATIC_SPLIT_OUTPUT_MODEL_OK "
        f"path={arguments.destination.resolve()} "
        f"raw_tensor={contract.raw_tensor} anchors={contract.anchors} "
        f"classes={contract.classes} model_size={contract.model_size} "
        f"strides={','.join(stride.__str__() for stride in contract.strides)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
