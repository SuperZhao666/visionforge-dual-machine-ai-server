"""Expose separate YOLOv8 coordinate and confidence outputs for QNN.

Ultralytics detection exports concatenate decoded pixel coordinates and
sigmoid class probabilities into one tensor. A quantized backend can then
assign both value domains one activation encoding. This adapter removes only
that final mixed-domain Concat and publishes the two existing branches as
FP32 outputs expected by the mobile runtime.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import onnx
from onnx import TensorProto, checker, helper, shape_inference


COORDINATE_OUTPUT = "output_coordinates"
CONFIDENCE_OUTPUT = "output_confidences"
STANDARD_ONNX_DOMAINS = frozenset({"", "ai.onnx"})


@dataclass(frozen=True, slots=True)
class YoloV8SplitContract:
    anchors: int
    classes: int
    mixed_output: str
    coordinate_branch: str
    confidence_branch: str


def _static_shapes(model: onnx.ModelProto) -> dict[str, tuple[int, ...]]:
    inferred = shape_inference.infer_shapes(model)
    shapes: dict[str, tuple[int, ...]] = {}
    for value in (
        list(inferred.graph.input)
        + list(inferred.graph.value_info)
        + list(inferred.graph.output)
    ):
        dimensions = value.type.tensor_type.shape.dim
        if dimensions and all(dimension.HasField("dim_value") for dimension in dimensions):
            shapes[value.name] = tuple(int(dimension.dim_value) for dimension in dimensions)
    return shapes


def _attribute_int(node: onnx.NodeProto, name: str) -> int | None:
    attribute = next((item for item in node.attribute if item.name == name), None)
    return None if attribute is None else int(attribute.i)


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

    retained_initializers = [
        initializer
        for initializer in model.graph.initializer
        if initializer.name in required_tensors
    ]
    del model.graph.initializer[:]
    model.graph.initializer.extend(retained_initializers)

    initializer_names = {initializer.name for initializer in retained_initializers}
    retained_inputs = [
        graph_input
        for graph_input in model.graph.input
        if graph_input.name in required_tensors
        and graph_input.name not in initializer_names
    ]
    del model.graph.input[:]
    model.graph.input.extend(retained_inputs)

    retained_value_info = [
        value
        for value in model.graph.value_info
        if value.name in required_tensors
    ]
    del model.graph.value_info[:]
    model.graph.value_info.extend(retained_value_info)


def create_yolov8_split_output_model(
    source: Path,
    destination: Path,
    *,
    anchors: int,
    classes: int,
) -> YoloV8SplitContract:
    """Publish the two pre-Concat branches and return their explicit contract."""
    if anchors <= 0 or classes <= 0:
        raise ValueError("anchors and classes must be positive")
    model = onnx.load(source)
    if len(model.graph.output) != 1:
        raise ValueError("Expected exactly one mixed YOLOv8 detector output")
    output = model.graph.output[0]
    mixed_output = output.name
    shapes = _static_shapes(model)
    expected_mixed_shape = (1, 4 + classes, anchors)
    if shapes.get(mixed_output) != expected_mixed_shape:
        raise ValueError(
            f"Mixed detector output must have shape {expected_mixed_shape}; "
            f"got {shapes.get(mixed_output)}"
        )

    producer = next(
        (node for node in model.graph.node if mixed_output in node.output),
        None,
    )
    if producer is None or producer.op_type != "Concat":
        raise ValueError("Mixed detector output must be produced by Concat")
    if _attribute_int(producer, "axis") != 1 or len(producer.input) != 2:
        raise ValueError("Final detector Concat must join two branches on axis 1")

    coordinate_branch, confidence_branch = producer.input
    expected_coordinate_shape = (1, 4, anchors)
    expected_confidence_shape = (1, classes, anchors)
    if shapes.get(coordinate_branch) != expected_coordinate_shape:
        raise ValueError(
            f"Coordinate branch must have shape {expected_coordinate_shape}; "
            f"got {shapes.get(coordinate_branch)}"
        )
    if shapes.get(confidence_branch) != expected_confidence_shape:
        raise ValueError(
            f"Confidence branch must have shape {expected_confidence_shape}; "
            f"got {shapes.get(confidence_branch)}"
        )
    confidence_producer = next(
        (node for node in model.graph.node if confidence_branch in node.output),
        None,
    )
    if confidence_producer is None or confidence_producer.op_type != "Sigmoid":
        raise ValueError("Confidence branch must be produced directly by Sigmoid")

    custom_domains = sorted(
        {
            node.domain
            for node in model.graph.node
            if node.domain not in STANDARD_ONNX_DOMAINS
        }
    )
    if custom_domains:
        raise ValueError(
            "Custom operator domains are unsupported: " + ", ".join(custom_domains)
        )

    model.graph.node.extend(
        [
            helper.make_node(
                "Identity",
                [coordinate_branch],
                [COORDINATE_OUTPUT],
                name="VisionForgeYoloV8Coordinates",
            ),
            helper.make_node(
                "Identity",
                [confidence_branch],
                [CONFIDENCE_OUTPUT],
                name="VisionForgeYoloV8Confidences",
            ),
        ]
    )
    del model.graph.output[:]
    model.graph.output.extend(
        [
            helper.make_tensor_value_info(
                COORDINATE_OUTPUT,
                TensorProto.FLOAT,
                expected_coordinate_shape,
            ),
            helper.make_tensor_value_info(
                CONFIDENCE_OUTPUT,
                TensorProto.FLOAT,
                expected_confidence_shape,
            ),
        ]
    )
    _prune_graph_to_outputs(model)
    if any(mixed_output in node.output for node in model.graph.node):
        raise ValueError("Mixed-domain detector output was not pruned")

    model.producer_name = "VisionForge QNN YOLOv8 split-output adapter"
    model.producer_version = "1"
    model.graph.doc_string = (
        "VisionForge YOLOv8 split outputs: decoded xywh coordinates and "
        "sigmoid class confidences before the final mixed-domain Concat"
    )
    checker.check_model(model)
    inferred = shape_inference.infer_shapes(model)
    checker.check_model(inferred)
    destination.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(inferred, destination)
    return YoloV8SplitContract(
        anchors=anchors,
        classes=classes,
        mixed_output=mixed_output,
        coordinate_branch=coordinate_branch,
        confidence_branch=confidence_branch,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--anchors", type=int, required=True)
    parser.add_argument("--classes", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    contract = create_yolov8_split_output_model(
        arguments.source,
        arguments.destination,
        anchors=arguments.anchors,
        classes=arguments.classes,
    )
    print(
        "QNN_YOLOV8_SPLIT_OUTPUT_MODEL_OK "
        f"path={arguments.destination.resolve()} anchors={contract.anchors} "
        f"classes={contract.classes} mixed_output={contract.mixed_output} "
        f"coordinates={contract.coordinate_branch} "
        f"confidences={contract.confidence_branch}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
