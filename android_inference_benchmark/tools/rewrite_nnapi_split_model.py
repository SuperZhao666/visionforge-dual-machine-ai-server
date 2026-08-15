"""Replace static Split nodes with equivalent Slice nodes for ORT NNAPI parsing."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import onnx
from onnx import helper, numpy_helper


def rewrite_static_splits(source: Path, destination: Path) -> int:
    model = onnx.load(source, load_external_data=False)
    initializer_values = {
        initializer.name: numpy_helper.to_array(initializer)
        for initializer in model.graph.initializer
    }
    rewritten_nodes: list[onnx.NodeProto] = []
    generated_initializers: list[onnx.TensorProto] = []
    replaced_outputs = 0

    for node_index, node in enumerate(model.graph.node):
        split_lengths = initializer_values.get(node.input[1]) if node.op_type == "Split" and len(node.input) >= 2 else None
        if split_lengths is None:
            rewritten_nodes.append(node)
            continue

        lengths = [int(value) for value in split_lengths.reshape(-1)]
        axis = next((int(attribute.i) for attribute in node.attribute if attribute.name == "axis"), 0)
        if len(lengths) != len(node.output) or any(length <= 0 for length in lengths):
            raise ValueError(f"Unsupported static Split node: {node.name}")

        start = 0
        for output_index, (length, output_name) in enumerate(zip(lengths, node.output)):
            prefix = f"visionforge_nnapi_split_{node_index}_{output_index}"
            slice_inputs = [node.input[0]]
            for suffix, values in {
                "starts": [start],
                "ends": [start + length],
                "axes": [axis],
                "steps": [1],
            }.items():
                tensor_name = f"{prefix}_{suffix}"
                generated_initializers.append(
                    numpy_helper.from_array(np.asarray(values, dtype=np.int64), name=tensor_name)
                )
                slice_inputs.append(tensor_name)
            rewritten_nodes.append(
                helper.make_node("Slice", slice_inputs, [output_name], name=f"{node.name}_slice_{output_index}")
            )
            start += length
            replaced_outputs += 1

    model.graph.ClearField("node")
    model.graph.node.extend(rewritten_nodes)
    model.graph.initializer.extend(generated_initializers)
    onnx.checker.check_model(model)
    onnx.save(model, destination)
    return replaced_outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    replaced_outputs = rewrite_static_splits(args.source, args.destination)
    print(f"rewrote {replaced_outputs} Split outputs: {args.destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
