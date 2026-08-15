from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np


INPUT_SHAPE_NCHW = (1, 3, 320, 320)
INPUT_SHAPE_NHWC = (1, 320, 320, 3)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert VisionForge FP32 NCHW calibration input to QNN UINT8 NHWC runtime input."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("android_inference_benchmark/qnn_workspace/calibration/raw/input_0000.raw"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("android_inference_benchmark/qnn_workspace/runtime_input/images_u8_nhwc.raw"),
    )
    return parser.parse_args()


def load_normalized_nchw(input_path: Path) -> np.ndarray:
    values = np.fromfile(input_path, dtype=np.float32)
    expected_values = int(np.prod(INPUT_SHAPE_NCHW))
    if values.size != expected_values:
        raise ValueError(
            f"Expected {expected_values} float32 values in {input_path}, got {values.size}."
        )
    if not np.isfinite(values).all() or values.min() < 0.0 or values.max() > 1.0:
        raise ValueError("Expected finite normalized RGB input values in the inclusive range [0, 1].")
    return values.reshape(INPUT_SHAPE_NCHW)


def main() -> None:
    args = parse_args()
    input_path = args.input.resolve()
    output_path = args.output.resolve()
    nchw = load_normalized_nchw(input_path)
    # The QNN converter lowered the graph input to NHWC UINT8 with scale 1/255.
    nhwc_u8 = np.rint(np.transpose(nchw, (0, 2, 3, 1)) * 255.0).astype(np.uint8)
    if nhwc_u8.shape != INPUT_SHAPE_NHWC:
        raise AssertionError(f"Unexpected converted input shape: {nhwc_u8.shape}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    nhwc_u8.tofile(output_path)
    if output_path.stat().st_size != int(np.prod(INPUT_SHAPE_NHWC)):
        raise AssertionError("QNN UINT8 runtime input has an unexpected byte size.")
    print(
        "QNN_RUNTIME_INPUT_OK"
        f" path={output_path}"
        f" shape={list(INPUT_SHAPE_NHWC)}"
        " dtype=uint8"
        f" bytes={output_path.stat().st_size}"
        f" range=[{int(nhwc_u8.min())},{int(nhwc_u8.max())}]"
    )


if __name__ == "__main__":
    main()
