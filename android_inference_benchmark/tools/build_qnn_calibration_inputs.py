"""Build representative FP32 calibration tensors for an Android QNN-HTP model.

The selected model consumes a static square RGB NCHW tensor. QNN quantization
must use tensors created by the same letterbox/normalization path as realtime
inference; random tensors would make its ranges meaningless.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import cv2
import numpy as np


LETTERBOX_COLOR = (114, 114, 114)


def letterbox_rgb_nchw(image_bgr: np.ndarray, model_size: int) -> np.ndarray:
    """Build a square RGB NCHW tensor matching the selected model input."""
    source_height, source_width = image_bgr.shape[:2]
    scale = min(model_size / source_width, model_size / source_height)
    resized_width = max(1, int(round(source_width * scale)))
    resized_height = max(1, int(round(source_height * scale)))
    resized = cv2.resize(image_bgr, (resized_width, resized_height), interpolation=cv2.INTER_LINEAR)
    canvas = np.full((model_size, model_size, 3), LETTERBOX_COLOR, dtype=np.uint8)
    offset_x = (model_size - resized_width) // 2
    offset_y = (model_size - resized_height) // 2
    canvas[offset_y : offset_y + resized_height, offset_x : offset_x + resized_width] = resized
    rgb = cv2.cvtColor(canvas, cv2.COLOR_BGR2RGB).astype(np.float32) / 255.0
    return np.transpose(rgb, (2, 0, 1))[None, ...]


def collect_images(source: Path, limit: int) -> list[Path]:
    cropped_frames = sorted(source.glob("crop_frame_*"))
    if cropped_frames:
        return cropped_frames[:limit]
    patterns = ("*.jpg", "*.jpeg", "*.png")
    images = sorted(path for pattern in patterns for path in source.rglob(pattern))
    if not images:
        raise FileNotFoundError(f"No calibration images found under {source}")
    return images[:limit]


def write_inputs(images: list[Path], output: Path, model_size: int) -> None:
    raw_directory = output / "raw"
    raw_directory.mkdir(parents=True, exist_ok=True)
    list_lines: list[str] = []
    manifest_lines = ["source_image,raw_tensor,shape,dtype"]
    for index, image_path in enumerate(images):
        image = cv2.imdecode(np.fromfile(image_path, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            raise ValueError(f"Failed to decode calibration image: {image_path}")
        tensor = letterbox_rgb_nchw(image, model_size)
        raw_path = raw_directory / f"input_{index:04d}.raw"
        tensor.astype(np.float32, copy=False).tofile(raw_path)
        list_lines.append(f"images:={raw_path.resolve()}")
        manifest_lines.append(
            f"{image_path.resolve()},{raw_path.resolve()},1x3x{model_size}x{model_size},float32"
        )
    (output / "input_list.txt").write_text("\n".join(list_lines) + "\n", encoding="utf-8")
    (output / "manifest.csv").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("analysis_output/video_1784130488633_166"),
        help="Directory containing representative gameplay frames.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("android_inference_benchmark/qnn_workspace/calibration"),
        help="Destination for raw tensors and QNN input list.",
    )
    parser.add_argument("--limit", type=int, default=80, help="Maximum number of source images.")
    parser.add_argument("--model-size", type=int, default=320, help="Static square model input size.")
    args = parser.parse_args()
    if args.limit <= 0:
        raise ValueError("--limit must be positive")
    if args.model_size <= 0 or args.model_size % 32 != 0:
        raise ValueError("--model-size must be a positive multiple of 32")
    images = collect_images(args.source, args.limit)
    write_inputs(images, args.output, args.model_size)
    print(f"QNN_CALIBRATION_INPUTS_OK count={len(images)} output={args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
