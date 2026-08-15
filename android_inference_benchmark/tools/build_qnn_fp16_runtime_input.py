from __future__ import annotations

from pathlib import Path

import numpy as np


source = Path("android_inference_benchmark/qnn_workspace/calibration/raw/input_0000.raw")
destination = Path("android_inference_benchmark/qnn_workspace/runtime_input/images_fp16_nhwc.raw")
values = np.fromfile(source, dtype=np.float32)
if values.size != 1 * 3 * 320 * 320:
    raise ValueError(f"Unexpected FP32 calibration input length: {values.size}")
nhwc_fp16 = np.transpose(values.reshape(1, 3, 320, 320), (0, 2, 3, 1)).astype(np.float16)
destination.parent.mkdir(parents=True, exist_ok=True)
nhwc_fp16.tofile(destination)
expected = 1 * 320 * 320 * 3 * np.dtype(np.float16).itemsize
if destination.stat().st_size != expected:
    raise AssertionError(f"Unexpected output size: {destination.stat().st_size}")
print(f"QNN_FP16_RUNTIME_INPUT_OK path={destination.resolve()} bytes={expected}")
