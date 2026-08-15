"""Create and validate a calibrated QDQ INT8 candidate from VisionForge frames."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np
import onnxruntime as ort
from onnxruntime.quantization import CalibrationDataReader, CalibrationMethod, QuantFormat, QuantType, quantize_static


class CalibrationReader(CalibrationDataReader):
    def __init__(self, input_name: str, manifest: Path, limit: int, input_size: int) -> None:
        with manifest.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))[:limit]
        if not rows:
            raise ValueError(f"No calibration rows in {manifest}")
        self._input_name = input_name
        self._paths = [Path(row["raw_tensor"]) for row in rows]
        self._input_size = input_size
        self.rewind()

    def get_next(self) -> dict[str, np.ndarray] | None:
        if self._index >= len(self._paths):
            return None
        path = self._paths[self._index]
        self._index += 1
        tensor = np.fromfile(path, dtype=np.float32).reshape(
            1, 3, self._input_size, self._input_size
        )
        return {self._input_name: tensor}

    def rewind(self) -> None:
        self._index = 0


def sample_outputs(model: Path, samples: list[Path], input_size: int) -> list[np.ndarray]:
    session = ort.InferenceSession(str(model), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    outputs: list[np.ndarray] = []
    for sample in samples:
        tensor = np.fromfile(sample, dtype=np.float32).reshape(1, 3, input_size, input_size)
        outputs.append(session.run(None, {input_name: tensor})[0])
    return outputs


def validate(reference: Path, candidate: Path, manifest: Path, samples: int, input_size: int) -> None:
    with manifest.open(encoding="utf-8", newline="") as handle:
        raw_paths = [Path(row["raw_tensor"]) for row in list(csv.DictReader(handle))[:samples]]
    reference_outputs = sample_outputs(reference, raw_paths, input_size)
    candidate_outputs = sample_outputs(candidate, raw_paths, input_size)
    errors = [np.abs(reference - candidate) for reference, candidate in zip(reference_outputs, candidate_outputs)]
    reference_flat = np.concatenate([item.ravel() for item in reference_outputs])
    candidate_flat = np.concatenate([item.ravel() for item in candidate_outputs])
    cosine = float(np.dot(reference_flat, candidate_flat) / (np.linalg.norm(reference_flat) * np.linalg.norm(candidate_flat)))
    print(
        "QDQ_INT8_VALIDATION "
        f"samples={len(errors)} mean_abs={np.mean([error.mean() for error in errors]):.8f} "
        f"max_abs={max(float(error.max()) for error in errors):.8f} cosine={cosine:.8f}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("android_inference_benchmark/qnn_workspace/calibration/manifest.csv"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
    )
    parser.add_argument("--input-size", type=int, default=416)
    parser.add_argument("--calibration-samples", type=int, default=80)
    parser.add_argument("--validation-samples", type=int, default=16)
    args = parser.parse_args()
    if args.input_size <= 0 or args.input_size % 32 != 0:
        raise ValueError("--input-size must be a positive multiple of 32")
    source_session = ort.InferenceSession(str(args.model), providers=["CPUExecutionProvider"])
    input_name = source_session.get_inputs()[0].name
    reader = CalibrationReader(input_name, args.manifest, args.calibration_samples, args.input_size)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    quantize_static(
        model_input=str(args.model),
        model_output=str(args.output),
        calibration_data_reader=reader,
        quant_format=QuantFormat.QDQ,
        activation_type=QuantType.QUInt8,
        weight_type=QuantType.QInt8,
        per_channel=True,
        calibrate_method=CalibrationMethod.MinMax,
        extra_options={"ActivationSymmetric": False, "WeightSymmetric": True},
    )
    validate(args.model, args.output, args.manifest, args.validation_samples, args.input_size)
    print(f"QDQ_INT8_MODEL_OK path={args.output.resolve()} bytes={args.output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
