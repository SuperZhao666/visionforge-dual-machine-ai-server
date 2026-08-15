"""Prepare a storage-conscious CS2 calibration and held-out evaluation set.

The public archive is read with HTTP Range requests. Only selected PNG entries
are downloaded; the multi-gigabyte ZIP is never materialized on disk.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import time
import uuid
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import requests
from PIL import Image

DATASET_PAGE = (
    "https://huggingface.co/datasets/"
    "CactusBooblegum/Counter-Strike-2-rectangles-yolo"
)
DEFAULT_ARCHIVE_URL = f"{DATASET_PAGE}/resolve/main/anubis_rectangles_500img.zip"
EXPECTED_ARCHIVE_BYTES = 1_256_407_050
MODEL_SIZE = 416
PADDING_VALUE = 114
PUBLIC_CALIBRATION_COUNT = 13
PUBLIC_EVALUATION_COUNT = 5
LOCAL_CALIBRATION_COUNT = 2
HTTP_BLOCK_BYTES = 512 * 1024
HTTP_RETRY_COUNT = 6


@dataclass(frozen=True, slots=True)
class SelectedFrame:
    archive_path: str
    label_path: str
    role: str
    label_bytes: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _request_range(
    session: requests.Session,
    url: str,
    start: int,
    end: int,
) -> bytes:
    expected_bytes = end - start + 1
    for attempt in range(HTTP_RETRY_COUNT):
        try:
            response = session.get(
                url,
                headers={
                    "Range": f"bytes={start}-{end}",
                    "User-Agent": "VisionForge/1.0",
                },
                timeout=(30, 120),
            )
            response.raise_for_status()
            content_range = response.headers.get("Content-Range", "")
            payload = response.content
            if response.status_code != 206 or len(payload) != expected_bytes:
                raise RuntimeError(
                    "Invalid HTTP Range response: "
                    f"status={response.status_code} range={content_range!r} "
                    f"expected={expected_bytes} actual={len(payload)}"
                )
            return payload
        except (requests.RequestException, RuntimeError):
            if attempt + 1 == HTTP_RETRY_COUNT:
                raise
            time.sleep(min(2**attempt, 8))
    raise AssertionError("unreachable HTTP retry path")


def _download_zip_entry(
    session: requests.Session,
    archive_url: str,
    info: zipfile.ZipInfo,
) -> bytes:
    local_header = _request_range(
        session,
        archive_url,
        info.header_offset,
        info.header_offset + 29,
    )
    fields = struct.unpack("<IHHHHHIIIHH", local_header)
    if fields[0] != 0x04034B50:
        raise RuntimeError(f"Invalid ZIP local header for {info.filename}")
    filename_bytes = fields[-2]
    extra_bytes = fields[-1]
    data_start = info.header_offset + 30 + filename_bytes + extra_bytes
    compressed = bytearray()
    for offset in range(0, info.compress_size, HTTP_BLOCK_BYTES):
        block_bytes = min(HTTP_BLOCK_BYTES, info.compress_size - offset)
        compressed.extend(
            _request_range(
                session,
                archive_url,
                data_start + offset,
                data_start + offset + block_bytes - 1,
            )
        )
    if info.compress_type == zipfile.ZIP_STORED:
        payload = bytes(compressed)
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        payload = zlib.decompress(compressed, -zlib.MAX_WBITS)
    else:
        raise RuntimeError(
            f"Unsupported ZIP compression type for {info.filename}: "
            f"{info.compress_type}"
        )
    if len(payload) != info.file_size:
        raise RuntimeError(
            f"ZIP entry size mismatch for {info.filename}: "
            f"expected={info.file_size} actual={len(payload)}"
        )
    if zlib.crc32(payload) & 0xFFFFFFFF != info.CRC:
        raise RuntimeError(f"ZIP entry CRC mismatch for {info.filename}")
    return payload


def _evenly_spaced(values: list[str], count: int) -> list[str]:
    if count < 0 or len(values) < count:
        raise ValueError("Insufficient values for deterministic selection")
    if count == 0:
        return []
    if count == 1:
        return [values[len(values) // 2]]
    return [
        values[round(index * (len(values) - 1) / (count - 1))]
        for index in range(count)
    ]


def select_frames(archive: zipfile.ZipFile) -> list[SelectedFrame]:
    infos = {info.filename: info for info in archive.infolist()}
    png_paths = sorted(
        path
        for path in infos
        if path.startswith("obj_train_data/frame_") and path.endswith(".png")
    )
    labelled: list[tuple[str, str, int]] = []
    for image_path in png_paths:
        label_path = image_path.removesuffix(".png") + ".txt"
        label = infos.get(label_path)
        if label is not None and label.file_size > 0:
            labelled.append((image_path, label_path, label.file_size))
    single = [item[0] for item in labelled if item[2] <= 40]
    multiple = [item[0] for item in labelled if item[2] > 40]
    labels = {item[0]: (item[1], item[2]) for item in labelled}

    calibration = set(_evenly_spaced(single, 9) + _evenly_spaced(multiple, 4))
    remaining_single = [path for path in single if path not in calibration]
    remaining_multiple = [path for path in multiple if path not in calibration]
    evaluation = set(
        _evenly_spaced(remaining_single, 3)
        + _evenly_spaced(remaining_multiple, 2)
    )
    selected: list[SelectedFrame] = []
    for role, paths in (("calibration", calibration), ("evaluation", evaluation)):
        for image_path in sorted(paths):
            label_path, label_bytes = labels[image_path]
            selected.append(
                SelectedFrame(image_path, label_path, role, label_bytes)
            )
    if len(calibration) != PUBLIC_CALIBRATION_COUNT:
        raise RuntimeError("Public calibration selection count drifted")
    if len(evaluation) != PUBLIC_EVALUATION_COUNT:
        raise RuntimeError("Public evaluation selection count drifted")
    return selected


def _letterbox_rgb(image_path: Path) -> np.ndarray:
    with Image.open(image_path) as opened:
        image = opened.convert("RGB")
        scale = min(MODEL_SIZE / image.width, MODEL_SIZE / image.height)
        resized_width = round(image.width * scale)
        resized_height = round(image.height * scale)
        resized = image.resize(
            (resized_width, resized_height),
            Image.Resampling.BILINEAR,
        )
        canvas = Image.new(
            "RGB",
            (MODEL_SIZE, MODEL_SIZE),
            (PADDING_VALUE, PADDING_VALUE, PADDING_VALUE),
        )
        canvas.paste(
            resized,
            ((MODEL_SIZE - resized_width) // 2, (MODEL_SIZE - resized_height) // 2),
        )
        return np.asarray(canvas, dtype=np.uint8)


def _write_calibration_tensor(image_path: Path, destination: Path) -> None:
    rgb = _letterbox_rgb(image_path)
    tensor = rgb.astype(np.float32).transpose(2, 0, 1) / 255.0
    tensor.tofile(destination)


def _write_runtime_tensor(image_path: Path, destination: Path) -> None:
    rgb = _letterbox_rgb(image_path)
    tensor = rgb.astype("<u2") * np.uint16(257)
    tensor.tofile(destination)


def prepare_dataset(
    *,
    archive_url: str,
    output_root: Path,
    local_calibration_images: list[Path],
) -> dict[str, object]:
    try:
        from remotezip import RemoteZip
    except ModuleNotFoundError as missing_remotezip:
        raise RuntimeError(
            "prepare_cs2_calibration_dataset.py requires remotezip==0.12.3"
        ) from missing_remotezip
    if len(local_calibration_images) != LOCAL_CALIBRATION_COUNT:
        raise ValueError(
            f"Expected {LOCAL_CALIBRATION_COUNT} local calibration images"
        )
    local_images = [path.resolve(strict=True) for path in local_calibration_images]
    output_root = output_root.resolve()
    if output_root.exists():
        raise FileExistsError(f"Output root already exists: {output_root}")
    staging = output_root.with_name(f".{output_root.name}.staging-{uuid.uuid4().hex}")
    staging.mkdir(parents=True)
    try:
        source_directory = staging / "source_images"
        calibration_directory = staging / "calibration" / "raw"
        evaluation_directory = staging / "evaluation" / "u16_nhwc"
        source_directory.mkdir(parents=True)
        calibration_directory.mkdir(parents=True)
        evaluation_directory.mkdir(parents=True)

        records: list[dict[str, object]] = []
        with RemoteZip(
            archive_url,
            headers={"User-Agent": "VisionForge/1.0"},
        ) as archive:
            archive_bytes = archive.size()
            if archive_bytes != EXPECTED_ARCHIVE_BYTES:
                raise RuntimeError(
                    "Unexpected public dataset archive size: "
                    f"expected={EXPECTED_ARCHIVE_BYTES} actual={archive_bytes}"
                )
            selected = select_frames(archive)
            selected_infos = {
                path: archive.getinfo(path)
                for frame in selected
                for path in (frame.archive_path, frame.label_path)
            }
        with requests.Session() as session:
            for frame in selected:
                stem = Path(frame.archive_path).stem
                image_path = source_directory / f"hf_anubis_{stem}.png"
                label_path = source_directory / f"hf_anubis_{stem}.txt"
                image_path.write_bytes(
                    _download_zip_entry(
                        session,
                        archive_url,
                        selected_infos[frame.archive_path],
                    )
                )
                label_path.write_bytes(
                    _download_zip_entry(
                        session,
                        archive_url,
                        selected_infos[frame.label_path],
                    )
                )
                with Image.open(image_path) as image:
                    image.verify()
                tensor_name = f"hf_anubis_{stem}.raw"
                if frame.role == "calibration":
                    tensor_path = calibration_directory / tensor_name
                    _write_calibration_tensor(image_path, tensor_path)
                else:
                    tensor_path = evaluation_directory / tensor_name
                    _write_runtime_tensor(image_path, tensor_path)
                records.append(
                    {
                        "role": frame.role,
                        "source": frame.archive_path,
                        "image": str(image_path.relative_to(staging)),
                        "image_sha256": _sha256(image_path),
                        "label": str(label_path.relative_to(staging)),
                        "label_sha256": _sha256(label_path),
                        "label_bytes": frame.label_bytes,
                        "tensor": str(tensor_path.relative_to(staging)),
                        "tensor_sha256": _sha256(tensor_path),
                    }
                )

        for index, image_path in enumerate(local_images):
            tensor_path = calibration_directory / f"local_{index:02d}.raw"
            _write_calibration_tensor(image_path, tensor_path)
            records.append(
                {
                    "role": "calibration",
                    "source": str(image_path),
                    "image": None,
                    "image_sha256": _sha256(image_path),
                    "label": None,
                    "label_sha256": None,
                    "label_bytes": None,
                    "tensor": str(tensor_path.relative_to(staging)),
                    "tensor_sha256": _sha256(tensor_path),
                }
            )

        calibration_tensors = sorted(calibration_directory.glob("*.raw"))
        evaluation_tensors = sorted(evaluation_directory.glob("*.raw"))
        expected_calibration_bytes = MODEL_SIZE * MODEL_SIZE * 3 * 4
        expected_runtime_bytes = MODEL_SIZE * MODEL_SIZE * 3 * 2
        if len(calibration_tensors) != 15 or any(
            path.stat().st_size != expected_calibration_bytes
            for path in calibration_tensors
        ):
            raise RuntimeError("Calibration tensor contract is incomplete")
        if len(evaluation_tensors) != 5 or any(
            path.stat().st_size != expected_runtime_bytes
            for path in evaluation_tensors
        ):
            raise RuntimeError("Evaluation tensor contract is incomplete")

        manifest: dict[str, object] = {
            "schema": "visionforge-cs2-calibration-dataset-v1",
            "dataset_page": DATASET_PAGE,
            "archive_url": archive_url,
            "archive_bytes": archive_bytes,
            "download_mode": "http_range_selected_entries_only",
            "model_input": [1, 3, MODEL_SIZE, MODEL_SIZE],
            "padding_rgb": [PADDING_VALUE, PADDING_VALUE, PADDING_VALUE],
            "calibration": {
                "count": len(calibration_tensors),
                "dtype": "float32",
                "layout": "NCHW",
                "bytes_per_tensor": expected_calibration_bytes,
            },
            "evaluation": {
                "count": len(evaluation_tensors),
                "dtype": "uint16",
                "layout": "NHWC",
                "scale": "rgb_u8_times_257",
                "bytes_per_tensor": expected_runtime_bytes,
            },
            "records": records,
        }
        (staging / "dataset_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        staging.replace(output_root)
        return manifest
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-url", default=DEFAULT_ARCHIVE_URL)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument(
        "--local-calibration-image",
        type=Path,
        action="append",
        default=[],
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    manifest = prepare_dataset(
        archive_url=arguments.archive_url,
        output_root=arguments.output_root,
        local_calibration_images=arguments.local_calibration_image,
    )
    print(
        "CS2_CALIBRATION_DATASET_OK "
        f"output={arguments.output_root.resolve()} "
        f"calibration={manifest['calibration']['count']} "
        f"evaluation={manifest['evaluation']['count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
