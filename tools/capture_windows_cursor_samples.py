from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import hashlib
import sys
import time
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.physical_output_route_evidence import REQUIRED_ROUTES  # noqa: E402


class Point(ctypes.Structure):
    _fields_ = (("x", ctypes.c_long), ("y", ctypes.c_long))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_cursor_position() -> tuple[bool, int, int]:
    if sys.platform != "win32":
        raise RuntimeError("Windows cursor sampling is only available on Windows")
    point = Point()
    valid = bool(ctypes.windll.user32.GetCursorPos(ctypes.byref(point)))
    return valid, int(point.x), int(point.y)


def capture_samples(
    *,
    output: Path,
    route: str,
    android_apk_sha256: str,
    device_serial: str,
    duration_seconds: float,
    warmup_seconds: float,
    interval_millis: int,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    started_at = time.monotonic()
    measurement_start = started_at + warmup_seconds
    deadline = measurement_start + duration_seconds
    interval_seconds = interval_millis / 1000.0
    sample_count = 0
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "Index",
                "Utc",
                "UnixMs",
                "X",
                "Y",
                "Valid",
                "Phase",
                "Route",
                "AndroidApkSha256",
                "DeviceSerial",
            ),
        )
        writer.writeheader()
        while True:
            sampled_at = time.monotonic()
            unix_millis = time.time_ns() // 1_000_000
            cursor_read_valid, x, y = get_cursor_position()
            measuring = sampled_at >= measurement_start
            valid = cursor_read_valid and measuring
            writer.writerow(
                {
                    "Index": sample_count,
                    "Utc": dt.datetime.fromtimestamp(
                        unix_millis / 1000.0,
                        tz=dt.UTC,
                    ).isoformat(timespec="milliseconds"),
                    "UnixMs": unix_millis,
                    "X": x,
                    "Y": y,
                    "Valid": str(valid).lower(),
                    "Phase": "measurement" if measuring else "warmup_setup",
                    "Route": route,
                    "AndroidApkSha256": android_apk_sha256,
                    "DeviceSerial": device_serial,
                }
            )
            sample_count += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            time.sleep(min(interval_seconds, remaining))
    return sample_count


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--route", required=True, choices=REQUIRED_ROUTES)
    parser.add_argument("--android-apk", required=True, type=Path)
    parser.add_argument("--device-serial", required=True)
    parser.add_argument("--duration-seconds", type=float, default=15.0)
    parser.add_argument("--warmup-seconds", type=float, default=0.0)
    parser.add_argument("--interval-millis", type=int, default=50)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if not 1.0 <= args.duration_seconds <= 300.0:
        raise ValueError("duration-seconds must be between 1 and 300")
    if not 0.0 <= args.warmup_seconds <= 30.0:
        raise ValueError("warmup-seconds must be between 0 and 30")
    if not 10 <= args.interval_millis <= 1_000:
        raise ValueError("interval-millis must be between 10 and 1000")
    android_apk = args.android_apk.resolve()
    if not android_apk.is_file():
        raise FileNotFoundError(f"Android APK is missing: {android_apk}")
    output = args.output.resolve()
    digest = sha256_file(android_apk)
    sample_count = capture_samples(
        output=output,
        route=args.route,
        android_apk_sha256=digest,
        device_serial=args.device_serial,
        duration_seconds=args.duration_seconds,
        warmup_seconds=args.warmup_seconds,
        interval_millis=args.interval_millis,
    )
    print(
        "VISIONFORGE_WINDOWS_CURSOR_SAMPLES "
        f"route={args.route} samples={sample_count} warmup_seconds="
        f"{args.warmup_seconds:.3f} apk_sha256={digest} path={output}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
