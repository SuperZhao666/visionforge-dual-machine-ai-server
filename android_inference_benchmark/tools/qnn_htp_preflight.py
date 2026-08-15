"""Refuse false HTP claims by checking the exact QAIRT Android runtime closure."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


ANDROID_REQUIRED = (
    "lib/aarch64-android/libQnnSystem.so",
    "lib/aarch64-android/libQnnHtp.so",
    "lib/aarch64-android/libQnnHtpPrepare.so",
)
HEXAGON_SKEL_GLOB = "lib/hexagon-*/**/libQnnHtp*Skel.so"
HOST_TOOL_CANDIDATES = (
    "bin/x86_64-windows-msvc/qnn-onnx-converter",
    "bin/x86_64-windows-msvc/qairt-converter.exe",
)


def sdk_root(value: str | None) -> Path | None:
    if value:
        return Path(value).expanduser().resolve()
    for name in ("QAIRT_SDK_ROOT", "QNN_SDK_ROOT"):
        candidate = os.environ.get(name)
        if candidate:
            return Path(candidate).expanduser().resolve()
    return None


def report(root: Path | None, calibration: Path) -> dict[str, object]:
    outcome: dict[str, object] = {
        "sdk_root": str(root) if root else None,
        "calibration_input_list": str(calibration),
        "calibration_ready": calibration.is_file() and calibration.stat().st_size > 0,
        "host_tools": {},
        "android_runtime": {},
        "hexagon_skeletons": [],
        "ok": False,
    }
    if root is None or not root.is_dir():
        return outcome
    host_tools = {item: (root / item).is_file() for item in HOST_TOOL_CANDIDATES}
    runtime = {item: (root / item).is_file() for item in ANDROID_REQUIRED}
    skeletons = sorted(str(path.relative_to(root)) for path in root.glob(HEXAGON_SKEL_GLOB))
    outcome["host_tools"] = host_tools
    outcome["android_runtime"] = runtime
    outcome["hexagon_skeletons"] = skeletons
    outcome["ok"] = bool(
        any(host_tools.values())
        and all(runtime.values())
        and skeletons
        and outcome["calibration_ready"]
    )
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", help="QAIRT/QNN SDK root; otherwise QAIRT_SDK_ROOT or QNN_SDK_ROOT.")
    parser.add_argument(
        "--calibration-list",
        type=Path,
        default=Path("android_inference_benchmark/qnn_workspace/calibration/input_list.txt"),
    )
    parser.add_argument("--json", type=Path, help="Optional path for the machine-readable report.")
    args = parser.parse_args()
    outcome = report(sdk_root(args.sdk), args.calibration_list.resolve())
    encoded = json.dumps(outcome, ensure_ascii=False, indent=2)
    print(encoded)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded + "\n", encoding="utf-8")
    return 0 if outcome["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
