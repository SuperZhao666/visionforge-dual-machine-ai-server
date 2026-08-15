from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "visionforge-android-device-connectivity-v1"


@dataclass(frozen=True, slots=True)
class AdbDeviceRow:
    serial: str
    state: str
    raw: str


@dataclass(frozen=True, slots=True)
class AdbCommandResult:
    returncode: int
    stdout: str
    stderr: str


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def resolve_adb_path(requested_path: Path | None) -> Path:
    candidates: list[Path] = []
    if requested_path is not None:
        candidates.append(requested_path)
    candidates.append(ROOT / ".android-sdk" / "platform-tools" / "adb.exe")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    discovered = shutil.which("adb")
    if discovered:
        return Path(discovered).resolve()
    raise FileNotFoundError(
        "ADB missing. Pass --adb-path, set PATH, or install the workspace Android SDK.",
    )


def run_adb_devices(adb_path: Path, timeout_sec: int) -> AdbCommandResult:
    completed = subprocess.run(
        [str(adb_path), "devices", "-l"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return AdbCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_adb_mdns_services(adb_path: Path, timeout_sec: int) -> AdbCommandResult:
    completed = subprocess.run(
        [str(adb_path), "mdns", "services"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return AdbCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def parse_adb_devices(output: str) -> list[AdbDeviceRow]:
    rows: list[AdbDeviceRow] = []
    for raw_line in output.splitlines()[1:]:
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^(?P<serial>.+?)\s+(?P<state>device|offline|unauthorized)\b", line)
        if not match:
            continue
        rows.append(
            AdbDeviceRow(
                serial=match.group("serial"),
                state=match.group("state"),
                raw=line,
            ),
        )
    return rows


def parse_adb_mdns_services(output: str) -> list[str]:
    services: list[str] = []
    for raw_line in output.splitlines()[1:]:
        line = raw_line.strip()
        if line:
            services.append(line)
    return services


def adb_physical_device_key(serial: str) -> str:
    match = re.match(r"^(?P<base>adb-[^ ]+?)(?: \(\d+\))?\._adb-tls-connect\._tcp$", serial)
    if match:
        return match.group("base")
    return serial


def duplicate_adb_transport_groups(rows: Sequence[AdbDeviceRow]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for row in rows:
        if row.state != "device":
            continue
        key = adb_physical_device_key(row.serial)
        groups.setdefault(key, []).append(row.serial)
    return [
        serials
        for key, serials in groups.items()
        if key.startswith("adb-") and len(serials) > 1
    ]


def analyze_adb_devices(
    rows: Sequence[AdbDeviceRow],
    requested_serial: str,
) -> tuple[bool, str, str]:
    duplicates = duplicate_adb_transport_groups(rows)
    if duplicates:
        return False, "duplicate_adb_transports", ""

    online = [row for row in rows if row.state == "device"]
    if requested_serial:
        matching = [row for row in rows if row.serial == requested_serial]
        if matching and matching[0].state == "device":
            return True, "selected_requested_device", requested_serial
        if matching:
            return False, "requested_device_not_online", ""
        return False, "requested_device_missing", ""

    if len(online) == 1:
        return True, "selected_single_device", online[0].serial
    if len(online) > 1:
        return False, "multiple_authorized_devices", ""
    if any(row.state == "unauthorized" for row in rows):
        return False, "unauthorized_device", ""
    if any(row.state == "offline" for row in rows):
        return False, "offline_device", ""
    return False, "no_authorized_device", ""


def device_connectivity_next_actions(
    reason: str,
    requested_serial: str,
    mdns_services: Sequence[str],
) -> list[dict[str, object]]:
    if reason in ("selected_requested_device", "selected_single_device"):
        return []
    if reason == "no_authorized_device":
        hint = (
            "ADB mDNS discovered wireless debugging services; connect one listed target and authorize it on the phone."
            if mdns_services
            else "No ADB mDNS services were discovered; confirm wireless debugging is enabled, the phone is on the same network path, or attach USB once and accept authorization."
        )
        return [
            {
                "reason": reason,
                "action": "Authorize or connect exactly one target phone before formal acceptance.",
                "commands": ["adb mdns services", "adb devices -l"],
                "hint": hint,
            }
        ]
    if reason == "unauthorized_device":
        return [
            {
                "reason": reason,
                "action": "Accept the ADB authorization prompt on the phone, then rerun the device preflight.",
                "commands": ["adb devices -l"],
            }
        ]
    if reason == "offline_device":
        return [
            {
                "reason": reason,
                "action": "Reconnect the phone or restart ADB so the target reaches the device state.",
                "commands": ["adb kill-server", "adb start-server", "adb devices -l"],
            }
        ]
    if reason == "duplicate_adb_transports":
        return [
            {
                "reason": reason,
                "action": "Disconnect duplicate wireless ADB aliases and keep one authorized transport for the phone.",
                "commands": ["adb disconnect", "adb devices -l"],
            }
        ]
    if reason == "multiple_authorized_devices":
        return [
            {
                "reason": reason,
                "action": "Select one phone explicitly for formal acceptance.",
                "commands": ["adb devices -l"],
                "device_serial_arg": "--device-serial",
            }
        ]
    if reason in ("requested_device_missing", "requested_device_not_online"):
        return [
            {
                "reason": reason,
                "action": "Make the requested phone visible and authorized, or rerun without the stale serial.",
                "commands": ["adb devices -l"],
                "requested_serial": requested_serial,
            }
        ]
    if reason == "adb_devices_command_failed":
        return [
            {
                "reason": reason,
                "action": "Fix the local ADB installation or PATH before formal acceptance.",
                "commands": ["adb version", "adb devices -l"],
            }
        ]
    return [
        {
            "reason": reason,
            "action": "Resolve the Android device preflight failure and rerun formal acceptance.",
            "commands": ["adb devices -l"],
        }
    ]


def build_report(
    *,
    adb_path: Path,
    requested_serial: str,
    command_result: AdbCommandResult,
    mdns_result: AdbCommandResult | None = None,
) -> dict[str, object]:
    rows = parse_adb_devices(command_result.stdout)
    mdns_result = mdns_result or AdbCommandResult(returncode=0, stdout="", stderr="")
    mdns_services = parse_adb_mdns_services(mdns_result.stdout)
    ok, reason, selected_serial = analyze_adb_devices(rows, requested_serial)
    if command_result.returncode != 0:
        ok = False
        reason = "adb_devices_command_failed"
        selected_serial = ""
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": ok,
        "reason": reason,
        "adb_path": str(adb_path),
        "requested_serial": requested_serial,
        "selected_serial": selected_serial,
        "devices": [asdict(row) for row in rows],
        "duplicate_transport_groups": duplicate_adb_transport_groups(rows),
        "adb_mdns_services": mdns_services,
        "adb_mdns_returncode": mdns_result.returncode,
        "adb_mdns_stdout": mdns_result.stdout,
        "adb_mdns_stderr": mdns_result.stderr,
        "next_actions": device_connectivity_next_actions(
            reason,
            requested_serial,
            mdns_services,
        ),
        "adb_returncode": command_result.returncode,
        "adb_stdout": command_result.stdout,
        "adb_stderr": command_result.stderr,
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def verify_android_device_connectivity(
    *,
    adb_path: Path | None,
    requested_serial: str,
    output: Path,
    timeout_sec: int,
) -> dict[str, object]:
    resolved_adb = resolve_adb_path(adb_path)
    command_result = run_adb_devices(resolved_adb, timeout_sec)
    mdns_result = run_adb_mdns_services(resolved_adb, timeout_sec)
    report = build_report(
        adb_path=resolved_adb,
        requested_serial=requested_serial,
        command_result=command_result,
        mdns_result=mdns_result,
    )
    write_report(output, report)
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adb-path", type=Path, default=None)
    parser.add_argument("--device-serial", default="")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "analysis_output" / "android_device_connectivity.json",
    )
    parser.add_argument("--timeout-sec", type=int, default=30)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output.resolve()
    try:
        report = verify_android_device_connectivity(
            adb_path=args.adb_path.resolve() if args.adb_path else None,
            requested_serial=args.device_serial,
            output=output,
            timeout_sec=args.timeout_sec,
        )
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema": SCHEMA,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "ok": False,
            "reason": "android_device_preflight_error",
            "error": str(exc),
        }
        write_report(output, report)
        print(f"[ERROR] Android device preflight failed; report={output}", flush=True)
        print(f"[ERROR] {exc}", flush=True)
        return 1
    if report.get("ok") is True:
        print(
            "[OK] Android ADB device ready; "
            f"serial={report.get('selected_serial')} report={output}",
            flush=True,
        )
        return 0
    print(
        "[ERROR] Android ADB device is not ready; "
        f"reason={report.get('reason')} report={output}",
        flush=True,
    )
    return 2


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
