from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_android_device_connectivity as verifier  # noqa: E402


def _command(stdout: str, returncode: int = 0) -> verifier.AdbCommandResult:
    return verifier.AdbCommandResult(returncode=returncode, stdout=stdout, stderr="")


def _mdns(stdout: str, returncode: int = 0) -> verifier.AdbCommandResult:
    return verifier.AdbCommandResult(returncode=returncode, stdout=stdout, stderr="")


def test_android_device_connectivity_accepts_single_authorized_device() -> None:
    rows = verifier.parse_adb_devices(
        "List of devices attached\n"
        "R5CT device product:phone model:Pixel device:pixel transport_id:1\n",
    )

    ok, reason, serial = verifier.analyze_adb_devices(rows, "")

    assert ok is True
    assert reason == "selected_single_device"
    assert serial == "R5CT"


def test_android_device_connectivity_rejects_no_device() -> None:
    report = verifier.build_report(
        adb_path=Path("adb.exe"),
        requested_serial="",
        command_result=_command("List of devices attached\n\n"),
        mdns_result=_mdns("List of discovered mdns services\n\n"),
    )

    assert report["ok"] is False
    assert report["reason"] == "no_authorized_device"
    assert report["devices"] == []
    assert report["adb_mdns_services"] == []
    assert report["next_actions"][0]["commands"] == [
        "adb mdns services",
        "adb devices -l",
    ]
    assert "No ADB mDNS services were discovered" in report["next_actions"][0]["hint"]


def test_android_device_connectivity_records_mdns_services_in_failure_report() -> None:
    report = verifier.build_report(
        adb_path=Path("adb.exe"),
        requested_serial="",
        command_result=_command("List of devices attached\n\n"),
        mdns_result=_mdns(
            "List of discovered mdns services\n"
            "adb-R5CT._adb-tls-connect._tcp.\t_adb-tls-connect._tcp.\n",
        ),
    )

    assert report["ok"] is False
    assert report["reason"] == "no_authorized_device"
    assert report["adb_mdns_services"] == [
        "adb-R5CT._adb-tls-connect._tcp.\t_adb-tls-connect._tcp.",
    ]
    assert "discovered wireless debugging services" in report["next_actions"][0]["hint"]


def test_android_device_connectivity_rejects_unauthorized_device() -> None:
    report = verifier.build_report(
        adb_path=Path("adb.exe"),
        requested_serial="",
        command_result=_command("List of devices attached\nR5CT unauthorized usb:1\n"),
    )

    assert report["ok"] is False
    assert report["reason"] == "unauthorized_device"


def test_android_device_connectivity_accepts_requested_serial() -> None:
    rows = verifier.parse_adb_devices(
        "List of devices attached\n"
        "R5CT device usb:1\n"
        "R7CT device usb:2\n",
    )

    ok, reason, serial = verifier.analyze_adb_devices(rows, "R7CT")

    assert ok is True
    assert reason == "selected_requested_device"
    assert serial == "R7CT"


def test_android_device_connectivity_rejects_duplicate_mdns_transports() -> None:
    rows = verifier.parse_adb_devices(
        "List of devices attached\n"
        "adb-ABC._adb-tls-connect._tcp device product:x\n"
        "adb-ABC (2)._adb-tls-connect._tcp device product:x\n",
    )

    ok, reason, serial = verifier.analyze_adb_devices(rows, "")

    assert ok is False
    assert reason == "duplicate_adb_transports"
    assert serial == ""
    assert verifier.duplicate_adb_transport_groups(rows) == [
        [
            "adb-ABC._adb-tls-connect._tcp",
            "adb-ABC (2)._adb-tls-connect._tcp",
        ],
    ]


def test_android_device_connectivity_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "android_device_connectivity.json"
    report = verifier.build_report(
        adb_path=Path("adb.exe"),
        requested_serial="",
        command_result=_command("List of devices attached\nR5CT device usb:1\n"),
    )

    verifier.write_report(output, report)

    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert persisted["schema"] == verifier.SCHEMA
    assert persisted["ok"] is True
    assert persisted["selected_serial"] == "R5CT"
