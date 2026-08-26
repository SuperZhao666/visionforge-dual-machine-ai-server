from __future__ import annotations

import copy
import json
from pathlib import Path

from tests._physical_output_route_fixture import valid_route_payload
from tools import physical_output_route_evidence as evidence


def _valid_payload(route: str):
    return valid_route_payload(
        route=route,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_log_sha256="b" * 64,
        start_unix_ms=1_800_000_000_000,
    )


def test_bluetooth_and_makcu_route_evidence_pass_independent_raw_record_checks() -> None:
    for route in evidence.REQUIRED_ROUTES:
        payload = _valid_payload(route)

        assert evidence.route_evidence_errors(
            payload,
            expected_route=route,
            expected_apk_sha256="a" * 64,
            expected_device_serial="R5CT",
        ) == []


def test_static_windows_cursor_cannot_prove_physical_output() -> None:
    payload = _valid_payload(evidence.BLUETOOTH_HID_ROUTE)
    static_samples = [
        {**sample, "x": 100, "y": 100}
        for sample in payload["cursor_samples"]
    ]
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.BLUETOOTH_HID_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=payload["mobile_events"],
        cursor_samples=static_samples,
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    errors = evidence.route_evidence_errors(rebuilt)

    assert any("windows_cursor_moved" in error for error in errors)


def test_cursor_reset_across_invalid_warmup_gap_is_not_counted_as_movement() -> None:
    payload = _valid_payload(evidence.BLUETOOTH_HID_ROUTE)
    reset_samples = []
    for index, sample in enumerate(payload["cursor_samples"]):
        if index < 3:
            reset_samples.append({**sample, "x": 100, "y": 100, "valid": True})
        elif index == 3:
            reset_samples.append({**sample, "x": 900, "y": 700, "valid": False})
        else:
            reset_samples.append({**sample, "x": 900, "y": 700, "valid": True})
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.BLUETOOTH_HID_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=payload["mobile_events"],
        cursor_samples=reset_samples,
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    errors = evidence.route_evidence_errors(rebuilt)

    assert rebuilt["metrics"]["cursor"]["valid_segment_count"] == 2
    assert rebuilt["metrics"]["cursor"]["maximum_displacement_px"] == 0.0
    assert any("windows_cursor_moved" in error for error in errors)


def test_latest_recent_route_selection_may_precede_measurement_window() -> None:
    payload = _valid_payload(evidence.BLUETOOTH_HID_ROUTE)
    events = copy.deepcopy(payload["mobile_events"])
    route_event = next(
        event
        for event in events
        if event["event"] == "mobile_control_output_route_selected"
    )
    measurement_start = int(payload["metrics"]["capture_start_unix_ms"])
    route_event["timestamp_unix_ms"] = measurement_start - 10_000
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.BLUETOOTH_HID_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=events,
        cursor_samples=payload["cursor_samples"],
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    assert evidence.route_evidence_errors(rebuilt) == []
    assert rebuilt["checks"]["route_selected"] is True


def test_later_different_route_selection_invalidates_measurement_route() -> None:
    payload = _valid_payload(evidence.BLUETOOTH_HID_ROUTE)
    events = copy.deepcopy(payload["mobile_events"])
    events.append(
        {
            "timestamp_unix_ms": int(payload["metrics"]["capture_start_unix_ms"])
            + 2_000,
            "event": "mobile_control_output_route_selected",
            "detail": "route=makcu_usb fail_closed=false",
        }
    )
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.BLUETOOTH_HID_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=events,
        cursor_samples=payload["cursor_samples"],
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    errors = evidence.route_evidence_errors(rebuilt)

    assert rebuilt["checks"]["route_selected"] is False
    assert any("route_selected" in error for error in errors)


def test_bluetooth_api_acceptance_must_advance_during_capture() -> None:
    payload = _valid_payload(evidence.BLUETOOTH_HID_ROUTE)
    events = copy.deepcopy(payload["mobile_events"])
    for event in events:
        if event["event"] == "mobile_runtime_health":
            event["detail"] = event["detail"].replace(
                "native_bluetooth_hid_api_acceptances=3",
                "native_bluetooth_hid_api_acceptances=0",
            )
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.BLUETOOTH_HID_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=events,
        cursor_samples=payload["cursor_samples"],
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    errors = evidence.route_evidence_errors(rebuilt)

    assert any("native_bluetooth_hid_api_acceptances_advanced" in error for error in errors)


def test_makcu_ack_counters_must_advance_during_capture() -> None:
    payload = _valid_payload(evidence.MAKCU_USB_ROUTE)
    events = copy.deepcopy(payload["mobile_events"])
    for event in events:
        if event["event"] == "mobile_runtime_health":
            event["detail"] = event["detail"].replace(
                "native_device_ack_completions=3",
                "native_device_ack_completions=0",
            ).replace(
                "device_move_acknowledgements=3",
                "device_move_acknowledgements=0",
            )
    rebuilt = evidence.build_route_evidence_from_records(
        route=evidence.MAKCU_USB_ROUTE,
        android_apk_sha256="a" * 64,
        device_serial="R5CT",
        mobile_events=events,
        cursor_samples=payload["cursor_samples"],
        source_mobile_logs=payload["source_mobile_logs"],
        cursor_source=payload["cursor_source"],
    )

    errors = evidence.route_evidence_errors(rebuilt)

    assert any("makcu_native_device_acknowledgements_advanced" in error for error in errors)
    assert any("makcu_java_device_acknowledgements_advanced" in error for error in errors)


def test_prefilled_true_checks_are_recomputed_from_raw_records() -> None:
    payload = copy.deepcopy(_valid_payload(evidence.BLUETOOTH_HID_ROUTE))
    payload["cursor_samples"] = [
        {**sample, "x": 100, "y": 100}
        for sample in payload["cursor_samples"]
    ]

    errors = evidence.route_evidence_errors(payload)

    assert "physical route evidence checks do not match raw records" in errors
    assert any("windows_cursor_moved" in error for error in errors)


def test_cursor_csv_parser_accepts_powershell_utc_format(tmp_path: Path) -> None:
    csv_path = tmp_path / "cursor.csv"
    csv_path.write_text(
        "\n".join(
            (
                '"Index","Utc","Local","X","Y"',
                '"0","2026-07-28T07:26:48.2673826Z","ignored","525","490"',
                '"1","2026-07-28T07:26:48.3673826Z","ignored","530","490"',
            )
        ),
        encoding="utf-8",
    )

    samples = evidence.read_cursor_samples(csv_path)

    assert samples[0]["timestamp_unix_ms"] < samples[1]["timestamp_unix_ms"]
    assert samples[1]["x"] == 530
    assert samples[1]["valid"] is True


def test_mobile_event_parser_accepts_powershell_utf16_logcat_capture(tmp_path: Path) -> None:
    event = {
        "timestamp_unix_ms": 1_800_000_000_000,
        "event": "bluetooth_hid_send_report",
        "detail": "accepted=true reason=api_return",
    }
    logcat = tmp_path / "logcat.txt"
    logcat.write_text(
        "07-28 15:27:03.124 I VisionForgeMobile: " + json.dumps(event) + "\n",
        encoding="utf-16",
    )

    parsed = evidence.read_mobile_events([logcat])

    assert parsed == [event]
