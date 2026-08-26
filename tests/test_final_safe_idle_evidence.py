from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Mapping

import pytest

from tests._physical_output_route_fixture import valid_physical_output_routes
from tools import final_safe_idle_evidence as safe_idle


APK_SHA256 = "a" * 64
DEVICE_SERIAL = "adb-production._adb-tls-connect._tcp"
MOBILE_LOG_SHA256 = "b" * 64


def _ui_xml() -> str:
    return (
        "<hierarchy>"
        '<node package="com.visionforge.mobile" '
        'content-desc="vf.output_route.makcu_usb" enabled="true" />'
        '<node package="com.visionforge.mobile" '
        'content-desc="vf.control_output_toggle" enabled="false" />'
        "</hierarchy>"
    )


UI_XML_SHA256 = hashlib.sha256(_ui_xml().encode("utf-8")).hexdigest()


def _terminal_events(start_unix_ms: int) -> list[Mapping[str, Any]]:
    return [
        {
            "timestamp_unix_ms": start_unix_ms + 1_000,
            "sequence": 1,
            "event": "mobile_runtime_phase_changed",
            "detail": (
                "from=running to=ready revision=12 "
                "detail={pipeline_data_plane_closed reason=formal_usage_closed}"
            ),
        },
        {
            "timestamp_unix_ms": start_unix_ms + 2_000,
            "sequence": 2,
            "event": "dual_machine_formal_stop_finished",
            "detail": "local_closed=true server_confirmed=true",
        },
        {
            "timestamp_unix_ms": start_unix_ms + 3_000,
            "sequence": 3,
            "event": "mobile_control_output_route_selected",
            "detail": "route=makcu_usb reason=makcu_selected fail_closed=false",
        },
        {
            "timestamp_unix_ms": start_unix_ms + 4_000,
            "sequence": 4,
            "event": "control_trigger_applied",
            "detail": (
                "trigger=mouse5 physical_read_only=true output_fail_closed=true"
            ),
        },
        {
            "timestamp_unix_ms": start_unix_ms + 4_500,
            "sequence": 5,
            "event": "control_output_auto_locked",
            "detail": (
                "reason=control_output_route_switch automatic_retry=true "
                "fail_closed=true"
            ),
        },
        {
            "timestamp_unix_ms": start_unix_ms + 5_000,
            "sequence": 6,
            "event": "mobile_runtime_phase_changed",
            "detail": (
                "from=ready to=ready revision=13 "
                "detail={pipeline_stopped reason=control_output_route_switch}"
            ),
        },
        {
            "timestamp_unix_ms": start_unix_ms + 10_000,
            "sequence": 7,
            "event": "mobile_runtime_health",
            "detail": (
                "phase=ready video={ethernet_network_bound=1} "
                "decoder={makcu_bridge{output_requested=0 output_enabled=0 "
                "native_move_completion_pending=0}} qnn={backend=QNN HTP} "
                "makcu={serial_open=1 adapter_identity_verified=1 "
                "protocol_identity_verified=1 selected_baud=4000000}"
            ),
        },
    ]


def _valid_payload() -> Mapping[str, Any]:
    routes = valid_physical_output_routes(
        android_apk_sha256=APK_SHA256,
        device_serial=DEVICE_SERIAL,
        mobile_log_sha256=MOBILE_LOG_SHA256,
    )
    route_payloads = {
        route: entry["evidence"] for route, entry in routes.items()
    }
    acceptance_end = max(
        int(entry["evidence"]["metrics"]["capture_end_unix_ms"])
        for entry in routes.values()
    )
    ui_xml = _ui_xml()
    return safe_idle.build_final_safe_idle_evidence_from_records(
        android_apk_sha256=APK_SHA256,
        device_serial=DEVICE_SERIAL,
        physical_route_payloads=route_payloads,
        mobile_events=_terminal_events(acceptance_end),
        source_mobile_logs=(
            {
                "name": "mobile-events-final.jsonl",
                "size": 1,
                "sha256": MOBILE_LOG_SHA256,
            },
        ),
        ui_xml=ui_xml,
        ui_source={
            "name": "final-safe-idle.xml",
            "size": len(ui_xml.encode("utf-8")),
            "sha256": UI_XML_SHA256,
            "embedded_text_sha256": hashlib.sha256(
                ui_xml.encode("utf-8")
            ).hexdigest(),
        },
    )


def test_final_safe_idle_evidence_recomputes_complete_terminal_state() -> None:
    payload = _valid_payload()

    assert safe_idle.final_safe_idle_evidence_errors(
        payload,
        expected_apk_sha256=APK_SHA256,
        expected_device_serial=DEVICE_SERIAL,
        expected_physical_output_routes=payload["physical_output_routes"],
        allowed_mobile_log_hashes={MOBILE_LOG_SHA256},
        allowed_ui_xml_hashes={UI_XML_SHA256},
    ) == []
    assert all(payload["checks"][name] for name in safe_idle.REQUIRED_CHECKS)


@pytest.mark.parametrize(
    ("event", "expected_check"),
    (
        (
            {
                "event": "dual_machine_formal_data_plane_opened",
                "detail": "host_authorization=false",
            },
            "no_later_runtime_reactivation",
        ),
        (
            {
                "event": "mobile_control_output_route_selected",
                "detail": "route=bluetooth_hid fail_closed=false",
            },
            "makcu_route_restored",
        ),
        (
            {
                "event": "control_trigger_applied",
                "detail": "trigger=mouse4 output_fail_closed=true",
            },
            "side_button_2_restored",
        ),
    ),
)
def test_final_safe_idle_rejects_later_state_override(
    event: Mapping[str, str],
    expected_check: str,
) -> None:
    payload = deepcopy(_valid_payload())
    terminal_timestamp = int(payload["metrics"]["terminal_health_timestamp_unix_ms"])
    payload["mobile_events"].append(
        {
            "timestamp_unix_ms": terminal_timestamp + 1_000,
            "sequence": 20,
            **event,
        }
    )
    recomputed = safe_idle.evaluate_records(
        android_apk_sha256=APK_SHA256,
        device_serial=DEVICE_SERIAL,
        physical_output_routes=payload["physical_output_routes"],
        mobile_events=payload["mobile_events"],
        ui_xml=payload["ui_xml"],
    )

    assert recomputed["checks"][expected_check] is False


def test_final_safe_idle_rejects_unconfirmed_server_stop() -> None:
    payload = deepcopy(_valid_payload())
    stop_event = next(
        event
        for event in payload["mobile_events"]
        if event["event"] == "dual_machine_formal_stop_finished"
    )
    stop_event["detail"] = "local_closed=true server_confirmed=false"
    recomputed = safe_idle.evaluate_records(
        android_apk_sha256=APK_SHA256,
        device_serial=DEVICE_SERIAL,
        physical_output_routes=payload["physical_output_routes"],
        mobile_events=payload["mobile_events"],
        ui_xml=payload["ui_xml"],
    )

    assert recomputed["checks"]["formal_usage_stop_server_confirmed"] is False


def test_final_safe_idle_rejects_prefilled_green_checks() -> None:
    payload = deepcopy(_valid_payload())
    payload["mobile_events"] = []

    errors = safe_idle.final_safe_idle_evidence_errors(payload)

    assert "final safe-idle checks do not match raw records" in errors
    assert any("safe_idle_after_physical_acceptance" in error for error in errors)
