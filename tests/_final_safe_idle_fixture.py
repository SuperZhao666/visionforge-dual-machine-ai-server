from __future__ import annotations

import hashlib
from typing import Any, Mapping

from tests._physical_output_route_fixture import valid_physical_output_routes
from tools import final_safe_idle_evidence as safe_idle


def final_safe_idle_ui_xml() -> str:
    return (
        "<hierarchy>"
        '<node package="com.visionforge.mobile" '
        'content-desc="vf.output_route.makcu_usb" enabled="true" />'
        '<node package="com.visionforge.mobile" '
        'content-desc="vf.control_output_toggle" enabled="false" />'
        "</hierarchy>"
    )


def valid_final_safe_idle_events(start_unix_ms: int) -> list[Mapping[str, Any]]:
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


def valid_final_safe_idle_payload(
    *,
    android_apk_sha256: str,
    device_serial: str,
    mobile_log_sha256: str,
    ui_xml_sha256: str = "",
    ui_xml: str = "",
    physical_output_routes: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    routes = physical_output_routes or valid_physical_output_routes(
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        mobile_log_sha256=mobile_log_sha256,
    )
    route_payloads = {
        route: entry["evidence"] for route, entry in routes.items()
    }
    acceptance_end = max(
        int(entry["evidence"]["metrics"]["capture_end_unix_ms"])
        for entry in routes.values()
    )
    ui_xml = ui_xml or final_safe_idle_ui_xml()
    actual_ui_xml_sha256 = hashlib.sha256(ui_xml.encode("utf-8")).hexdigest()
    ui_xml_sha256 = ui_xml_sha256 or actual_ui_xml_sha256
    payload = safe_idle.build_final_safe_idle_evidence_from_records(
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        physical_route_payloads=route_payloads,
        mobile_events=valid_final_safe_idle_events(acceptance_end),
        source_mobile_logs=(
            {
                "name": "mobile-events-final.jsonl",
                "size": 1,
                "sha256": mobile_log_sha256,
            },
        ),
        ui_xml=ui_xml,
        ui_source={
            "name": "final-safe-idle.xml",
            "size": len(ui_xml.encode("utf-8")),
            "sha256": ui_xml_sha256,
            "embedded_text_sha256": hashlib.sha256(
                ui_xml.encode("utf-8")
            ).hexdigest(),
        },
    )
    assert safe_idle.final_safe_idle_evidence_errors(payload) == []
    return payload
