from __future__ import annotations

from typing import Any, Mapping

from tools import physical_output_route_evidence as route_evidence


def _health_detail(
    *,
    route: str,
    candidate_moves: int,
    java_acceptances: int,
    bluetooth_acceptances: int,
    device_acknowledgements: int,
) -> str:
    makcu_ready = route == route_evidence.MAKCU_USB_ROUTE
    return (
        "phase=running "
        "video={ethernet_network_bound=1 completed_access_units=40} "
        "decoder={qnn_executions=40 qnn_failures=0 consecutive_qnn_failures=0 "
        "last_detection_count=2 makcu_bridge{"
        f"candidate_moves={candidate_moves} java_offer_acceptances={java_acceptances} "
        "java_offer_rejections=0 java_dispatch_failures=0 "
        "native_move_completion_pending=0 native_move_completion_timeouts=0 "
        f"native_device_ack_completions={device_acknowledgements} "
        "native_device_ack_failures=0 stale_device_feedback=0 "
        f"native_bluetooth_hid_api_acceptances={bluetooth_acceptances} "
        "stale_bluetooth_hid_api_acceptances=0 output_requested=1 output_enabled=1}} "
        "qnn={backend=QNN HTP} "
        f"makcu={{serial_open={int(makcu_ready)} "
        f"adapter_identity_verified={int(makcu_ready)} "
        f"protocol_identity_verified={int(makcu_ready)} "
        f"selected_baud={4000000 if makcu_ready else 0} "
        f"device_move_acknowledgements={device_acknowledgements} "
        "device_acknowledgement_failures=0 unexpected_device_responses=0 "
        "response_parser_overflows=0 delivery_failures=0 "
        "consecutive_delivery_failures=0 delivery_circuit_open=0 "
        "delivery_circuit_trips=0}"
    )


def valid_route_payload(
    *,
    route: str,
    android_apk_sha256: str,
    device_serial: str,
    mobile_log_sha256: str,
    start_unix_ms: int,
) -> Mapping[str, Any]:
    first_health = _health_detail(
        route=route,
        candidate_moves=1,
        java_acceptances=1,
        bluetooth_acceptances=0,
        device_acknowledgements=0,
    )
    second_health = _health_detail(
        route=route,
        candidate_moves=4,
        java_acceptances=4,
        bluetooth_acceptances=3 if route == route_evidence.BLUETOOTH_HID_ROUTE else 0,
        device_acknowledgements=3 if route == route_evidence.MAKCU_USB_ROUTE else 0,
    )
    events: list[Mapping[str, Any]] = [
        {
            "timestamp_unix_ms": start_unix_ms + 500,
            "event": "mobile_control_output_route_selected",
            "detail": f"route={route} fail_closed=false",
        },
        {
            "timestamp_unix_ms": start_unix_ms + 1_000,
            "event": "mobile_runtime_health",
            "detail": first_health,
        },
    ]
    if route == route_evidence.BLUETOOTH_HID_ROUTE:
        events.append(
            {
                "timestamp_unix_ms": start_unix_ms + 3_000,
                "event": "bluetooth_hid_send_report",
                "detail": "accepted=true reason=api_return accepted_total=1",
            }
        )
    events.append(
        {
            "timestamp_unix_ms": start_unix_ms + 6_000,
            "event": "mobile_runtime_health",
            "detail": second_health,
        }
    )
    samples = [
        {
            "timestamp_unix_ms": start_unix_ms + (index * 1_000),
            "x": 120 if index >= 3 else 100,
            "y": 100,
            "valid": True,
        }
        for index in range(8)
    ]
    payload = route_evidence.build_route_evidence_from_records(
        route=route,
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        mobile_events=events,
        cursor_samples=samples,
        source_mobile_logs=(
            {"name": "mobile-events.jsonl", "size": 1, "sha256": mobile_log_sha256},
        ),
        cursor_source={"name": "cursor.csv", "size": 1, "sha256": "c" * 64},
    )
    assert route_evidence.route_evidence_errors(payload) == []
    return payload


def valid_physical_output_routes(
    *,
    android_apk_sha256: str,
    device_serial: str,
    mobile_log_sha256: str,
) -> Mapping[str, Any]:
    routes: dict[str, Any] = {}
    for index, route in enumerate(route_evidence.REQUIRED_ROUTES):
        payload = valid_route_payload(
            route=route,
            android_apk_sha256=android_apk_sha256,
            device_serial=device_serial,
            mobile_log_sha256=mobile_log_sha256,
            start_unix_ms=1_800_000_000_000 + (index * 20_000),
        )
        routes[route] = {
            "evidence_sha256": route_evidence.canonical_sha256(payload),
            "evidence": payload,
        }
    return routes
