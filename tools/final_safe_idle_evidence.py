from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.physical_output_route_evidence import (  # noqa: E402
    BLUETOOTH_HID_ROUTE,
    MAKCU_USB_ROUTE,
    REQUIRED_ROUTES,
    canonical_sha256,
    read_mobile_events,
    route_evidence_errors,
    sha256_file,
)


SCHEMA = "visionforge-final-safe-idle-evidence-v1"
EXPECTED_ANDROID_PACKAGE = "com.visionforge.mobile"
EXPECTED_TRIGGER = "mouse5"

REQUIRED_CHECKS = (
    "dual_physical_acceptance_bound",
    "same_apk_and_device_bound",
    "safe_idle_after_physical_acceptance",
    "makcu_route_restored",
    "side_button_2_restored",
    "formal_usage_closed_locally",
    "formal_usage_stop_server_confirmed",
    "inference_pipeline_stopped",
    "control_output_fail_closed",
    "no_pending_native_move",
    "terminal_health_after_restoration",
    "no_later_runtime_reactivation",
    "ui_package_scope",
    "ui_makcu_route_present",
    "ui_output_gate_disabled",
)

_RELEVANT_EVENT_NAMES = {
    "control_output_auto_locked",
    "control_trigger_applied",
    "dual_machine_formal_data_plane_continued",
    "dual_machine_formal_data_plane_opened",
    "dual_machine_formal_start_exact_retry",
    "dual_machine_formal_start_recovered",
    "dual_machine_formal_stop_failed",
    "dual_machine_formal_stop_finished",
    "mobile_control_output_fail_closed",
    "mobile_control_output_route_command",
    "mobile_control_output_route_selected",
    "mobile_pipeline_stop_requested",
    "mobile_pipeline_stopped",
    "mobile_runtime_health",
    "mobile_runtime_phase_changed",
    "mobile_runtime_service_started",
}


def decode_ui_xml(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="strict").replace("\r\n", "\n").replace(
        "\r",
        "\n",
    )


def _event_order(event: Mapping[str, Any]) -> tuple[int, int]:
    timestamp = int(event.get("timestamp_unix_ms") or 0)
    try:
        sequence = int(event.get("sequence") or 0)
    except (TypeError, ValueError):
        sequence = 0
    return timestamp, sequence


def _detail_has_token(detail: str, key: str, value: str) -> bool:
    return (
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(key)}={re.escape(value)}(?:\s|$)",
            detail,
        )
        is not None
    )


def _metric_value(detail: str, key: str) -> int | None:
    values = re.findall(
        rf"(?<![A-Za-z0-9_]){re.escape(key)}=(-?\d+)",
        detail,
    )
    return int(values[-1]) if values else None


def _ui_nodes(xml_text: str, content_desc: str | None = None) -> list[str]:
    nodes = re.findall(r"<node\b[^>]*>", xml_text)
    if content_desc is None:
        return nodes
    marker = f'content-desc="{content_desc}"'
    return [node for node in nodes if marker in node]


def _ui_package_scope(xml_text: str) -> bool:
    nodes = [node for node in _ui_nodes(xml_text) if 'content-desc="vf.' in node]
    return bool(nodes) and all(
        f'package="{EXPECTED_ANDROID_PACKAGE}"' in node for node in nodes
    )


def _route_entries_from_payloads(
    payloads: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Mapping[str, Any]]:
    return {
        route: {
            "evidence_sha256": canonical_sha256(payloads[route]),
            "evidence": payloads[route],
        }
        for route in REQUIRED_ROUTES
        if route in payloads
    }


def _physical_route_evaluation(
    entries: object,
    *,
    android_apk_sha256: str,
    device_serial: str,
) -> tuple[Mapping[str, bool], Mapping[str, Any], list[str]]:
    errors: list[str] = []
    acceptance_ends: dict[str, int] = {}
    route_hashes: dict[str, str] = {}
    same_apk_and_device = True
    if not isinstance(entries, Mapping):
        return (
            {
                "dual_physical_acceptance_bound": False,
                "same_apk_and_device_bound": False,
            },
            {
                "physical_acceptance_end_unix_ms": 0,
                "route_acceptance_end_unix_ms": {},
                "route_evidence_sha256": {},
            },
            ["final safe-idle physical_output_routes are missing"],
        )
    for route in REQUIRED_ROUTES:
        entry = entries.get(route)
        if not isinstance(entry, Mapping):
            errors.append(f"final safe-idle physical route {route} is missing")
            same_apk_and_device = False
            continue
        evidence = entry.get("evidence")
        if not isinstance(evidence, Mapping):
            errors.append(f"final safe-idle physical route {route} evidence is missing")
            same_apk_and_device = False
            continue
        digest = str(entry.get("evidence_sha256") or "").lower()
        actual_digest = canonical_sha256(evidence)
        route_hashes[route] = actual_digest
        if digest != actual_digest:
            errors.append(f"final safe-idle physical route {route} digest does not match")
        route_errors = route_evidence_errors(
            evidence,
            expected_route=route,
            expected_apk_sha256=android_apk_sha256,
            expected_device_serial=device_serial,
        )
        errors.extend(f"{route}: {error}" for error in route_errors)
        if route_errors:
            same_apk_and_device = False
        metrics = evidence.get("metrics")
        try:
            acceptance_end = int(
                metrics.get("capture_end_unix_ms")
                if isinstance(metrics, Mapping)
                else 0
            )
        except (TypeError, ValueError):
            acceptance_end = 0
        if acceptance_end <= 0:
            errors.append(f"final safe-idle physical route {route} end time is invalid")
        acceptance_ends[route] = acceptance_end
    complete = not errors and set(acceptance_ends) == set(REQUIRED_ROUTES)
    return (
        {
            "dual_physical_acceptance_bound": complete,
            "same_apk_and_device_bound": complete and same_apk_and_device,
        },
        {
            "physical_acceptance_end_unix_ms": max(acceptance_ends.values(), default=0),
            "route_acceptance_end_unix_ms": acceptance_ends,
            "route_evidence_sha256": route_hashes,
        },
        errors,
    )


def _is_runtime_reactivation(event: Mapping[str, Any]) -> bool:
    name = str(event.get("event") or "")
    detail = str(event.get("detail") or "")
    if name in {
        "dual_machine_formal_data_plane_continued",
        "dual_machine_formal_data_plane_opened",
        "dual_machine_formal_start_exact_retry",
        "dual_machine_formal_start_recovered",
    }:
        return True
    if name == "mobile_runtime_phase_changed" and re.search(
        r"(?<![A-Za-z0-9_])to=(?:starting|running)(?:\s|$)",
        detail,
    ):
        return True
    if name == "mobile_runtime_health":
        return (
            _detail_has_token(detail, "phase", "running")
            or (_metric_value(detail, "output_requested") or 0) > 0
            or (_metric_value(detail, "output_enabled") or 0) > 0
        )
    return False


def evaluate_records(
    *,
    android_apk_sha256: str,
    device_serial: str,
    physical_output_routes: object,
    mobile_events: Sequence[Mapping[str, Any]],
    ui_xml: str,
) -> Mapping[str, Any]:
    physical_checks, physical_metrics, physical_errors = _physical_route_evaluation(
        physical_output_routes,
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
    )
    acceptance_end = int(physical_metrics["physical_acceptance_end_unix_ms"])
    ordered_events = sorted(mobile_events, key=_event_order)
    post_acceptance = [
        event
        for event in ordered_events
        if int(event.get("timestamp_unix_ms") or 0) > acceptance_end
    ]
    route_events = [
        event
        for event in post_acceptance
        if event.get("event") == "mobile_control_output_route_selected"
    ]
    trigger_events = [
        event
        for event in post_acceptance
        if event.get("event") == "control_trigger_applied"
    ]
    phase_events = [
        event
        for event in post_acceptance
        if event.get("event") == "mobile_runtime_phase_changed"
    ]
    formal_stop_events = [
        event
        for event in post_acceptance
        if event.get("event") == "dual_machine_formal_stop_finished"
    ]
    formal_closed_phases = [
        event
        for event in phase_events
        if _detail_has_token(str(event.get("detail") or ""), "to", "ready")
        and "reason=formal_usage_closed" in str(event.get("detail") or "")
    ]
    lock_events = [
        event
        for event in post_acceptance
        if event.get("event") in {
            "control_output_auto_locked",
            "mobile_control_output_fail_closed",
        }
    ]

    last_route = route_events[-1] if route_events else None
    last_trigger = trigger_events[-1] if trigger_events else None
    last_phase = phase_events[-1] if phase_events else None
    last_stop = formal_stop_events[-1] if formal_stop_events else None
    last_closed_phase = formal_closed_phases[-1] if formal_closed_phases else None
    required_terminal_events = [
        event
        for event in (last_route, last_trigger, last_stop, last_closed_phase)
        if event is not None
    ]
    terminal_action_end = max(
        (int(event.get("timestamp_unix_ms") or 0) for event in required_terminal_events),
        default=0,
    )
    terminal_health_events = [
        event
        for event in post_acceptance
        if event.get("event") == "mobile_runtime_health"
        and int(event.get("timestamp_unix_ms") or 0) >= terminal_action_end
    ]
    terminal_health = terminal_health_events[-1] if terminal_health_events else None
    terminal_health_detail = str(
        terminal_health.get("detail") if terminal_health is not None else ""
    )
    output_requested = _metric_value(terminal_health_detail, "output_requested")
    output_enabled = _metric_value(terminal_health_detail, "output_enabled")
    pending_moves = _metric_value(
        terminal_health_detail,
        "native_move_completion_pending",
    )

    stop_timestamp = int(last_stop.get("timestamp_unix_ms") or 0) if last_stop else 0
    later_reactivations = [
        event
        for event in post_acceptance
        if int(event.get("timestamp_unix_ms") or 0) > stop_timestamp
        and _is_runtime_reactivation(event)
    ] if stop_timestamp else []
    final_phase_ready = last_phase is not None and (
        _detail_has_token(str(last_phase.get("detail") or ""), "to", "ready")
        or _detail_has_token(str(last_phase.get("detail") or ""), "to", "stopped")
    )
    final_health_idle = terminal_health is not None and (
        _detail_has_token(terminal_health_detail, "phase", "ready")
        or _detail_has_token(terminal_health_detail, "phase", "stopped")
    )
    last_stop_detail = str(last_stop.get("detail") or "") if last_stop else ""

    makcu_ui_nodes = _ui_nodes(ui_xml, "vf.output_route.makcu_usb")
    output_ui_nodes = _ui_nodes(ui_xml, "vf.control_output_toggle")
    checks = {
        **physical_checks,
        "safe_idle_after_physical_acceptance": (
            len(required_terminal_events) == 4
            and all(
                int(event.get("timestamp_unix_ms") or 0) > acceptance_end
                for event in required_terminal_events
            )
            and terminal_health is not None
            and int(terminal_health.get("timestamp_unix_ms") or 0) >= terminal_action_end
        ),
        "makcu_route_restored": (
            last_route is not None
            and _detail_has_token(
                str(last_route.get("detail") or ""),
                "route",
                MAKCU_USB_ROUTE,
            )
        ),
        "side_button_2_restored": (
            last_trigger is not None
            and _detail_has_token(
                str(last_trigger.get("detail") or ""),
                "trigger",
                EXPECTED_TRIGGER,
            )
        ),
        "formal_usage_closed_locally": (
            last_closed_phase is not None
            and _detail_has_token(last_stop_detail, "local_closed", "true")
        ),
        "formal_usage_stop_server_confirmed": _detail_has_token(
            last_stop_detail,
            "server_confirmed",
            "true",
        ),
        "inference_pipeline_stopped": final_phase_ready and final_health_idle,
        "control_output_fail_closed": (
            bool(lock_events) and output_requested == 0 and output_enabled == 0
        ),
        "no_pending_native_move": pending_moves == 0,
        "terminal_health_after_restoration": terminal_health is not None,
        "no_later_runtime_reactivation": bool(last_stop) and not later_reactivations,
        "ui_package_scope": _ui_package_scope(ui_xml),
        "ui_makcu_route_present": bool(makcu_ui_nodes),
        "ui_output_gate_disabled": bool(output_ui_nodes)
        and all('enabled="false"' in node for node in output_ui_nodes),
    }
    return {
        "checks": checks,
        "metrics": {
            **physical_metrics,
            "physical_route_errors": physical_errors,
            "post_acceptance_event_count": len(post_acceptance),
            "last_route_timestamp_unix_ms": (
                int(last_route.get("timestamp_unix_ms") or 0) if last_route else 0
            ),
            "last_trigger_timestamp_unix_ms": (
                int(last_trigger.get("timestamp_unix_ms") or 0) if last_trigger else 0
            ),
            "formal_closed_timestamp_unix_ms": (
                int(last_closed_phase.get("timestamp_unix_ms") or 0)
                if last_closed_phase
                else 0
            ),
            "formal_stop_timestamp_unix_ms": stop_timestamp,
            "terminal_health_timestamp_unix_ms": (
                int(terminal_health.get("timestamp_unix_ms") or 0)
                if terminal_health
                else 0
            ),
            "terminal_output_requested": output_requested,
            "terminal_output_enabled": output_enabled,
            "terminal_native_move_completion_pending": pending_moves,
            "later_runtime_reactivation_count": len(later_reactivations),
        },
    }


def build_final_safe_idle_evidence_from_records(
    *,
    android_apk_sha256: str,
    device_serial: str,
    physical_route_payloads: Mapping[str, Mapping[str, Any]],
    mobile_events: Sequence[Mapping[str, Any]],
    source_mobile_logs: Sequence[Mapping[str, Any]],
    ui_xml: str,
    ui_source: Mapping[str, Any],
) -> Mapping[str, Any]:
    physical_output_routes = _route_entries_from_payloads(physical_route_payloads)
    evaluation = evaluate_records(
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        physical_output_routes=physical_output_routes,
        mobile_events=mobile_events,
        ui_xml=ui_xml,
    )
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "android_apk_sha256": android_apk_sha256.lower(),
        "device_serial": device_serial,
        "expected_idle_state": {
            "output_route": MAKCU_USB_ROUTE,
            "control_trigger": EXPECTED_TRIGGER,
            "pipeline_running": False,
            "control_output_enabled": False,
            "formal_usage_active": False,
        },
        "physical_output_routes": physical_output_routes,
        "checks": evaluation["checks"],
        "metrics": evaluation["metrics"],
        "mobile_events": list(mobile_events),
        "source_mobile_logs": list(source_mobile_logs),
        "ui_xml": ui_xml,
        "ui_source": dict(ui_source),
    }


def final_safe_idle_evidence_errors(
    data: Mapping[str, Any],
    *,
    expected_apk_sha256: str = "",
    expected_device_serial: str = "",
    expected_physical_output_routes: Mapping[str, Any] | None = None,
    allowed_mobile_log_hashes: set[str] | None = None,
    allowed_ui_xml_hashes: set[str] | None = None,
    allowed_ui_xml_sources: Mapping[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"final safe-idle evidence schema is not {SCHEMA}")
    apk_sha256 = str(data.get("android_apk_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", apk_sha256):
        errors.append("final safe-idle Android APK hash is invalid")
    elif expected_apk_sha256 and apk_sha256 != expected_apk_sha256.lower():
        errors.append("final safe-idle Android APK hash does not match")
    device_serial = str(data.get("device_serial") or "")
    if not device_serial:
        errors.append("final safe-idle device serial is missing")
    elif expected_device_serial and device_serial != expected_device_serial:
        errors.append("final safe-idle device serial does not match")
    mobile_events = data.get("mobile_events")
    if not isinstance(mobile_events, Sequence) or isinstance(
        mobile_events,
        (str, bytes),
    ):
        errors.append("final safe-idle mobile events are missing")
        return errors
    ui_xml = data.get("ui_xml")
    if not isinstance(ui_xml, str) or not ui_xml:
        errors.append("final safe-idle UI XML is missing")
        return errors
    try:
        recomputed = evaluate_records(
            android_apk_sha256=apk_sha256,
            device_serial=device_serial,
            physical_output_routes=data.get("physical_output_routes"),
            mobile_events=mobile_events,
            ui_xml=ui_xml,
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"final safe-idle raw records are invalid: {exc}")
        return errors
    if data.get("checks") != recomputed["checks"]:
        errors.append("final safe-idle checks do not match raw records")
    if data.get("metrics") != recomputed["metrics"]:
        errors.append("final safe-idle metrics do not match raw records")
    for name in REQUIRED_CHECKS:
        if recomputed["checks"].get(name) is not True:
            errors.append(f"final safe-idle check {name} is not true")

    physical_routes = data.get("physical_output_routes")
    if expected_physical_output_routes is not None:
        if not isinstance(physical_routes, Mapping):
            errors.append("final safe-idle physical route bindings are missing")
        else:
            for route in REQUIRED_ROUTES:
                actual = physical_routes.get(route)
                expected = expected_physical_output_routes.get(route)
                actual_digest = (
                    str(actual.get("evidence_sha256") or "").lower()
                    if isinstance(actual, Mapping)
                    else ""
                )
                expected_digest = (
                    str(expected.get("evidence_sha256") or "").lower()
                    if isinstance(expected, Mapping)
                    else ""
                )
                if not actual_digest or actual_digest != expected_digest:
                    errors.append(
                        f"final safe-idle physical route {route} binding does not match"
                    )

    source_mobile_logs = data.get("source_mobile_logs")
    if not isinstance(source_mobile_logs, Sequence) or isinstance(
        source_mobile_logs,
        (str, bytes),
    ) or not source_mobile_logs:
        errors.append("final safe-idle source mobile logs are missing")
    else:
        source_hashes: set[str] = set()
        for source in source_mobile_logs:
            digest = (
                str(source.get("sha256") or "").lower()
                if isinstance(source, Mapping)
                else ""
            )
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                errors.append("final safe-idle source mobile log hash is invalid")
                break
            source_hashes.add(digest)
        if (
            allowed_mobile_log_hashes is not None
            and not source_hashes.issubset(allowed_mobile_log_hashes)
        ):
            errors.append("final safe-idle mobile log is not archived")

    ui_source = data.get("ui_source")
    ui_digest = (
        str(ui_source.get("sha256") or "").lower()
        if isinstance(ui_source, Mapping)
        else ""
    )
    embedded_digest = (
        str(ui_source.get("embedded_text_sha256") or "").lower()
        if isinstance(ui_source, Mapping)
        else ""
    )
    actual_embedded_digest = hashlib.sha256(ui_xml.encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", ui_digest):
        errors.append("final safe-idle UI source hash is invalid")
    elif allowed_ui_xml_hashes is not None and ui_digest not in allowed_ui_xml_hashes:
        errors.append("final safe-idle UI XML is not archived")
    if allowed_ui_xml_sources is not None:
        archived_text_digest = allowed_ui_xml_sources.get(ui_digest)
        if archived_text_digest is None:
            errors.append("final safe-idle UI XML source binding is not archived")
        elif archived_text_digest != actual_embedded_digest:
            errors.append("final safe-idle UI source does not match embedded XML")
    if embedded_digest != actual_embedded_digest:
        errors.append("final safe-idle embedded UI XML hash does not match")
    return errors


def _load_route_payload(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(f"physical route evidence root is not an object: {path}")
    return value


def create_final_safe_idle_evidence(
    *,
    android_apk: Path,
    device_serial: str,
    physical_route_evidence_paths: Mapping[str, Path],
    mobile_logs: Sequence[Path],
    ui_xml_path: Path,
) -> Mapping[str, Any]:
    android_apk_sha256 = sha256_file(android_apk)
    route_payloads = {
        route: _load_route_payload(physical_route_evidence_paths[route])
        for route in REQUIRED_ROUTES
    }
    mobile_events = [
        event
        for event in read_mobile_events(mobile_logs)
        if str(event.get("event") or "") in _RELEVANT_EVENT_NAMES
    ]
    ui_xml = decode_ui_xml(ui_xml_path.read_bytes())
    source_mobile_logs = [
        {
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in mobile_logs
    ]
    ui_source = {
        "name": ui_xml_path.name,
        "size": ui_xml_path.stat().st_size,
        "sha256": sha256_file(ui_xml_path),
        "embedded_text_sha256": hashlib.sha256(ui_xml.encode("utf-8")).hexdigest(),
    }
    return build_final_safe_idle_evidence_from_records(
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        physical_route_payloads=route_payloads,
        mobile_events=mobile_events,
        source_mobile_logs=source_mobile_logs,
        ui_xml=ui_xml,
        ui_source=ui_source,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-apk", required=True, type=Path)
    parser.add_argument("--device-serial", required=True)
    parser.add_argument("--bluetooth-route-evidence", required=True, type=Path)
    parser.add_argument("--makcu-route-evidence", required=True, type=Path)
    parser.add_argument("--mobile-log", required=True, action="append", type=Path)
    parser.add_argument("--ui-xml", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    android_apk = args.android_apk.resolve()
    evidence = create_final_safe_idle_evidence(
        android_apk=android_apk,
        device_serial=args.device_serial,
        physical_route_evidence_paths={
            BLUETOOTH_HID_ROUTE: args.bluetooth_route_evidence.resolve(),
            MAKCU_USB_ROUTE: args.makcu_route_evidence.resolve(),
        },
        mobile_logs=[path.resolve() for path in args.mobile_log],
        ui_xml_path=args.ui_xml.resolve(),
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    errors = final_safe_idle_evidence_errors(
        evidence,
        expected_apk_sha256=sha256_file(android_apk),
        expected_device_serial=args.device_serial,
    )
    print(
        "VISIONFORGE_FINAL_SAFE_IDLE_EVIDENCE "
        f"path={output} complete={not errors}",
        flush=True,
    )
    if errors:
        print("missing_or_invalid=" + ",".join(errors), flush=True)
        return 2 if args.require_complete else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
