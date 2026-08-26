from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "visionforge-physical-output-route-evidence-v1"
BLUETOOTH_HID_ROUTE = "bluetooth_hid"
MAKCU_USB_ROUTE = "makcu_usb"
REQUIRED_ROUTES = (BLUETOOTH_HID_ROUTE, MAKCU_USB_ROUTE)
EXPECTED_MAKCU_PROTOCOL_IDENTITY = "km.MAKCU\r\n>>> "

EVENT_CLOCK_SKEW_MILLIS = 2_000
ROUTE_SELECTION_CONTEXT_MILLIS = 30 * 60 * 1_000
MINIMUM_CURSOR_SAMPLES = 5
MINIMUM_CAPTURE_DURATION_MILLIS = 1_000
MINIMUM_CURSOR_DISPLACEMENT_PIXELS = 2.0

COMMON_REQUIRED_CHECKS = (
    "capture_window_valid",
    "route_selected",
    "runtime_health_samples_sufficient",
    "cat6_stream_connected",
    "qnn_htp_target_positive",
    "candidate_moves_and_java_acceptances_advanced",
    "control_output_enabled",
    "control_failures_zero",
    "windows_cursor_moved",
    "route_activity_correlated_with_cursor",
)
ROUTE_REQUIRED_CHECKS = {
    BLUETOOTH_HID_ROUTE: (
        "bluetooth_hid_send_report_accepted",
        "bluetooth_hid_send_report_failures_zero",
        "native_bluetooth_hid_api_acceptances_advanced",
        "bluetooth_hid_native_failures_zero",
    ),
    MAKCU_USB_ROUTE: (
        "makcu_runtime_identity_verified",
        "makcu_exact_protocol_identity_contract_bound",
        "makcu_native_device_acknowledgements_advanced",
        "makcu_java_device_acknowledgements_advanced",
        "makcu_device_failures_zero",
    ),
}

_COUNTER_NAMES = (
    "completed_access_units",
    "qnn_executions",
    "qnn_failures",
    "consecutive_qnn_failures",
    "last_detection_count",
    "candidate_moves",
    "java_offer_acceptances",
    "java_offer_rejections",
    "java_dispatch_failures",
    "native_move_completion_pending",
    "native_move_completion_timeouts",
    "native_device_ack_completions",
    "native_device_ack_failures",
    "stale_device_feedback",
    "native_bluetooth_hid_api_acceptances",
    "stale_bluetooth_hid_api_acceptances",
    "output_requested",
    "output_enabled",
    "serial_open",
    "adapter_identity_verified",
    "protocol_identity_verified",
    "selected_baud",
    "device_move_acknowledgements",
    "device_acknowledgement_failures",
    "unexpected_device_responses",
    "response_parser_overflows",
    "delivery_failures",
    "consecutive_delivery_failures",
    "delivery_circuit_open",
    "delivery_circuit_trips",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalise_column_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _parse_timestamp_millis(value: object) -> int:
    text = str(value or "").strip()
    if not text:
        raise ValueError("cursor sample timestamp is missing")
    if re.fullmatch(r"\d{10,16}", text):
        return int(text)
    parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("cursor sample timestamp must include a UTC offset")
    return int(round(parsed.timestamp() * 1000.0))


def _parse_bool(value: object, default: bool = True) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return default
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def read_cursor_samples(path: Path) -> list[Mapping[str, Any]]:
    samples: list[Mapping[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("cursor CSV has no header")
        for row_number, row in enumerate(reader, start=2):
            normalised = {
                _normalise_column_name(str(key)): value
                for key, value in row.items()
                if key is not None
            }
            timestamp = next(
                (
                    normalised[key]
                    for key in ("timestampunixms", "unixms", "utc", "timestamp")
                    if key in normalised and str(normalised[key] or "").strip()
                ),
                None,
            )
            try:
                samples.append(
                    {
                        "timestamp_unix_ms": _parse_timestamp_millis(timestamp),
                        "x": int(str(normalised.get("x", "")).strip()),
                        "y": int(str(normalised.get("y", "")).strip()),
                        "valid": _parse_bool(normalised.get("valid"), default=True),
                    }
                )
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid cursor CSV row {row_number}: {exc}") from exc
    if not samples:
        raise ValueError("cursor CSV has no samples")
    return samples


def _decode_json_line(raw_line: str) -> Mapping[str, Any] | None:
    stripped = raw_line.strip()
    if not stripped:
        return None
    candidates = (stripped, stripped[stripped.find("{") :] if "{" in stripped else "")
    for candidate in candidates:
        if not candidate:
            continue
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, Mapping):
            return value
    return None


def read_mobile_events(paths: Sequence[Path]) -> list[Mapping[str, Any]]:
    events: list[Mapping[str, Any]] = []
    for path in paths:
        with path.open("rb") as binary_handle:
            prefix = binary_handle.read(3)
        encoding = "utf-16" if prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        with path.open("r", encoding=encoding, errors="replace") as handle:
            for raw_line in handle:
                value = _decode_json_line(raw_line)
                if value is None:
                    continue
                try:
                    timestamp = int(value.get("timestamp_unix_ms"))
                except (TypeError, ValueError):
                    continue
                event = str(value.get("event") or "")
                if not event:
                    continue
                normalised: dict[str, Any] = {
                    "timestamp_unix_ms": timestamp,
                    "event": event,
                    "detail": str(value.get("detail") or ""),
                }
                for key in ("trace_id", "sequence", "process_id"):
                    if key in value:
                        normalised[key] = value[key]
                events.append(normalised)
    return sorted(events, key=lambda item: int(item["timestamp_unix_ms"]))


def _is_relevant_event(event: str) -> bool:
    return (
        event == "mobile_runtime_health"
        or event == "mobile_runtime_service_started"
        or event == "mobile_control_runtime_created"
        or "control_output" in event
        or event.startswith("bluetooth_hid")
        or event.startswith("makcu_")
    )


def _metric_values(detail: str, key: str) -> list[int]:
    return [
        int(value)
        for value in re.findall(
            rf"(?<![A-Za-z0-9_]){re.escape(key)}=(-?\d+)",
            detail,
        )
    ]


def _metric_value(detail: str, key: str) -> int | None:
    values = _metric_values(detail, key)
    return values[-1] if values else None


def _counter_summary(health_events: Sequence[Mapping[str, Any]], key: str) -> Mapping[str, Any]:
    values: list[int] = []
    for event in health_events:
        value = _metric_value(str(event.get("detail") or ""), key)
        if value is not None:
            values.append(value)
    if not values:
        return {"first": None, "last": None, "minimum": None, "maximum": None, "delta": None}
    return {
        "first": values[0],
        "last": values[-1],
        "minimum": min(values),
        "maximum": max(values),
        "delta": values[-1] - values[0],
    }


def _summary_positive(summary: Mapping[str, Any]) -> bool:
    maximum = summary.get("maximum")
    return isinstance(maximum, int) and maximum > 0


def _summary_advanced(summary: Mapping[str, Any]) -> bool:
    delta = summary.get("delta")
    return isinstance(delta, int) and delta > 0


def _summary_zero(summary: Mapping[str, Any]) -> bool:
    maximum = summary.get("maximum")
    minimum = summary.get("minimum")
    return maximum == 0 and minimum == 0


def _cursor_metrics(samples: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    valid_samples = [sample for sample in samples if sample.get("valid") is True]
    timestamps = [int(sample["timestamp_unix_ms"]) for sample in valid_samples]
    ordered = all(left <= right for left, right in zip(timestamps, timestamps[1:]))
    duration = timestamps[-1] - timestamps[0] if timestamps else 0
    distinct_positions = {
        (int(sample["x"]), int(sample["y"])) for sample in valid_samples
    }
    maximum_displacement = 0.0
    total_path = 0.0
    movement_timestamps: list[int] = []
    valid_segments: list[list[Mapping[str, Any]]] = []
    previous_sample_valid = False
    for sample in samples:
        if sample.get("valid") is not True:
            previous_sample_valid = False
            continue
        if not previous_sample_valid:
            valid_segments.append([])
        valid_segments[-1].append(sample)
        previous_sample_valid = True
    for segment in valid_segments:
        if not segment:
            continue
        origin_x = int(segment[0]["x"])
        origin_y = int(segment[0]["y"])
        previous_x = origin_x
        previous_y = origin_y
        for sample in segment[1:]:
            x = int(sample["x"])
            y = int(sample["y"])
            step = math.hypot(x - previous_x, y - previous_y)
            if step > 0.0:
                movement_timestamps.append(int(sample["timestamp_unix_ms"]))
            total_path += step
            maximum_displacement = max(
                maximum_displacement,
                math.hypot(x - origin_x, y - origin_y),
            )
            previous_x = x
            previous_y = y
    return {
        "sample_count": len(samples),
        "valid_sample_count": len(valid_samples),
        "distinct_position_count": len(distinct_positions),
        "timestamps_ordered": ordered,
        "duration_ms": duration,
        "valid_segment_count": len(valid_segments),
        "maximum_displacement_px": round(maximum_displacement, 3),
        "total_path_px": round(total_path, 3),
        "movement_timestamps_unix_ms": movement_timestamps,
    }


def _metric_is_positive(detail: str, key: str) -> bool:
    return any(value > 0 for value in _metric_values(detail, key))


def _metric_is_one(detail: str, key: str) -> bool:
    return 1 in _metric_values(detail, key)


def _makcu_ack_intervals(
    health_events: Sequence[Mapping[str, Any]],
) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    previous: tuple[int, int] | None = None
    for event in health_events:
        detail = str(event.get("detail") or "")
        value = _metric_value(detail, "native_device_ack_completions")
        if value is None:
            continue
        current = (int(event["timestamp_unix_ms"]), value)
        if previous is not None and current[1] > previous[1]:
            intervals.append((previous[0], current[0]))
        previous = current
    return intervals


def evaluate_records(
    *,
    route: str,
    mobile_events: Sequence[Mapping[str, Any]],
    cursor_samples: Sequence[Mapping[str, Any]],
    protocol_contracts: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    if route not in REQUIRED_ROUTES:
        raise ValueError(f"unsupported physical output route: {route}")
    cursor = _cursor_metrics(cursor_samples)
    valid_samples = [sample for sample in cursor_samples if sample.get("valid") is True]
    capture_start = int(valid_samples[0]["timestamp_unix_ms"]) if valid_samples else 0
    capture_end = int(valid_samples[-1]["timestamp_unix_ms"]) if valid_samples else 0
    strict_events = [
        event
        for event in mobile_events
        if capture_start <= int(event["timestamp_unix_ms"]) <= capture_end
    ]
    health_events = [
        event for event in strict_events if event.get("event") == "mobile_runtime_health"
    ]
    counters = {
        key: _counter_summary(health_events, key) for key in _COUNTER_NAMES
    }
    route_selection_events = [
        event
        for event in mobile_events
        if event.get("event") == "mobile_control_output_route_selected"
        and capture_start - ROUTE_SELECTION_CONTEXT_MILLIS
        <= int(event["timestamp_unix_ms"])
        <= capture_end
    ]
    latest_route_selection = max(
        route_selection_events,
        key=lambda item: int(item["timestamp_unix_ms"]),
        default=None,
    )
    route_selected = latest_route_selection is not None and re.search(
        rf"(?<![A-Za-z0-9_])route={re.escape(route)}(?:\s|$)",
        str(latest_route_selection.get("detail") or ""),
    ) is not None
    cat6_connected = any(
        _metric_is_one(str(event.get("detail") or ""), "ethernet_network_bound")
        and _metric_is_positive(str(event.get("detail") or ""), "completed_access_units")
        for event in health_events
    )
    qnn_target_positive = any(
        "backend=QNN HTP" in str(event.get("detail") or "")
        and _metric_is_positive(str(event.get("detail") or ""), "qnn_executions")
        and _metric_is_positive(str(event.get("detail") or ""), "last_detection_count")
        for event in health_events
    )
    failures_zero = all(
        _summary_zero(counters[key])
        for key in (
            "qnn_failures",
            "consecutive_qnn_failures",
            "java_offer_rejections",
            "java_dispatch_failures",
            "native_move_completion_pending",
            "native_move_completion_timeouts",
        )
    )
    cursor_moved = (
        cursor["valid_sample_count"] >= MINIMUM_CURSOR_SAMPLES
        and cursor["timestamps_ordered"] is True
        and cursor["duration_ms"] >= MINIMUM_CAPTURE_DURATION_MILLIS
        and cursor["distinct_position_count"] >= 2
        and cursor["maximum_displacement_px"] >= MINIMUM_CURSOR_DISPLACEMENT_PIXELS
    )
    checks: dict[str, bool] = {
        "capture_window_valid": (
            bool(valid_samples)
            and cursor["timestamps_ordered"] is True
            and cursor["duration_ms"] >= MINIMUM_CAPTURE_DURATION_MILLIS
        ),
        "route_selected": route_selected,
        "runtime_health_samples_sufficient": len(health_events) >= 2,
        "cat6_stream_connected": cat6_connected,
        "qnn_htp_target_positive": qnn_target_positive,
        "candidate_moves_and_java_acceptances_advanced": (
            _summary_positive(counters["candidate_moves"])
            and _summary_advanced(counters["candidate_moves"])
            and _summary_positive(counters["java_offer_acceptances"])
            and _summary_advanced(counters["java_offer_acceptances"])
        ),
        "control_output_enabled": (
            _summary_positive(counters["output_requested"])
            and _summary_positive(counters["output_enabled"])
        ),
        "control_failures_zero": failures_zero,
        "windows_cursor_moved": cursor_moved,
        "route_activity_correlated_with_cursor": False,
    }
    movement_timestamps = [
        int(value) for value in cursor["movement_timestamps_unix_ms"]
    ]
    if route == BLUETOOTH_HID_ROUTE:
        accepted_events = [
            event
            for event in strict_events
            if event.get("event") == "bluetooth_hid_send_report"
            and re.search(r"(?<![A-Za-z0-9_])accepted=true(?:\s|$)", str(event.get("detail") or ""))
        ]
        rejected_events = [
            event
            for event in strict_events
            if event.get("event") == "bluetooth_hid_send_report"
            and re.search(r"(?<![A-Za-z0-9_])accepted=false(?:\s|$)", str(event.get("detail") or ""))
        ]
        acceptance_timestamps = [
            int(event["timestamp_unix_ms"]) for event in accepted_events
        ]
        checks.update(
            {
                "bluetooth_hid_send_report_accepted": bool(accepted_events),
                "bluetooth_hid_send_report_failures_zero": not rejected_events,
                "native_bluetooth_hid_api_acceptances_advanced": (
                    _summary_positive(counters["native_bluetooth_hid_api_acceptances"])
                    and _summary_advanced(counters["native_bluetooth_hid_api_acceptances"])
                ),
                "bluetooth_hid_native_failures_zero": _summary_zero(
                    counters["stale_bluetooth_hid_api_acceptances"]
                ),
            }
        )
        checks["route_activity_correlated_with_cursor"] = any(
            abs(movement - acceptance) <= EVENT_CLOCK_SKEW_MILLIS
            for movement in movement_timestamps
            for acceptance in acceptance_timestamps
        )
    else:
        identity_verified = any(
            all(
                required in str(event.get("detail") or "")
                for required in (
                    "serial_open=1",
                    "adapter_identity_verified=1",
                    "protocol_identity_verified=1",
                    "selected_baud=4000000",
                )
            )
            for event in health_events
        )
        makcu_failures_zero = all(
            _summary_zero(counters[key])
            for key in (
                "native_device_ack_failures",
                "stale_device_feedback",
                "device_acknowledgement_failures",
                "unexpected_device_responses",
                "response_parser_overflows",
                "delivery_failures",
                "consecutive_delivery_failures",
                "delivery_circuit_open",
                "delivery_circuit_trips",
            )
        )
        checks.update(
            {
                "makcu_runtime_identity_verified": identity_verified,
                "makcu_exact_protocol_identity_contract_bound": (
                    isinstance(protocol_contracts, Mapping)
                    and protocol_contracts.get("makcu_identity_response")
                    == EXPECTED_MAKCU_PROTOCOL_IDENTITY
                ),
                "makcu_native_device_acknowledgements_advanced": (
                    _summary_positive(counters["native_device_ack_completions"])
                    and _summary_advanced(counters["native_device_ack_completions"])
                ),
                "makcu_java_device_acknowledgements_advanced": (
                    _summary_positive(counters["device_move_acknowledgements"])
                    and _summary_advanced(counters["device_move_acknowledgements"])
                ),
                "makcu_device_failures_zero": makcu_failures_zero,
            }
        )
        acknowledgement_intervals = _makcu_ack_intervals(health_events)
        checks["route_activity_correlated_with_cursor"] = any(
            start - EVENT_CLOCK_SKEW_MILLIS
            <= movement
            <= end + EVENT_CLOCK_SKEW_MILLIS
            for movement in movement_timestamps
            for start, end in acknowledgement_intervals
        )
    return {
        "checks": checks,
        "metrics": {
            "capture_start_unix_ms": capture_start,
            "capture_end_unix_ms": capture_end,
            "event_count": len(strict_events),
            "runtime_health_sample_count": len(health_events),
            "route_selection_timestamp_unix_ms": (
                int(latest_route_selection["timestamp_unix_ms"])
                if latest_route_selection is not None
                else 0
            ),
            "cursor": cursor,
            "counters": counters,
        },
    }


def required_check_names(route: str) -> tuple[str, ...]:
    if route not in ROUTE_REQUIRED_CHECKS:
        raise ValueError(f"unsupported physical output route: {route}")
    return (*COMMON_REQUIRED_CHECKS, *ROUTE_REQUIRED_CHECKS[route])


def build_route_evidence_from_records(
    *,
    route: str,
    android_apk_sha256: str,
    device_serial: str,
    mobile_events: Sequence[Mapping[str, Any]],
    cursor_samples: Sequence[Mapping[str, Any]],
    source_mobile_logs: Sequence[Mapping[str, Any]],
    cursor_source: Mapping[str, Any],
) -> Mapping[str, Any]:
    protocol_contracts = (
        {"makcu_identity_response": EXPECTED_MAKCU_PROTOCOL_IDENTITY}
        if route == MAKCU_USB_ROUTE
        else {}
    )
    evaluation = evaluate_records(
        route=route,
        mobile_events=mobile_events,
        cursor_samples=cursor_samples,
        protocol_contracts=protocol_contracts,
    )
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "route": route,
        "android_apk_sha256": android_apk_sha256.lower(),
        "device_serial": device_serial,
        "protocol_contracts": protocol_contracts,
        "checks": evaluation["checks"],
        "metrics": evaluation["metrics"],
        "mobile_events": list(mobile_events),
        "cursor_samples": list(cursor_samples),
        "source_mobile_logs": list(source_mobile_logs),
        "cursor_source": dict(cursor_source),
    }


def route_evidence_errors(
    data: Mapping[str, Any],
    *,
    expected_route: str | None = None,
    expected_apk_sha256: str = "",
    expected_device_serial: str = "",
) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"physical route evidence schema is not {SCHEMA}")
    route = str(data.get("route") or "")
    if route not in REQUIRED_ROUTES:
        errors.append("physical route evidence route is invalid")
        return errors
    if expected_route and route != expected_route:
        errors.append(f"physical route evidence route is not {expected_route}")
    apk_sha256 = str(data.get("android_apk_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", apk_sha256):
        errors.append("physical route evidence android_apk_sha256 is invalid")
    elif expected_apk_sha256 and apk_sha256 != expected_apk_sha256.lower():
        errors.append("physical route evidence Android APK hash does not match")
    device_serial = str(data.get("device_serial") or "")
    if not device_serial:
        errors.append("physical route evidence device_serial is missing")
    elif expected_device_serial and device_serial != expected_device_serial:
        errors.append("physical route evidence device_serial does not match")
    mobile_events = data.get("mobile_events")
    cursor_samples = data.get("cursor_samples")
    if not isinstance(mobile_events, Sequence) or isinstance(mobile_events, (str, bytes)):
        errors.append("physical route evidence mobile_events are missing")
        return errors
    if not isinstance(cursor_samples, Sequence) or isinstance(cursor_samples, (str, bytes)):
        errors.append("physical route evidence cursor_samples are missing")
        return errors
    try:
        recomputed = evaluate_records(
            route=route,
            mobile_events=mobile_events,
            cursor_samples=cursor_samples,
            protocol_contracts=(
                data.get("protocol_contracts")
                if isinstance(data.get("protocol_contracts"), Mapping)
                else {}
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"physical route evidence records are invalid: {exc}")
        return errors
    if data.get("checks") != recomputed["checks"]:
        errors.append("physical route evidence checks do not match raw records")
    if data.get("metrics") != recomputed["metrics"]:
        errors.append("physical route evidence metrics do not match raw records")
    for name in required_check_names(route):
        if recomputed["checks"].get(name) is not True:
            errors.append(f"physical route evidence check {name} is not true")
    source_mobile_logs = data.get("source_mobile_logs")
    if not isinstance(source_mobile_logs, Sequence) or isinstance(
        source_mobile_logs, (str, bytes)
    ) or not source_mobile_logs:
        errors.append("physical route evidence source_mobile_logs are missing")
    else:
        for source in source_mobile_logs:
            if not isinstance(source, Mapping) or not re.fullmatch(
                r"[0-9a-f]{64}", str(source.get("sha256") or "").lower()
            ):
                errors.append("physical route evidence mobile log hash is invalid")
                break
    cursor_source = data.get("cursor_source")
    if not isinstance(cursor_source, Mapping) or not re.fullmatch(
        r"[0-9a-f]{64}", str(cursor_source.get("sha256") or "").lower()
    ):
        errors.append("physical route evidence cursor source hash is invalid")
    return errors


def create_route_evidence(
    *,
    route: str,
    android_apk: Path,
    device_serial: str,
    mobile_logs: Sequence[Path],
    cursor_samples_path: Path,
) -> Mapping[str, Any]:
    cursor_samples = read_cursor_samples(cursor_samples_path)
    valid_samples = [sample for sample in cursor_samples if sample.get("valid") is True]
    if not valid_samples:
        raise ValueError("cursor CSV has no valid samples")
    start = (
        int(valid_samples[0]["timestamp_unix_ms"])
        - ROUTE_SELECTION_CONTEXT_MILLIS
    )
    end = int(valid_samples[-1]["timestamp_unix_ms"]) + EVENT_CLOCK_SKEW_MILLIS
    mobile_events = [
        event
        for event in read_mobile_events(mobile_logs)
        if start <= int(event["timestamp_unix_ms"]) <= end
        and _is_relevant_event(str(event.get("event") or ""))
    ]
    source_mobile_logs = [
        {
            "name": path.name,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in mobile_logs
    ]
    cursor_source = {
        "name": cursor_samples_path.name,
        "size": cursor_samples_path.stat().st_size,
        "sha256": sha256_file(cursor_samples_path),
    }
    return build_route_evidence_from_records(
        route=route,
        android_apk_sha256=sha256_file(android_apk),
        device_serial=device_serial,
        mobile_events=mobile_events,
        cursor_samples=cursor_samples,
        source_mobile_logs=source_mobile_logs,
        cursor_source=cursor_source,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--route", required=True, choices=REQUIRED_ROUTES)
    parser.add_argument("--android-apk", required=True, type=Path)
    parser.add_argument("--device-serial", required=True)
    parser.add_argument("--mobile-log", required=True, action="append", type=Path)
    parser.add_argument("--cursor-samples", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    evidence = create_route_evidence(
        route=args.route,
        android_apk=args.android_apk.resolve(),
        device_serial=args.device_serial,
        mobile_logs=[path.resolve() for path in args.mobile_log],
        cursor_samples_path=args.cursor_samples.resolve(),
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    errors = route_evidence_errors(
        evidence,
        expected_route=args.route,
        expected_apk_sha256=sha256_file(args.android_apk.resolve()),
        expected_device_serial=args.device_serial,
    )
    print(
        "VISIONFORGE_PHYSICAL_OUTPUT_ROUTE_EVIDENCE "
        f"route={args.route} path={output} complete={not errors}",
        flush=True,
    )
    if errors:
        print("missing_or_invalid=" + ",".join(errors), flush=True)
        return 2 if args.require_complete else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
