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

from tools.verify_formal_release_bundle import (  # noqa: E402
    DEVICE_EVIDENCE_SCHEMA,
    EXPECTED_ANDROID_PACKAGE,
    EXPECTED_GAME_DISPLAY_NAMES,
    EXPECTED_GAME_TOKENS,
    EXPECTED_MODEL_TARGET_CONTRACTS,
    REQUIRED_DEVICE_EVIDENCE_FLAGS,
    default_host_release,
    latest_windows_release,
)
from tools.physical_output_route_evidence import (  # noqa: E402
    BLUETOOTH_HID_ROUTE,
    MAKCU_USB_ROUTE,
    REQUIRED_ROUTES,
    canonical_sha256 as physical_route_evidence_sha256,
    route_evidence_errors,
)
from tools.final_safe_idle_evidence import (  # noqa: E402
    decode_ui_xml,
    final_safe_idle_evidence_errors,
)


QNN_HTP_PATTERNS = (
    r"Result: graphExecute completed through QNN HTP backend",
    r"QNN realtime graphExecute=OK",
    r"backend=QNN HTP",
    r"qnn_executions=[1-9]\d*",
)
ETHERNET_PATTERNS = (
    r"ethernet_network_bound=(?:true|1)",
    r"\binternet_route=ethernet\b",
    r"\btransport=ethernet\b",
    r"\bethernet=true\b",
)
STREAM_PATTERNS = (
    r"completed_access_units=[1-9]\d*",
    r"decoder_accepted_access_units=[1-9]\d*",
    r"\baccess_unit_fps=([1-9]\d*|[0-9]+\.[1-9])",
)
CONTROL_MOVE_PATTERNS = (
    r"control_output_usb_write_completed",
    r"native_move_offer_accepted",
    r"offerNativeMove.*\btrue\b",
)
COUNTER_STRIKE_2_MODEL_TOKEN = "counter-strike-2-vombit-416-v8s"
COUNTER_STRIKE_2_AIM_TARGETS = frozenset(
    {"ct_body", "ct_head", "t_body", "t_head"}
)


def sha256_file(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_text(path: Path, limit_bytes: int = 8 * 1024 * 1024) -> str:
    data = path.read_bytes()[:limit_bytes]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _joined_text(paths: Sequence[Path]) -> str:
    parts: list[str] = []
    for path in paths:
        if path.exists() and path.is_file():
            parts.append(_read_text(path))
    return "\n".join(parts)


def _matches_any(text: str, patterns: Sequence[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _integer_metric(detail: str, name: str) -> int | None:
    match = re.search(rf"(?:^|\s){re.escape(name)}=(\d+)(?:\s|$)", detail)
    return int(match.group(1)) if match else None


def _float_metric(detail: str, name: str) -> float | None:
    match = re.search(
        rf"(?:^|\s){re.escape(name)}=(\d+(?:\.\d+)?)(?:\s|$)",
        detail,
    )
    return float(match.group(1)) if match else None


def _integer_pair_metric(detail: str, name: str) -> list[int] | None:
    match = re.search(
        rf"(?:^|\s){re.escape(name)}=(\d+),(\d+)(?:\s|$)",
        detail,
    )
    return [int(match.group(1)), int(match.group(2))] if match else None


def _counter_strike_2_qnn_observation(
    log_text: str,
) -> Mapping[str, Any] | None:
    """Return one model-attributed CS2 render/QNN metrics sample.

    A generic QNN health event is intentionally insufficient: another model
    can execute successfully while the CS2 library or selection path is still
    broken.  The mobile metrics event is the atomic ownership boundary for the
    selected model, native post-process contract, renderer and QNN counters.
    """
    observations: list[Mapping[str, Any]] = []
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        event = ""
        detail = line
        timestamp_unix_ms: int | None = None
        payload = _json_payload_from_log_line(line)
        if isinstance(payload, Mapping):
            event = str(payload.get("event") or "")
            detail = str(payload.get("detail") or "")
            timestamp = payload.get("timestamp_unix_ms")
            if isinstance(timestamp, int) and not isinstance(timestamp, bool):
                timestamp_unix_ms = timestamp
        if event and event != "mobile_pipeline_metrics":
            continue
        if f"model={COUNTER_STRIKE_2_MODEL_TOKEN}" not in detail:
            continue
        aim_target_match = re.search(r"(?:^|\s)aim_target=([^\s]+)", detail)
        if (
            aim_target_match is None
            or aim_target_match.group(1) not in COUNTER_STRIKE_2_AIM_TARGETS
            or "native_applied=true" not in detail
        ):
            continue
        rendered_frames = _integer_metric(detail, "rendered_frames")
        qnn_executions = _integer_metric(detail, "qnn_executions")
        qnn_failures = _integer_metric(detail, "qnn_failures")
        qnn_fps = _float_metric(detail, "qnn_fps")
        preprocess_p50 = _float_metric(detail, "preprocess_p50")
        qnn_p50 = _float_metric(detail, "qnn_p50")
        inference_total_p50 = _float_metric(detail, "inference_total_p50")
        decode_queue_p50 = _float_metric(detail, "decode_queue_p50")
        if (
            rendered_frames is not None
            and rendered_frames > 0
            and qnn_executions is not None
            and qnn_executions > 0
            and qnn_failures == 0
            and qnn_fps is not None
            and qnn_fps > 0.0
            and preprocess_p50 is not None
            and preprocess_p50 >= 0.0
            and qnn_p50 is not None
            and qnn_p50 >= 0.0
            and inference_total_p50 is not None
            and inference_total_p50 >= 0.0
            and decode_queue_p50 is not None
            and decode_queue_p50 >= 0.0
        ):
            observations.append({
                "event": event or "external_runtime_snapshot",
                "timestamp_unix_ms": timestamp_unix_ms,
                "model": COUNTER_STRIKE_2_MODEL_TOKEN,
                "aim_target": aim_target_match.group(1),
                "native_applied": True,
                "rendered_frames": rendered_frames,
                "qnn_executions": qnn_executions,
                "qnn_failures": qnn_failures,
                "qnn_fps": qnn_fps,
                "preprocess_p50_ms": preprocess_p50,
                "qnn_p50_ms": qnn_p50,
                "inference_total_p50_ms": inference_total_p50,
                "decode_queue_p50_ms": decode_queue_p50,
                "target_switches": _integer_metric(detail, "target_switches"),
                "motion_plans": _integer_metric(detail, "motion_plans"),
                "direction_flips_xy": _integer_pair_metric(
                    detail, "direction_flips"
                ),
                "detail_sha256": hashlib.sha256(
                    detail.encode("utf-8")
                ).hexdigest(),
            })
    if not observations:
        return None
    return max(
        observations,
        key=lambda observation: (
            int(observation.get("timestamp_unix_ms") or -1),
            int(observation.get("qnn_executions") or -1),
        ),
    )


def _json_payload_from_log_line(line: str) -> Mapping[str, Any] | None:
    """Decode a naked event or the JSON suffix emitted by Android logcat."""
    candidates = [line]
    object_start = line.find("{")
    if object_start > 0:
        candidates.append(line[object_start:])
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            return payload
    return None


def _counter_strike_2_qnn_full_chain(log_text: str) -> bool:
    return _counter_strike_2_qnn_observation(log_text) is not None


def _counter_strike_2_qnn_observation_from_sources(
    mobile_logs: Sequence[Path],
) -> Mapping[str, Any] | None:
    for path in mobile_logs:
        if not path.is_file():
            continue
        observation = _counter_strike_2_qnn_observation(_read_text(path))
        if observation is not None:
            return {
                **observation,
                "source_mobile_log": str(path),
                "source_mobile_log_sha256": sha256_file(path),
            }
    return None


def _ui_xml_files(ui_evidence_dir: Path | None) -> list[Path]:
    if ui_evidence_dir is None or not ui_evidence_dir.exists():
        return []
    return sorted(ui_evidence_dir.glob("*.xml"))


def _ui_text(ui_evidence_dir: Path | None) -> str:
    return _joined_text(_ui_xml_files(ui_evidence_dir))


def _has_content_desc(xml_text: str, value: str) -> bool:
    return f'content-desc="{value}"' in xml_text


def _ui_evidence_package_scope(xml_text: str) -> bool:
    vf_nodes = re.findall(
        r"<node\b(?=[^>]*content-desc=\"vf\.)[^>]*>",
        xml_text,
    )
    return bool(vf_nodes) and all(
        f'package="{EXPECTED_ANDROID_PACKAGE}"' in node for node in vf_nodes
    )


def _has_content_desc_with_text(xml_text: str, content_desc: str, text: str) -> bool:
    return (
        re.search(
            (
                r"<node\b"
                rf"(?=[^>]*content-desc=\"{re.escape(content_desc)}\")"
                rf"(?=[^>]*text=\"{re.escape(text)}\")"
                r"[^>]*>"
            ),
            xml_text,
        )
        is not None
    )


def _game_models_available(xml_text: str) -> bool:
    return all(_has_content_desc(xml_text, f"vf.game_model.{token}") for token in EXPECTED_GAME_TOKENS)


def _game_model_display_names_visible(xml_text: str) -> bool:
    return all(
        _has_content_desc_with_text(xml_text, f"vf.game_model.{token}", display_name)
        for token, display_name in EXPECTED_GAME_DISPLAY_NAMES.items()
    )


def _model_target_contracts() -> Mapping[str, Mapping[str, Any]]:
    return {
        token: {
            key: list(value) if isinstance(value, list) else value
            for key, value in contract.items()
        }
        for token, contract in EXPECTED_MODEL_TARGET_CONTRACTS.items()
    }


def _overwatch_enemy_target_contract(ui_evidence_dir: Path | None, all_xml_text: str) -> bool:
    candidates: list[Path] = []
    if ui_evidence_dir is not None and ui_evidence_dir.exists():
        candidates = sorted(ui_evidence_dir.glob("*ow2-targets.xml"))
    ow2_text = _joined_text(candidates) if candidates else all_xml_text
    if not _has_content_desc(ow2_text, "vf.game_model.overwatch2-416-yolov5"):
        return False
    if not _has_content_desc(ow2_text, "vf.aim_target.body"):
        return False
    if not _has_content_desc(ow2_text, "vf.aim_target.head"):
        return False
    return not any(
        _has_content_desc(ow2_text, f"vf.aim_target.{target}")
        for target in ("teammate", "ai", "crosshair")
    )


def _counter_strike_2_faction_target_contract(
    ui_evidence_dir: Path | None,
    all_xml_text: str,
) -> bool:
    candidates: list[Path] = []
    if ui_evidence_dir is not None and ui_evidence_dir.exists():
        candidates = sorted(ui_evidence_dir.glob("*cs2-targets.xml"))
    cs2_text = _joined_text(candidates) if candidates else all_xml_text
    if not _has_content_desc(
        cs2_text,
        "vf.game_model.counter-strike-2-vombit-416-v8s",
    ):
        return False
    if not all(
        _has_content_desc(cs2_text, f"vf.aim_target.{target}")
        for target in ("ct_body", "ct_head", "t_body", "t_head")
    ):
        return False
    return not any(
        _has_content_desc(cs2_text, f"vf.aim_target.{target}")
        for target in ("body", "head", "teammate", "ai", "crosshair")
    )


def _control_output_fail_closed(xml_text: str, log_text: str) -> bool:
    return (
        re.search(
            r'content-desc="vf\.control_output_toggle"[^>]*enabled="false"',
            xml_text,
            flags=re.IGNORECASE,
        )
        is not None
        or "control_output_auto_locked" in log_text
        or "control_output_fail_closed=true" in log_text
    )


def _load_physical_output_routes(
    *,
    route_evidence_paths: Mapping[str, Path],
    android_apk_sha256: str,
    device_serial: str,
    mobile_logs: Sequence[Path],
) -> tuple[Mapping[str, Any], Mapping[str, bool], Mapping[str, list[str]]]:
    archived_mobile_log_hashes = {
        sha256_file(path) for path in mobile_logs if path.is_file()
    }
    entries: dict[str, Any] = {}
    statuses: dict[str, bool] = {}
    errors_by_route: dict[str, list[str]] = {}
    for route in REQUIRED_ROUTES:
        path = route_evidence_paths.get(route)
        route_errors: list[str] = []
        payload: Mapping[str, Any] | None = None
        if path is None:
            route_errors.append("physical route evidence file is missing")
        elif not path.is_file():
            route_errors.append(f"physical route evidence file does not exist: {path}")
        else:
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(loaded, Mapping):
                    route_errors.append("physical route evidence root is not an object")
                else:
                    payload = loaded
            except (OSError, json.JSONDecodeError) as exc:
                route_errors.append(f"physical route evidence is unreadable: {exc}")
        if payload is not None:
            route_errors.extend(
                route_evidence_errors(
                    payload,
                    expected_route=route,
                    expected_apk_sha256=android_apk_sha256,
                    expected_device_serial=device_serial,
                )
            )
            source_logs = payload.get("source_mobile_logs")
            source_hashes = {
                str(source.get("sha256") or "").lower()
                for source in source_logs
                if isinstance(source, Mapping)
            } if isinstance(source_logs, Sequence) and not isinstance(
                source_logs, (str, bytes)
            ) else set()
            if not source_hashes:
                route_errors.append("physical route evidence mobile log hashes are missing")
            elif not source_hashes.issubset(archived_mobile_log_hashes):
                route_errors.append(
                    "physical route evidence mobile log is not listed in sources.mobile_logs"
                )
            entries[route] = {
                "evidence_sha256": physical_route_evidence_sha256(payload),
                "evidence": payload,
            }
        statuses[route] = not route_errors
        errors_by_route[route] = route_errors
    return entries, statuses, errors_by_route


def _load_final_safe_idle(
    *,
    evidence_path: Path | None,
    android_apk_sha256: str,
    device_serial: str,
    physical_output_routes: Mapping[str, Any],
    mobile_logs: Sequence[Path],
    ui_evidence_dir: Path | None,
) -> tuple[Mapping[str, Any], bool, list[str]]:
    errors: list[str] = []
    payload: Mapping[str, Any] | None = None
    if evidence_path is None:
        errors.append("final safe-idle evidence file is missing")
    elif not evidence_path.is_file():
        errors.append(f"final safe-idle evidence file does not exist: {evidence_path}")
    else:
        try:
            loaded = json.loads(evidence_path.read_text(encoding="utf-8"))
            if isinstance(loaded, Mapping):
                payload = loaded
            else:
                errors.append("final safe-idle evidence root is not an object")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"final safe-idle evidence is unreadable: {exc}")
    if payload is None:
        return {}, False, errors
    allowed_mobile_log_hashes = {
        sha256_file(path) for path in mobile_logs if path.is_file()
    }
    allowed_ui_xml_sources = {
        sha256_file(path): hashlib.sha256(
            decode_ui_xml(path.read_bytes()).encode("utf-8")
        ).hexdigest()
        for path in _ui_xml_files(ui_evidence_dir)
    }
    errors.extend(
        final_safe_idle_evidence_errors(
            payload,
            expected_apk_sha256=android_apk_sha256,
            expected_device_serial=device_serial,
            expected_physical_output_routes=physical_output_routes,
            allowed_mobile_log_hashes=allowed_mobile_log_hashes,
            allowed_ui_xml_hashes=set(allowed_ui_xml_sources),
            allowed_ui_xml_sources=allowed_ui_xml_sources,
        )
    )
    return (
        {
            "evidence_sha256": physical_route_evidence_sha256(payload),
            "evidence": payload,
        },
        not errors,
        errors,
    )


def build_device_evidence(
    *,
    android_apk: Path | None,
    windows_exe: Path | None,
    host_exe: Path | None,
    ui_evidence_dir: Path | None,
    mobile_logs: Sequence[Path],
    host_logs: Sequence[Path],
    output: Path,
    apk_installed: bool,
    device_serial: str,
    installed_package_version: str,
    physical_route_evidence_paths: Mapping[str, Path] | None = None,
    final_safe_idle_evidence_path: Path | None = None,
) -> Mapping[str, Any]:
    xml_text = _ui_text(ui_evidence_dir)
    log_text = _joined_text([*mobile_logs, *host_logs])
    cs2_qnn_observation = _counter_strike_2_qnn_observation_from_sources(
        mobile_logs
    )
    android_apk_sha256 = sha256_file(android_apk)
    physical_routes, route_statuses, physical_route_errors = _load_physical_output_routes(
        route_evidence_paths=physical_route_evidence_paths or {},
        android_apk_sha256=android_apk_sha256,
        device_serial=device_serial,
        mobile_logs=mobile_logs,
    )
    bluetooth_complete = route_statuses.get(BLUETOOTH_HID_ROUTE) is True
    makcu_complete = route_statuses.get(MAKCU_USB_ROUTE) is True
    same_apk = (
        bool(android_apk_sha256)
        and bluetooth_complete
        and makcu_complete
        and all(
            str(entry["evidence"].get("android_apk_sha256") or "").lower()
            == android_apk_sha256.lower()
            for entry in physical_routes.values()
        )
    )
    dual_route_complete = bluetooth_complete and makcu_complete and same_apk
    final_safe_idle, final_safe_idle_complete, final_safe_idle_errors = (
        _load_final_safe_idle(
            evidence_path=final_safe_idle_evidence_path,
            android_apk_sha256=android_apk_sha256,
            device_serial=device_serial,
            physical_output_routes=physical_routes,
            mobile_logs=mobile_logs,
            ui_evidence_dir=ui_evidence_dir,
        )
    )
    checks = {
        "apk_installed": apk_installed,
        "ui_evidence_package_scope": _ui_evidence_package_scope(xml_text),
        "qnn_htp_graph_execute": _matches_any(log_text, QNN_HTP_PATTERNS),
        "counter_strike_2_qnn_full_chain": cs2_qnn_observation is not None,
        "game_models_available": _game_models_available(xml_text),
        "game_model_display_names_visible": _game_model_display_names_visible(xml_text),
        "overwatch_enemy_target_contract": _overwatch_enemy_target_contract(ui_evidence_dir, xml_text),
        "counter_strike_2_faction_target_contract": (
            _counter_strike_2_faction_target_contract(ui_evidence_dir, xml_text)
        ),
        "ethernet_link": _matches_any(log_text, ETHERNET_PATTERNS),
        "host_mobile_stream_connected": _matches_any(log_text, STREAM_PATTERNS),
        "control_output_fail_closed": _control_output_fail_closed(xml_text, log_text),
        "control_move_lock_smoke": dual_route_complete,
        "bluetooth_hid_physical_e2e": bluetooth_complete,
        "makcu_usb_physical_e2e": makcu_complete,
        "dual_output_routes_same_apk": same_apk,
        "final_safe_idle_restored": final_safe_idle_complete,
    }
    evidence = {
        "schema": DEVICE_EVIDENCE_SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "device_serial": device_serial,
        "installed_package_name": EXPECTED_ANDROID_PACKAGE,
        "installed_package_version": installed_package_version,
        "windows_exe_sha256": sha256_file(windows_exe),
        "android_apk_sha256": android_apk_sha256,
        "host_exe_sha256": sha256_file(host_exe),
        "game_model_tokens": list(EXPECTED_GAME_TOKENS),
        "game_display_names": dict(EXPECTED_GAME_DISPLAY_NAMES),
        "model_target_contracts": _model_target_contracts(),
        "physical_output_routes": physical_routes,
        "physical_output_route_errors": physical_route_errors,
        "final_safe_idle": final_safe_idle,
        "final_safe_idle_errors": final_safe_idle_errors,
        "observations": {
            "counter_strike_2_qnn_full_chain": cs2_qnn_observation or {},
            "legacy_generic_move_signal_observed": _matches_any(
                log_text,
                CONTROL_MOVE_PATTERNS,
            ),
            "legacy_generic_move_signal_is_release_proof": False,
        },
        "checks": checks,
        "sources": {
            "android_apk": str(android_apk) if android_apk else "",
            "windows_exe": str(windows_exe) if windows_exe else "",
            "host_exe": str(host_exe) if host_exe else "",
            "ui_evidence_dir": str(ui_evidence_dir) if ui_evidence_dir else "",
            "mobile_logs": [str(path) for path in mobile_logs],
            "host_logs": [str(path) for path in host_logs],
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8")
    return evidence


def _default_output(ui_evidence_dir: Path | None) -> Path:
    if ui_evidence_dir is not None:
        return ui_evidence_dir / "formal_device_evidence.json"
    return ROOT / "analysis_output" / "formal_device_evidence.json"


def _missing_complete_evidence_fields(evidence: Mapping[str, Any]) -> list[str]:
    missing = [
        name for name in REQUIRED_DEVICE_EVIDENCE_FLAGS if evidence["checks"].get(name) is not True
    ]
    if not str(evidence.get("device_serial") or ""):
        missing.append("device_serial")
    if not str(evidence.get("installed_package_version") or ""):
        missing.append("installed_package_version")
    return missing


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-apk", type=Path, default=None)
    parser.add_argument("--windows-exe", type=Path, default=None)
    parser.add_argument("--host-exe", type=Path, default=None)
    parser.add_argument("--ui-evidence-dir", type=Path, default=None)
    parser.add_argument("--mobile-log", action="append", type=Path, default=[])
    parser.add_argument("--host-log", action="append", type=Path, default=[])
    parser.add_argument("--bluetooth-route-evidence", type=Path, default=None)
    parser.add_argument("--makcu-route-evidence", type=Path, default=None)
    parser.add_argument("--final-safe-idle-evidence", type=Path, default=None)
    parser.add_argument("--device-serial", default="")
    parser.add_argument("--installed-package-version", default="")
    parser.add_argument("--apk-installed", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    windows_exe = args.windows_exe or latest_windows_release()
    host_exe = args.host_exe or default_host_release()
    output = args.output or _default_output(args.ui_evidence_dir)
    evidence = build_device_evidence(
        android_apk=args.android_apk.resolve() if args.android_apk else None,
        windows_exe=windows_exe.resolve() if windows_exe else None,
        host_exe=host_exe.resolve() if host_exe else None,
        ui_evidence_dir=args.ui_evidence_dir.resolve() if args.ui_evidence_dir else None,
        mobile_logs=[path.resolve() for path in args.mobile_log],
        host_logs=[path.resolve() for path in args.host_log],
        output=output.resolve(),
        apk_installed=args.apk_installed,
        device_serial=args.device_serial,
        installed_package_version=args.installed_package_version,
        physical_route_evidence_paths={
            route: path.resolve()
            for route, path in (
                (BLUETOOTH_HID_ROUTE, args.bluetooth_route_evidence),
                (MAKCU_USB_ROUTE, args.makcu_route_evidence),
            )
            if path is not None
        },
        final_safe_idle_evidence_path=(
            args.final_safe_idle_evidence.resolve()
            if args.final_safe_idle_evidence
            else None
        ),
    )
    missing = _missing_complete_evidence_fields(evidence)
    print(f"VISIONFORGE_FORMAL_DEVICE_EVIDENCE path={output} complete={not missing}", flush=True)
    if missing:
        print("missing_checks=" + ",".join(missing), flush=True)
        return 2 if args.require_complete else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
