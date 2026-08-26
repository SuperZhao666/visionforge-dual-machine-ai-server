from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_dual_machine_release_readiness import (  # noqa: E402
    check_reverse_resistance_contracts,
    check_source_contracts,
)
from tools.physical_output_route_evidence import (  # noqa: E402
    REQUIRED_ROUTES,
    canonical_sha256 as physical_route_evidence_sha256,
    route_evidence_errors,
)
from tools.final_safe_idle_evidence import (  # noqa: E402
    decode_ui_xml,
    final_safe_idle_evidence_errors,
)


ANDROID_DEBUG_CERT_SHA256 = (
    "179faf0492d0b49d66bdefcc66bc51541602525a25b8af8c4e42345a770c7155"
)
FORMAL_BUNDLE_REPORT_SCHEMA = "visionforge-formal-release-bundle-v1"
FORMAL_BUNDLE_REQUIRED_CHECKS = frozenset(
    {
        "windows_release",
        "android_release_apk",
        "host_release",
        "source_contracts",
        "device_evidence",
    }
)
EXPECTED_ANDROID_PACKAGE = "com.visionforge.mobile"
CANONICAL_HOST_EXE_NAME = "VFHost.exe"
DEVICE_EVIDENCE_SCHEMA = "visionforge-dual-machine-device-evidence-v3"
EXPECTED_ANDROID_MODELS = (
    "lib/arm64-v8a/libvalorant_416_v11s_no_flash_w8a16.so",
    "lib/arm64-v8a/libow2_416_w8a16.so",
    "lib/arm64-v8a/libdelta_416_v8s_w8a16.so",
    "lib/arm64-v8a/libcs2_vombit_416_v8s_w8a16.so",
)
EXPECTED_QNN_HTP_RUNTIME = (
    "lib/arm64-v8a/libvisionforge_qnn_htp.so",
    "lib/arm64-v8a/libQnnHtp.so",
    "lib/arm64-v8a/libQnnHtpPrepare.so",
    "lib/arm64-v8a/libQnnHtpV68Stub.so",
    "lib/arm64-v8a/libQnnHtpV69Stub.so",
    "lib/arm64-v8a/libQnnHtpV73Stub.so",
    "lib/arm64-v8a/libQnnHtpV75Stub.so",
    "lib/arm64-v8a/libQnnHtpV79Stub.so",
    "assets/qnn/libQnnHtp.so",
    "assets/qnn/libQnnHtpV68Skel.so",
    "assets/qnn/libQnnHtpV69Skel.so",
    "assets/qnn/libQnnHtpV73Skel.so",
    "assets/qnn/libQnnHtpV75Skel.so",
    "assets/qnn/libQnnHtpV79Skel.so",
)
CS2_MODEL_TOKEN = "counter-strike-2-vombit-416-v8s"
CS2_QNN_LIBRARY = "libcs2_vombit_416_v8s_w8a16.so"
CS2_DEX_MARKERS = (
    CS2_MODEL_TOKEN,
    CS2_QNN_LIBRARY,
    "vf.game_model.",
    "ct_body",
    "ct_head",
    "t_body",
    "t_head",
)
CS2_NATIVE_MARKERS = (
    CS2_MODEL_TOKEN,
    CS2_QNN_LIBRARY,
    "ct_body",
    "ct_head",
    "t_body",
    "t_head",
)
FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS = (
    "forTestPrivateScalar",
    "sec1ForTestScalar",
    "finishedKeyForTest",
    "channelBindingExporterForTest",
    "AuthenticatedPeerHandshakeV1SelfTest",
    "PairGenerationProposalV1SelfTest",
    "AndroidBoundPeerHandshakeSessionSelfTest",
    "AuthenticatedPeerHandshakeV1InstrumentationProbe",
    "ANDROID_AUTHENTICATED_PEER_HANDSHAKE_V1_INSTRUMENTATION_OK",
    "AndroidBoundPeerHandshakeSessionInstrumentationProbe",
    "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK",
    "RejectingPrivateKey",
    "fixedAgreement",
)
REQUIRED_DEVICE_EVIDENCE_FLAGS = (
    "apk_installed",
    "ui_evidence_package_scope",
    "qnn_htp_graph_execute",
    "counter_strike_2_qnn_full_chain",
    "game_models_available",
    "game_model_display_names_visible",
    "overwatch_enemy_target_contract",
    "counter_strike_2_faction_target_contract",
    "ethernet_link",
    "host_mobile_stream_connected",
    "control_output_fail_closed",
    "control_move_lock_smoke",
    "bluetooth_hid_physical_e2e",
    "makcu_usb_physical_e2e",
    "dual_output_routes_same_apk",
    "final_safe_idle_restored",
)
EXPECTED_GAME_TOKENS = (
    "valorant-yellow-416-v11s-no-flash",
    "overwatch2-416-yolov5",
    "delta-force-416-v8s",
    "counter-strike-2-vombit-416-v8s",
)
EXPECTED_GAME_DISPLAY_NAMES = {
    "valorant-yellow-416-v11s-no-flash": "无畏契约",
    "overwatch2-416-yolov5": "守望先锋",
    "delta-force-416-v8s": "三角洲行动",
    "counter-strike-2-vombit-416-v8s": "反恐精英2",
}
EXPECTED_MODEL_TARGET_CONTRACTS = {
    "overwatch2-416-yolov5": {
        "game_display_name": "守望先锋",
        "lock_class_id": 0,
        "lock_class_name": "enemy_body",
        "ignored_class_ids": [1],
        "ignored_class_names": ["non_enemy_body"],
        "supported_aim_targets": ["body", "head"],
        "unsupported_aim_targets": ["teammate", "ai", "crosshair"],
        "head_target_source": "geometric_body_box",
    },
    "counter-strike-2-vombit-416-v8s": {
        "game_display_name": "反恐精英2",
        "ct_body_class_id": 0,
        "ct_head_class_id": 1,
        "t_body_class_id": 2,
        "t_head_class_id": 3,
        "default_aim_target": "t_head",
        "enemy_selection_mode": "player_faction_pair",
        "supported_aim_targets": ["ct_body", "ct_head", "t_body", "t_head"],
        "unsupported_aim_targets": [
            "body",
            "head",
            "teammate",
            "ai",
            "crosshair",
        ],
        "cross_faction_pairing_allowed": False,
    },
}


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    evidence: Mapping[str, Any]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _pass(
    name: str,
    detail: str,
    evidence: Mapping[str, Any] | None = None,
) -> CheckResult:
    return CheckResult(name, True, detail, evidence or {})


def _fail(
    name: str,
    detail: str,
    evidence: Mapping[str, Any] | None = None,
) -> CheckResult:
    return CheckResult(name, False, detail, evidence or {})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Mapping[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def model_target_contract_errors(data: Mapping[str, Any]) -> list[str]:
    contracts = data.get("model_target_contracts")
    if not isinstance(contracts, Mapping):
        return ["device evidence model_target_contracts is missing"]
    errors: list[str] = []
    for token, expected in EXPECTED_MODEL_TARGET_CONTRACTS.items():
        actual = contracts.get(token)
        if not isinstance(actual, Mapping):
            errors.append(f"device evidence model_target_contracts.{token} is missing")
            continue
        for key, expected_value in expected.items():
            if actual.get(key) != expected_value:
                errors.append(
                    f"device evidence model_target_contracts.{token}.{key} is invalid"
                )
    return errors


def game_display_name_errors(data: Mapping[str, Any]) -> list[str]:
    names = data.get("game_display_names")
    if not isinstance(names, Mapping):
        return ["device evidence game_display_names is missing"]
    errors: list[str] = []
    for token, expected in EXPECTED_GAME_DISPLAY_NAMES.items():
        if names.get(token) != expected:
            errors.append(f"device evidence game_display_names.{token} is invalid")
    return errors


def counter_strike_2_runtime_observation_errors(
    data: Mapping[str, Any],
    *,
    allowed_mobile_log_hashes: set[str] | None = None,
) -> list[str]:
    observations = data.get("observations")
    if not isinstance(observations, Mapping):
        return ["device evidence observations is missing"]
    observation = observations.get("counter_strike_2_qnn_full_chain")
    if not isinstance(observation, Mapping):
        return ["device evidence CS2 QNN full-chain observation is missing"]

    token = CS2_MODEL_TOKEN
    allowed_targets = set(
        EXPECTED_MODEL_TARGET_CONTRACTS[token]["supported_aim_targets"]
    )
    errors: list[str] = []
    if observation.get("event") not in {
        "mobile_pipeline_metrics",
        "external_runtime_snapshot",
    }:
        errors.append("device evidence CS2 QNN event is invalid")
    if observation.get("model") != token:
        errors.append("device evidence CS2 QNN model identity is invalid")
    if observation.get("aim_target") not in allowed_targets:
        errors.append("device evidence CS2 QNN aim target is invalid")
    if observation.get("native_applied") is not True:
        errors.append("device evidence CS2 native model contract was not applied")
    for name in ("rendered_frames", "qnn_executions"):
        value = observation.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            errors.append(f"device evidence CS2 {name} is not positive")
    qnn_failures = observation.get("qnn_failures")
    if qnn_failures != 0 or isinstance(qnn_failures, bool):
        errors.append("device evidence CS2 qnn_failures is not zero")
    performance_fields = {
        "qnn_fps": True,
        "preprocess_p50_ms": False,
        "qnn_p50_ms": False,
        "inference_total_p50_ms": False,
        "decode_queue_p50_ms": False,
    }
    for name, must_be_positive in performance_fields.items():
        value = observation.get(name)
        valid_number = (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        )
        if not valid_number or (value <= 0 if must_be_positive else value < 0):
            qualifier = "positive" if must_be_positive else "non-negative"
            errors.append(f"device evidence CS2 {name} is not {qualifier}")
    detail_sha256 = str(observation.get("detail_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", detail_sha256):
        errors.append("device evidence CS2 metrics detail hash is invalid")
    source_sha256 = str(
        observation.get("source_mobile_log_sha256") or ""
    ).lower()
    if allowed_mobile_log_hashes is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
            errors.append("device evidence CS2 source mobile log hash is invalid")
        elif source_sha256 not in allowed_mobile_log_hashes:
            errors.append(
                "device evidence CS2 source is not an archived mobile log"
            )
    return errors


def physical_output_route_errors(
    data: Mapping[str, Any],
    *,
    expected_apk_sha256: str,
    expected_device_serial: str,
    allowed_mobile_log_hashes: set[str] | None = None,
) -> list[str]:
    routes = data.get("physical_output_routes")
    if not isinstance(routes, Mapping):
        return ["device evidence physical_output_routes is missing"]
    errors: list[str] = []
    for route in REQUIRED_ROUTES:
        entry = routes.get(route)
        if not isinstance(entry, Mapping):
            errors.append(f"device evidence physical_output_routes.{route} is missing")
            continue
        evidence = entry.get("evidence")
        if not isinstance(evidence, Mapping):
            errors.append(
                f"device evidence physical_output_routes.{route}.evidence is missing"
            )
            continue
        expected_digest = str(entry.get("evidence_sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            errors.append(
                f"device evidence physical_output_routes.{route}.evidence_sha256 is invalid"
            )
        elif physical_route_evidence_sha256(evidence) != expected_digest:
            errors.append(
                f"device evidence physical_output_routes.{route} digest does not match"
            )
        route_errors = route_evidence_errors(
            evidence,
            expected_route=route,
            expected_apk_sha256=expected_apk_sha256,
            expected_device_serial=expected_device_serial,
        )
        errors.extend(f"{route}: {error}" for error in route_errors)
        if allowed_mobile_log_hashes is not None:
            source_logs = evidence.get("source_mobile_logs")
            source_hashes = {
                str(source.get("sha256") or "").lower()
                for source in source_logs
                if isinstance(source, Mapping)
            } if isinstance(source_logs, Sequence) and not isinstance(
                source_logs, (str, bytes)
            ) else set()
            if not source_hashes:
                errors.append(f"{route}: physical route mobile log hashes are missing")
            elif not source_hashes.issubset(allowed_mobile_log_hashes):
                errors.append(
                    f"{route}: physical route mobile log is not archived by device evidence"
                )
    return errors


def final_safe_idle_errors(
    data: Mapping[str, Any],
    *,
    expected_apk_sha256: str,
    expected_device_serial: str,
    allowed_mobile_log_hashes: set[str] | None = None,
    allowed_ui_xml_hashes: set[str] | None = None,
    allowed_ui_xml_sources: Mapping[str, str] | None = None,
) -> list[str]:
    entry = data.get("final_safe_idle")
    if not isinstance(entry, Mapping):
        return ["device evidence final_safe_idle is missing"]
    evidence = entry.get("evidence")
    if not isinstance(evidence, Mapping):
        return ["device evidence final_safe_idle.evidence is missing"]
    errors: list[str] = []
    expected_digest = str(entry.get("evidence_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        errors.append("device evidence final_safe_idle.evidence_sha256 is invalid")
    elif physical_route_evidence_sha256(evidence) != expected_digest:
        errors.append("device evidence final_safe_idle digest does not match")
    physical_routes = data.get("physical_output_routes")
    errors.extend(
        final_safe_idle_evidence_errors(
            evidence,
            expected_apk_sha256=expected_apk_sha256,
            expected_device_serial=expected_device_serial,
            expected_physical_output_routes=(
                physical_routes if isinstance(physical_routes, Mapping) else {}
            ),
            allowed_mobile_log_hashes=allowed_mobile_log_hashes,
            allowed_ui_xml_hashes=allowed_ui_xml_hashes,
            allowed_ui_xml_sources=allowed_ui_xml_sources,
        )
    )
    return errors


def _resolve_device_evidence_source(evidence_path: Path, raw_path: object) -> Path:
    path = Path(str(raw_path or ""))
    if path.is_absolute():
        return path.resolve()
    local = (evidence_path.parent / path).resolve()
    if local.exists():
        return local
    return (ROOT / path).resolve()


def _device_evidence_mobile_log_hashes(
    evidence_path: Path,
    data: Mapping[str, Any],
) -> tuple[set[str], list[str]]:
    sources = data.get("sources")
    if not isinstance(sources, Mapping):
        return set(), ["device evidence sources are missing"]
    values = sources.get("mobile_logs")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        return set(), ["device evidence sources.mobile_logs are missing"]
    hashes: set[str] = set()
    errors: list[str] = []
    for value in values:
        path = _resolve_device_evidence_source(evidence_path, value)
        if not path.is_file():
            errors.append(f"device evidence mobile log source is missing: {path}")
            continue
        hashes.add(sha256_file(path))
    return hashes, errors


def _device_evidence_ui_xml_sources(
    evidence_path: Path,
    data: Mapping[str, Any],
) -> tuple[Mapping[str, str], list[str]]:
    sources = data.get("sources")
    if not isinstance(sources, Mapping):
        return {}, ["device evidence sources are missing"]
    raw_directory = sources.get("ui_evidence_dir")
    if not str(raw_directory or ""):
        return {}, ["device evidence sources.ui_evidence_dir is missing"]
    directory = _resolve_device_evidence_source(evidence_path, raw_directory)
    if not directory.is_dir():
        return {}, [f"device evidence UI source directory is missing: {directory}"]
    files = sorted(directory.glob("*.xml"))
    if not files:
        return {}, ["device evidence UI source directory has no XML files"]
    return {
        sha256_file(path): hashlib.sha256(
            decode_ui_xml(path.read_bytes()).encode("utf-8")
        ).hexdigest()
        for path in files
    }, []


def _find_latest(pattern: str, directory: Path) -> Path | None:
    candidates = sorted(
        directory.glob(pattern),
        key=lambda candidate: candidate.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def latest_windows_release() -> Path | None:
    return _find_latest("VisionForge_Protected*.exe", ROOT / "releases")


def default_host_release() -> Path | None:
    preferred = ROOT / "dual_machine_runtime" / "out" / CANONICAL_HOST_EXE_NAME
    if preferred.exists():
        return preferred
    candidates = sorted(
        (ROOT / "analysis_output").rglob(CANONICAL_HOST_EXE_NAME),
        key=lambda candidate: candidate.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def load_sha256_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        raise ValueError("empty sha256 file")
    return text.split()[0].lower()


def _check_windows_verify_payload(
    report: Mapping[str, Any],
    exe_sha256: str,
) -> list[str]:
    errors: list[str] = []
    if str(report.get("exe_sha256", "")).lower() not in ("", exe_sha256):
        errors.append("verify report exe_sha256 does not match the EXE")
    published = report.get("published")
    if isinstance(published, Mapping):
        if str(published.get("sha256", "")).lower() != exe_sha256:
            errors.append("published sha256 does not match the EXE")
    checks = report.get("checks")
    if not isinstance(checks, Mapping):
        return ["verify report has no checks object"]

    binary_protection = checks.get("binary_protection")
    if not isinstance(binary_protection, Mapping) or not binary_protection.get("ok"):
        errors.append("binary protection report was not accepted")
    clean_profile = checks.get("clean_profile")
    if not isinstance(clean_profile, Mapping) or not clean_profile.get("ok"):
        errors.append("clean profile packaged verification did not pass")
    resources = checks.get("resources")
    if isinstance(resources, Mapping):
        if resources.get("missing_required_resources"):
            errors.append("Windows release is missing required packaged resources")
    else:
        errors.append("Windows resource check is missing")
    runtime_dll = checks.get("runtime_dll_boundary")
    if isinstance(runtime_dll, Mapping):
        for key in (
            "forbidden_native_runtime_dlls",
            "missing_required_onnxruntime_dlls",
            "unexpected_runtime_files",
            "unexpected_top_level_dlls",
        ):
            if runtime_dll.get(key):
                errors.append(f"runtime_dll_boundary has {key}")
    else:
        errors.append("runtime_dll_boundary check is missing")
    runtime_ort = checks.get("runtime_ort_boundary")
    if isinstance(runtime_ort, Mapping):
        validator = runtime_ort.get("validator")
        if runtime_ort.get("missing") or runtime_ort.get("errors"):
            errors.append("runtime_ort_boundary reported missing files or errors")
        if isinstance(validator, Mapping) and not validator.get("ok"):
            errors.append("dual ORT runtime validator did not pass")
    else:
        errors.append("runtime_ort_boundary check is missing")

    for check_name in (
        "self_test",
        "self_test_second",
        "diagnostics_json",
        "runtime_contract_json",
        "cpu_self_test",
        "integrity_json",
    ):
        result = checks.get(check_name)
        if not isinstance(result, Mapping) or result.get("returncode") != 0:
            errors.append(f"{check_name} did not pass")
    integrity_parse = checks.get("integrity_json_parse")
    if not isinstance(integrity_parse, Mapping) or not integrity_parse.get("ok"):
        errors.append("integrity_json_parse did not pass")
    return errors


def verify_windows_release(
    exe_path: Path,
    verify_report_path: Path | None = None,
    sha256_path: Path | None = None,
) -> CheckResult:
    if not exe_path.exists() or exe_path.stat().st_size <= 0:
        return _fail("windows_release", "Windows EXE is missing or empty", {"exe": str(exe_path)})
    exe_sha256 = sha256_file(exe_path)
    evidence: dict[str, Any] = {
        "exe": str(exe_path),
        "size": exe_path.stat().st_size,
        "sha256": exe_sha256,
    }
    errors: list[str] = []
    with exe_path.open("rb") as handle:
        if handle.read(2) != b"MZ":
            errors.append("Windows EXE does not start with an MZ header")

    report_path = verify_report_path or exe_path.with_suffix(exe_path.suffix + ".verify.json")
    evidence["verify_report"] = str(report_path)
    if not report_path.exists():
        errors.append("Windows verify report is missing")
    else:
        try:
            report = read_json(report_path)
            errors.extend(_check_windows_verify_payload(report, exe_sha256))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Windows verify report is unreadable: {exc}")

    digest_path = sha256_path or exe_path.with_suffix(exe_path.suffix + ".sha256")
    evidence["sha256_file"] = str(digest_path)
    if not digest_path.exists():
        errors.append("Windows sha256 sidecar is missing")
    else:
        try:
            expected = load_sha256_file(digest_path)
            if expected != exe_sha256:
                errors.append("Windows sha256 sidecar does not match the EXE")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Windows sha256 sidecar is unreadable: {exc}")

    if errors:
        evidence["errors"] = errors
        return _fail("windows_release", "; ".join(errors), evidence)
    return _pass("windows_release", "Windows protected EXE passed release report checks", evidence)


def inspect_apk_zip(apk_path: Path) -> Mapping[str, Any]:
    with zipfile.ZipFile(apk_path) as archive:
        names = set(archive.namelist())
        dex_names = sorted(
            name
            for name in names
            if re.fullmatch(r"classes(?:\d+)?\.dex", name)
        )
        dex_contents = b"".join(archive.read(name) for name in dex_names)
        native_bridge_name = "lib/arm64-v8a/libvisionforge_qnn_htp.so"
        native_contents = (
            archive.read(native_bridge_name)
            if native_bridge_name in names
            else b""
        )
        resource_contents = (
            archive.read("resources.arsc") if "resources.arsc" in names else b""
        )
    required = (*EXPECTED_ANDROID_MODELS, *EXPECTED_QNN_HTP_RUNTIME)
    missing = [name for name in required if name not in names]
    missing_dex_markers = [
        marker
        for marker in CS2_DEX_MARKERS
        if marker.encode("ascii") not in dex_contents
    ]
    missing_native_markers = [
        marker
        for marker in CS2_NATIVE_MARKERS
        if marker.encode("ascii") not in native_contents
    ]
    forbidden_test_seam_markers = [
        marker
        for marker in FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS
        if marker.encode("ascii") in dex_contents
    ]
    return {
        "entry_count": len(names),
        "required_entries": list(required),
        "missing_required_entries": missing,
        "dex_entries": dex_names,
        "missing_cs2_dex_markers": missing_dex_markers,
        "missing_cs2_native_markers": missing_native_markers,
        "forbidden_test_seam_markers": forbidden_test_seam_markers,
        "cs2_string_resource_name_present": (
            b"game_counter_strike_2" in resource_contents
        ),
    }


def aapt_values_include_cs2_display_name(text: str) -> bool:
    return (
        "com.visionforge.mobile:string/game_counter_strike_2" in text
        and '(string8) "反恐精英2"' in text
    )


def parse_aapt_badging_output(text: str) -> Mapping[str, Any]:
    package_match = re.search(
        r"package: name='(?P<package>[^']+)'(?:[^\n]*versionCode='(?P<code>[^']+)')?"
        r"(?:[^\n]*versionName='(?P<name>[^']+)')?",
        text,
    )
    return {
        "package": package_match.group("package") if package_match else "",
        "version_code": package_match.group("code") if package_match else "",
        "version_name": package_match.group("name") if package_match else "",
        "debuggable": "application-debuggable" in text,
    }


def parse_apksigner_output(text: str) -> Mapping[str, Any]:
    signer_dns = re.findall(r"Signer #\d+ certificate DN: (.+)", text)
    signer_sha256 = [
        value.lower()
        for value in re.findall(r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", text)
    ]
    debug_dn = any("CN=Android Debug" in value for value in signer_dns)
    debug_digest = ANDROID_DEBUG_CERT_SHA256 in signer_sha256
    return {
        "v1_verified": bool(
            re.search(r"Verified using v1 scheme \(JAR signing\): true", text)
        ),
        "v2_verified": bool(
            re.search(r"Verified using v2 scheme \(APK Signature Scheme v2\): true", text)
        ),
        "v3_verified": bool(
            re.search(r"Verified using v3 scheme \(APK Signature Scheme v3\): true", text)
        ),
        "android_debug_certificate": debug_dn or debug_digest,
        "signer_dns": signer_dns,
        "signer_sha256": signer_sha256,
    }


def android_apk_signing_errors(
    signing: Mapping[str, Any],
    *,
    require_production_signing: bool,
) -> tuple[str, ...]:
    errors: list[str] = []
    if not signing["v2_verified"] and not signing["v3_verified"]:
        errors.append("APK is not verified with Signature Scheme v2 or v3")
    if require_production_signing:
        if signing["v1_verified"]:
            errors.append("production APK unexpectedly enables legacy JAR signing")
        if not signing["v3_verified"]:
            errors.append("production APK is not verified with Signature Scheme v3")
        if len(signing["signer_sha256"]) != 1:
            errors.append("production APK must contain exactly one current signer")
        if signing["android_debug_certificate"]:
            errors.append("APK is signed with Android Debug certificate")
    return tuple(errors)


def resolve_android_tool(root: Path, name: str) -> Path | str:
    candidate = root / ".android-sdk" / "build-tools" / "35.0.0" / name
    if candidate.exists():
        return candidate
    command = shutil.which(name)
    if command:
        return command
    if name.endswith(".bat"):
        command = shutil.which(name[:-4])
        if command:
            return command
    raise FileNotFoundError(f"{name} not found")


def run_text_command(command: Sequence[str | Path], timeout: int = 60) -> Mapping[str, Any]:
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return {
        "cmd": [str(part) for part in command],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def verify_android_release_apk(
    apk_path: Path,
    *,
    require_production_signing: bool,
) -> CheckResult:
    if not apk_path.exists() or apk_path.stat().st_size <= 0:
        return _fail("android_release_apk", "Android APK is missing or empty", {"apk": str(apk_path)})
    apk_sha256 = sha256_file(apk_path)
    evidence: dict[str, Any] = {
        "apk": str(apk_path),
        "size": apk_path.stat().st_size,
        "sha256": apk_sha256,
    }
    errors: list[str] = []
    try:
        zip_report = inspect_apk_zip(apk_path)
        evidence["zip"] = zip_report
        if zip_report["missing_required_entries"]:
            errors.append("APK is missing required model or QNN HTP entries")
        if zip_report["missing_cs2_dex_markers"]:
            errors.append("APK DEX is missing CS2 model, UI or target markers")
        if zip_report["missing_cs2_native_markers"]:
            errors.append("APK native bridge is missing the CS2 runtime contract")
        if zip_report["forbidden_test_seam_markers"]:
            errors.append(
                "APK DEX contains authenticated-handshake test-only crypto seams"
            )
        if not zip_report["cs2_string_resource_name_present"]:
            errors.append("APK resource table is missing the CS2 display entry")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"APK zip inspection failed: {exc}")

    try:
        aapt = resolve_android_tool(ROOT, "aapt.exe")
        aapt_result = run_text_command([aapt, "dump", "badging", apk_path])
        evidence["aapt"] = {
            "returncode": aapt_result["returncode"],
            "stderr_tail": str(aapt_result["stderr"])[-2000:],
        }
        if aapt_result["returncode"] != 0:
            errors.append("aapt badging check failed")
        else:
            badging = parse_aapt_badging_output(str(aapt_result["stdout"]))
            evidence["badging"] = badging
            if badging["package"] != EXPECTED_ANDROID_PACKAGE:
                errors.append("APK package name is not com.visionforge.mobile")
            if badging["debuggable"]:
                errors.append("APK manifest is debuggable")
        values_result = run_text_command(
            [aapt, "dump", "--values", "resources", apk_path]
        )
        evidence["aapt_values"] = {
            "returncode": values_result["returncode"],
            "stderr_tail": str(values_result["stderr"])[-2000:],
        }
        if values_result["returncode"] != 0:
            errors.append("aapt resource values check failed")
        elif not aapt_values_include_cs2_display_name(
            str(values_result["stdout"])
        ):
            errors.append("APK does not expose the CS2 Chinese display name")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"aapt badging check could not run: {exc}")

    try:
        apksigner = resolve_android_tool(ROOT, "apksigner.bat")
        signer_result = run_text_command(
            [apksigner, "verify", "--verbose", "--print-certs", apk_path]
        )
        evidence["apksigner"] = {
            "returncode": signer_result["returncode"],
            "stderr_tail": str(signer_result["stderr"])[-2000:],
        }
        if signer_result["returncode"] != 0:
            errors.append("apksigner verification failed")
        else:
            signing = parse_apksigner_output(str(signer_result["stdout"]))
            evidence["signing"] = signing
            errors.extend(
                android_apk_signing_errors(
                    signing,
                    require_production_signing=require_production_signing,
                )
            )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"apksigner check could not run: {exc}")

    if errors:
        evidence["errors"] = errors
        return _fail("android_release_apk", "; ".join(errors), evidence)
    return _pass("android_release_apk", "Android release APK passed static release checks", evidence)


AuthenticodeInspector = Callable[[Path], Mapping[str, Any]]


AUTHENTICODE_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$artifact = $env:VISIONFORGE_AUTHENTICODE_ARTIFACT
if ([string]::IsNullOrWhiteSpace($artifact)) {
    throw 'Authenticode artifact path is missing'
}
$trustedSecurityModule = Join-Path `
        $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1'
Import-Module -Name $trustedSecurityModule -Force -ErrorAction Stop
$signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature `
        -LiteralPath $artifact
$signerSha256 = ''
if ($null -ne $signature.SignerCertificate) {
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($signature.SignerCertificate.RawData)
        $signerSha256 = -join ($hashBytes | ForEach-Object {
            $_.ToString('x2')
        })
    } finally {
        $sha256.Dispose()
    }
}
[ordered]@{
    status = [string]$signature.Status
    status_message = [string]$signature.StatusMessage
    signer_subject = if ($signature.SignerCertificate) {
        [string]$signature.SignerCertificate.Subject
    } else { '' }
    signer_certificate_sha256 = $signerSha256
    timestamp_subject = if ($signature.TimeStamperCertificate) {
        [string]$signature.TimeStamperCertificate.Subject
    } else { '' }
    timestamp_present = $null -ne $signature.TimeStamperCertificate
} | ConvertTo-Json -Compress
"""


def _trusted_windows_powershell_path() -> Path:
    """Resolve Windows PowerShell from the native Windows directory.

    Formal verification must not use the current directory or ``PATH`` to
    locate its own signature verifier.
    """

    if os.name != "nt":
        raise RuntimeError("Windows PowerShell is available only on Windows")
    buffer = ctypes.create_unicode_buffer(32_768)
    length = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(  # type: ignore[attr-defined]
        buffer,
        len(buffer),
    )
    if length <= 0 or length >= len(buffer):
        raise OSError("GetSystemWindowsDirectoryW failed")
    windows_root = Path(buffer.value).resolve(strict=True)
    powershell_path = (
        windows_root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    ).resolve(strict=True)
    try:
        relative = powershell_path.relative_to(windows_root)
    except ValueError as exc:
        raise RuntimeError("Windows PowerShell resolved outside Windows root") from exc
    if relative.as_posix().lower() != (
        "system32/windowspowershell/v1.0/powershell.exe"
    ):
        raise RuntimeError("Windows PowerShell resolved to an unexpected path")
    return powershell_path


def inspect_authenticode_signature(artifact_path: Path) -> Mapping[str, Any]:
    """Return OS-verified Authenticode evidence without trusting sidecar JSON.

    The artifact path is passed through a dedicated environment variable, not
    interpolated into PowerShell source.  This keeps release paths containing
    spaces or shell metacharacters out of the command language.
    """

    if os.name != "nt":
        raise RuntimeError("Authenticode verification requires Windows")
    environment = os.environ.copy()
    environment["VISIONFORGE_AUTHENTICODE_ARTIFACT"] = str(
        artifact_path.resolve()
    )
    completed = subprocess.run(
        [
            str(_trusted_windows_powershell_path()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            AUTHENTICODE_POWERSHELL_SCRIPT,
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            "Authenticode verification failed"
            + (f": {detail[-2000:]}" if detail else "")
        )
    evidence = json.loads(completed.stdout)
    if not isinstance(evidence, Mapping):
        raise ValueError("Authenticode verifier returned a non-object result")
    return evidence


def _normalize_certificate_sha256(values: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        fingerprint = str(value or "").strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError(
                "Host signer certificate SHA256 must contain 64 hexadecimal characters"
            )
        if fingerprint not in normalized:
            normalized.append(fingerprint)
    return tuple(normalized)


def verify_host_release(
    host_path: Path,
    expected_sha256: str | None = None,
    *,
    require_authenticode: bool = True,
    expected_signer_sha256: Sequence[str] = (),
    authenticode_inspector: AuthenticodeInspector | None = None,
) -> CheckResult:
    if not host_path.exists() or host_path.stat().st_size <= 0:
        return _fail("host_release", "Host EXE is missing or empty", {"host": str(host_path)})
    digest = sha256_file(host_path)
    errors: list[str] = []
    if host_path.name != CANONICAL_HOST_EXE_NAME:
        errors.append(f"Host EXE must be named {CANONICAL_HOST_EXE_NAME}")
    with host_path.open("rb") as handle:
        if handle.read(2) != b"MZ":
            errors.append("Host EXE does not start with an MZ header")
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        errors.append("Host EXE sha256 does not match expected value")
    authenticode: Mapping[str, Any] = {}
    signer_allowlist: tuple[str, ...] = ()
    if require_authenticode:
        try:
            signer_allowlist = _normalize_certificate_sha256(
                expected_signer_sha256
            )
            if not signer_allowlist:
                errors.append(
                    "formal Host signer certificate SHA256 allowlist is missing"
                )
            inspector = authenticode_inspector or inspect_authenticode_signature
            authenticode = inspector(host_path)
            signer_fingerprint = str(
                authenticode.get("signer_certificate_sha256") or ""
            ).lower().replace(":", "")
            if authenticode.get("status") != "Valid":
                errors.append("Host EXE Authenticode signature is not valid")
            if authenticode.get("timestamp_present") is not True:
                errors.append("Host EXE Authenticode timestamp is missing")
            if not re.fullmatch(r"[0-9a-f]{64}", signer_fingerprint):
                errors.append(
                    "Host EXE signer certificate SHA256 is unavailable"
                )
            elif signer_allowlist and signer_fingerprint not in signer_allowlist:
                errors.append(
                    "Host EXE signer certificate is not in the release allowlist"
                )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"Host EXE Authenticode verification failed: {exc}")
    evidence = {
        "host": str(host_path),
        "size": host_path.stat().st_size,
        "sha256": digest,
        "authenticode_required": require_authenticode,
        "authenticode": dict(authenticode),
        "allowed_signer_certificate_sha256": list(signer_allowlist),
        "errors": errors,
    }
    if errors:
        return _fail("host_release", "; ".join(errors), evidence)
    return _pass("host_release", "Host EXE passed artifact checks", evidence)


def verify_source_contracts(root: Path) -> CheckResult:
    base_results = check_source_contracts(root)
    reverse_results = check_reverse_resistance_contracts(root)
    results = [*base_results, *reverse_results]
    failures = [result for result in results if not result.ok]
    evidence = {
        "checked": len(results),
        "base_checks_ok": all(result.ok for result in base_results),
        "reverse_resistance_ok": all(result.ok for result in reverse_results),
        "reverse_resistance_checks": [result.name for result in reverse_results],
        "failed": [
            {"name": result.name, "detail": result.detail, "evidence": result.evidence}
            for result in failures
        ],
    }
    if failures:
        return _fail("source_contracts", "dual-machine source contracts failed", evidence)
    return _pass("source_contracts", "dual-machine source contracts passed", evidence)


def verify_device_evidence(
    evidence_path: Path | None,
    *,
    required: bool,
    expected_hashes: Mapping[str, str],
    expected_package_version: str = "",
) -> CheckResult:
    if evidence_path is None:
        if required:
            return _fail(
                "device_evidence",
                "device evidence JSON is required for formal release",
                {"required": True},
            )
        return _pass(
            "device_evidence",
            "device evidence was not required for this lab check",
            {"required": False},
        )
    if not evidence_path.exists():
        return _fail("device_evidence", "device evidence JSON is missing", {"path": str(evidence_path)})
    errors: list[str] = []
    try:
        data = read_json(evidence_path)
    except Exception as exc:  # noqa: BLE001
        return _fail("device_evidence", f"device evidence JSON is unreadable: {exc}", {"path": str(evidence_path)})
    if data.get("schema") != DEVICE_EVIDENCE_SCHEMA:
        errors.append(f"device evidence schema is not {DEVICE_EVIDENCE_SCHEMA}")
    checks = data.get("checks")
    if not isinstance(checks, Mapping):
        errors.append("device evidence has no checks object")
        checks = {}
    for key in REQUIRED_DEVICE_EVIDENCE_FLAGS:
        if checks.get(key) is not True:
            errors.append(f"device evidence check {key} is not true")
    if not str(data.get("device_serial") or ""):
        errors.append("device evidence device_serial is missing")
    tokens = data.get("game_model_tokens")
    if sorted(tokens or []) != sorted(EXPECTED_GAME_TOKENS):
        errors.append("device evidence does not list all production game model tokens")
    errors.extend(game_display_name_errors(data))
    errors.extend(model_target_contract_errors(data))
    if str(data.get("installed_package_name") or "") != EXPECTED_ANDROID_PACKAGE:
        errors.append("device evidence installed_package_name is not com.visionforge.mobile")
    installed_package_version = str(data.get("installed_package_version") or "")
    if not installed_package_version:
        errors.append("device evidence installed_package_version is missing")
    elif expected_package_version and installed_package_version != expected_package_version:
        errors.append("device evidence installed_package_version does not match Android APK")
    for key, expected in expected_hashes.items():
        value = str(data.get(key, "")).lower()
        if value and value != expected.lower():
            errors.append(f"device evidence {key} does not match current artifact")
        if not value:
            errors.append(f"device evidence is missing {key}")
    mobile_log_hashes, mobile_log_errors = _device_evidence_mobile_log_hashes(
        evidence_path,
        data,
    )
    errors.extend(mobile_log_errors)
    errors.extend(
        counter_strike_2_runtime_observation_errors(
            data,
            allowed_mobile_log_hashes=mobile_log_hashes,
        )
    )
    ui_xml_sources, ui_xml_errors = _device_evidence_ui_xml_sources(
        evidence_path,
        data,
    )
    errors.extend(ui_xml_errors)
    expected_apk_sha256 = str(
        expected_hashes.get("android_apk_sha256")
        or data.get("android_apk_sha256")
        or ""
    )
    errors.extend(
        physical_output_route_errors(
            data,
            expected_apk_sha256=expected_apk_sha256,
            expected_device_serial=str(data.get("device_serial") or ""),
            allowed_mobile_log_hashes=mobile_log_hashes,
        )
    )
    errors.extend(
        final_safe_idle_errors(
            data,
            expected_apk_sha256=expected_apk_sha256,
            expected_device_serial=str(data.get("device_serial") or ""),
            allowed_mobile_log_hashes=mobile_log_hashes,
            allowed_ui_xml_hashes=set(ui_xml_sources),
            allowed_ui_xml_sources=ui_xml_sources,
        )
    )
    evidence = {"path": str(evidence_path), "errors": errors}
    if errors:
        return _fail("device_evidence", "; ".join(errors), evidence)
    return _pass("device_evidence", "device evidence proves physical full-chain acceptance", evidence)


def _result_to_json(result: CheckResult) -> Mapping[str, Any]:
    return {
        "name": result.name,
        "ok": result.ok,
        "detail": result.detail,
        "evidence": result.evidence,
    }


def formal_bundle_report_errors(report: Mapping[str, Any]) -> list[str]:
    """Validate every field a downstream formal-release consumer must trust.

    Exit status and a standalone ``ok`` boolean are deliberately insufficient:
    both are easy to launder through a development invocation or a substituted
    report.  Consumers use this single validator so acceptance, packaging and
    archive verification cannot drift onto different trust contracts.
    """
    errors: list[str] = []
    expected_true_fields = (
        "diagnostic_completed",
        "checks_ok",
        "strict_ok",
        "reverse_resistance_ok",
        "formal_eligible",
        "formal_ok",
        "formal_release_ok",
        "ok",
    )
    if report.get("schema") != FORMAL_BUNDLE_REPORT_SCHEMA:
        errors.append("formal bundle verifier report schema is invalid")
    if report.get("mode") != "formal":
        errors.append("formal bundle verifier report mode is not formal")
    for field in expected_true_fields:
        if report.get(field) is not True:
            errors.append(f"formal bundle verifier report {field} is not true")
    if report.get("bypasses") != []:
        errors.append("formal bundle verifier report bypasses must be empty")

    checks = report.get("checks")
    if not isinstance(checks, Sequence) or isinstance(checks, (str, bytes)):
        errors.append("formal bundle verifier report has no checks")
        return errors

    indexed: dict[str, Mapping[str, Any]] = {}
    duplicate_names: list[str] = []
    for check in checks:
        if not isinstance(check, Mapping):
            errors.append("formal bundle verifier report contains a non-object check")
            continue
        name = str(check.get("name") or "")
        if not name:
            errors.append("formal bundle verifier report contains an unnamed check")
            continue
        if name in indexed:
            duplicate_names.append(name)
            continue
        indexed[name] = check
    if duplicate_names:
        errors.append(
            "formal bundle verifier report has duplicate checks: "
            + ", ".join(sorted(set(duplicate_names)))
        )
    missing = sorted(FORMAL_BUNDLE_REQUIRED_CHECKS - indexed.keys())
    if missing:
        errors.append(
            "formal bundle verifier report is missing required checks: "
            + ", ".join(missing)
        )
    for name in sorted(FORMAL_BUNDLE_REQUIRED_CHECKS & indexed.keys()):
        if indexed[name].get("ok") is not True:
            errors.append(
                f"formal bundle verifier report {name} check is not successful"
            )

    source_contracts = indexed.get("source_contracts")
    if source_contracts is not None:
        evidence = source_contracts.get("evidence")
        if not isinstance(evidence, Mapping):
            errors.append("formal bundle verifier report source_contracts evidence is missing")
        else:
            if evidence.get("failed") != []:
                errors.append(
                    "formal bundle verifier report source_contracts failures must be empty"
                )
            if evidence.get("base_checks_ok") is not True:
                errors.append(
                    "formal bundle verifier report source_contracts base checks are not true"
                )
            if evidence.get("reverse_resistance_ok") is not True:
                errors.append(
                    "formal bundle verifier report source_contracts reverse resistance is not true"
                )
    return errors


def write_report(
    results: Sequence[CheckResult],
    output: Path,
    *,
    mode: str = "formal",
    bypasses: Sequence[str] = (),
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    checks_ok = all(result.ok for result in results)
    is_formal = mode == "formal"
    normalized_bypasses = sorted({str(value) for value in bypasses if value})
    source_result = next(
        (result for result in results if result.name == "source_contracts"),
        None,
    )
    reverse_resistance_ok = bool(
        source_result is not None
        and source_result.ok
        and source_result.evidence.get("reverse_resistance_ok") is True
    )
    strict_ok = (
        is_formal
        and not normalized_bypasses
        and checks_ok
        and reverse_resistance_ok
    )
    formal_eligible = strict_ok
    report = {
        "schema": (
            FORMAL_BUNDLE_REPORT_SCHEMA
            if is_formal
            else "visionforge-development-bundle-check-v1"
        ),
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "mode": mode,
        "diagnostic_completed": True,
        "checks_ok": checks_ok,
        "strict_ok": strict_ok,
        "reverse_resistance_ok": reverse_resistance_ok,
        "formal_eligible": formal_eligible,
        "formal_ok": formal_eligible,
        "formal_release_ok": formal_eligible,
        "bypasses": normalized_bypasses,
        "ok": formal_eligible,
        "checks": [_result_to_json(result) for result in results],
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("formal", "development"),
        default="formal",
    )
    parser.add_argument("--windows-exe", type=Path, default=None)
    parser.add_argument("--windows-verify-report", type=Path, default=None)
    parser.add_argument("--windows-sha256", type=Path, default=None)
    parser.add_argument(
        "--android-apk",
        type=Path,
        default=ROOT
        / "android_inference_benchmark"
        / "app"
        / "build"
        / "outputs"
        / "apk"
        / "release"
        / "app-release.apk",
    )
    parser.add_argument("--host-exe", type=Path, default=None)
    parser.add_argument("--host-sha256", default=None)
    parser.add_argument(
        "--host-signer-sha256",
        action="append",
        default=[
            value.strip()
            for value in os.getenv(
                "VISIONFORGE_HOST_SIGNER_CERTIFICATE_SHA256", ""
            ).split(",")
            if value.strip()
        ],
        help=(
            "Allowed Authenticode signer certificate SHA256; repeat during "
            "certificate rotation. Defaults to "
            "VISIONFORGE_HOST_SIGNER_CERTIFICATE_SHA256."
        ),
    )
    parser.add_argument(
        "--allow-unsigned-development-host",
        action="store_true",
        help="Development only: skip formal Host Authenticode verification.",
    )
    parser.add_argument("--device-evidence", type=Path, default=None)
    parser.add_argument("--allow-development-android-signing", action="store_true")
    parser.add_argument("--no-require-device-evidence", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def _development_bypasses(args: argparse.Namespace) -> tuple[str, ...]:
    bypasses: list[str] = []
    if args.allow_unsigned_development_host:
        bypasses.append("host_authenticode")
    if args.allow_development_android_signing:
        bypasses.append("android_production_signing")
    if args.no_require_device_evidence:
        bypasses.append("physical_device_evidence")
    return tuple(bypasses)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    bypasses = _development_bypasses(args)
    if args.mode == "formal" and bypasses:
        print(
            "[ERROR] development bypass flags require --mode development: "
            + ", ".join(bypasses),
            flush=True,
        )
        return 2
    windows_exe = args.windows_exe or latest_windows_release()
    host_exe = args.host_exe or default_host_release()
    if windows_exe is None:
        results = [_fail("windows_release", "No Windows release EXE was found", {})]
        output = args.output or ROOT / "analysis_output" / "formal_release_bundle_verify_missing.json"
        write_report(results, output, mode=args.mode, bypasses=bypasses)
        print(f"[ERROR] formal release bundle verification failed; report={output}", flush=True)
        return 1
    if host_exe is None:
        results = [_fail("host_release", "No host EXE was found", {})]
        output = args.output or ROOT / "analysis_output" / "formal_release_bundle_verify_missing.json"
        write_report(results, output, mode=args.mode, bypasses=bypasses)
        print(f"[ERROR] formal release bundle verification failed; report={output}", flush=True)
        return 1

    windows_result = verify_windows_release(
        windows_exe.resolve(),
        args.windows_verify_report.resolve() if args.windows_verify_report else None,
        args.windows_sha256.resolve() if args.windows_sha256 else None,
    )
    android_result = verify_android_release_apk(
        args.android_apk.resolve(),
        require_production_signing=not args.allow_development_android_signing,
    )
    host_result = verify_host_release(
        host_exe.resolve(),
        args.host_sha256,
        require_authenticode=not args.allow_unsigned_development_host,
        expected_signer_sha256=args.host_signer_sha256,
    )
    source_result = verify_source_contracts(ROOT)
    expected_hashes = {
        "windows_exe_sha256": str(windows_result.evidence.get("sha256", "")),
        "android_apk_sha256": str(android_result.evidence.get("sha256", "")),
        "host_exe_sha256": str(host_result.evidence.get("sha256", "")),
    }
    android_badging = android_result.evidence.get("badging")
    expected_package_version = (
        str(android_badging.get("version_name") or "")
        if isinstance(android_badging, Mapping)
        else ""
    )
    device_result = verify_device_evidence(
        args.device_evidence.resolve() if args.device_evidence else None,
        required=not args.no_require_device_evidence,
        expected_hashes=expected_hashes,
        expected_package_version=expected_package_version,
    )
    results = [windows_result, android_result, host_result, source_result, device_result]
    output = args.output or (
        ROOT
        / "analysis_output"
        / f"formal_release_bundle_verify_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    write_report(results, output, mode=args.mode, bypasses=bypasses)
    checks_ok = all(result.ok for result in results)
    if checks_ok:
        label = "formal release" if args.mode == "formal" else "development bundle"
        print(f"[OK] {label} verification passed; report={output}", flush=True)
        return 0
    print(f"[ERROR] formal release bundle verification failed; report={output}", flush=True)
    for result in results:
        status = "OK" if result.ok else "FAIL"
        print(f"[{status}] {result.name}: {result.detail}", flush=True)
    return 1


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
