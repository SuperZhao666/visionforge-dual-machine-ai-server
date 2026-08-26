from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_formal_release_bundle as verifier  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_parse_apksigner_output_rejects_android_debug_certificate() -> None:
    parsed = verifier.parse_apksigner_output(
        "\n".join(
            (
                "Verified using v1 scheme (JAR signing): false",
                "Verified using v2 scheme (APK Signature Scheme v2): true",
                "Verified using v3 scheme (APK Signature Scheme v3): true",
                "Signer #1 certificate DN: C=US, O=Android, CN=Android Debug",
                "Signer #1 certificate SHA-256 digest: "
                + verifier.ANDROID_DEBUG_CERT_SHA256,
            )
        )
    )

    assert parsed["v2_verified"] is True
    assert parsed["v1_verified"] is False
    assert parsed["v3_verified"] is True
    assert parsed["android_debug_certificate"] is True


def test_production_signing_accepts_v3_without_redundant_v2() -> None:
    errors = verifier.android_apk_signing_errors(
        {
            "v1_verified": False,
            "v2_verified": False,
            "v3_verified": True,
            "android_debug_certificate": False,
            "signer_sha256": ["a" * 64],
        },
        require_production_signing=True,
    )

    assert errors == ()


def test_production_signing_still_requires_v3() -> None:
    errors = verifier.android_apk_signing_errors(
        {
            "v1_verified": False,
            "v2_verified": True,
            "v3_verified": False,
            "android_debug_certificate": False,
            "signer_sha256": ["a" * 64],
        },
        require_production_signing=True,
    )

    assert "production APK is not verified with Signature Scheme v3" in errors


def test_parse_aapt_badging_output_extracts_package_and_debuggable_state() -> None:
    parsed = verifier.parse_aapt_badging_output(
        "package: name='com.visionforge.mobile' versionCode='1' "
        "versionName='1.0.0-rc1'\napplication-debuggable\n"
    )

    assert parsed["package"] == "com.visionforge.mobile"
    assert parsed["version_code"] == "1"
    assert parsed["version_name"] == "1.0.0-rc1"
    assert parsed["debuggable"] is True


def test_inspect_apk_zip_requires_all_four_models_and_qnn_closure(tmp_path: Path) -> None:
    apk = tmp_path / "app-release.apk"
    native_bridge = "lib/arm64-v8a/libvisionforge_qnn_htp.so"
    native_markers = " ".join(verifier.CS2_NATIVE_MARKERS).encode("ascii")
    with zipfile.ZipFile(apk, "w") as archive:
        for entry in (
            *verifier.EXPECTED_ANDROID_MODELS,
            *verifier.EXPECTED_QNN_HTP_RUNTIME,
        ):
            archive.writestr(
                entry,
                native_markers if entry == native_bridge else b"x",
            )
        dex_markers = " ".join(verifier.CS2_DEX_MARKERS).encode("ascii")
        archive.writestr("classes.dex", dex_markers)
        archive.writestr("resources.arsc", b"game_counter_strike_2")

    report = verifier.inspect_apk_zip(apk)

    assert report["missing_required_entries"] == []
    assert report["missing_cs2_dex_markers"] == []
    assert report["missing_cs2_native_markers"] == []
    assert report["forbidden_test_seam_markers"] == []
    assert report["cs2_string_resource_name_present"] is True


def test_inspect_apk_zip_rejects_library_only_cs2_packaging(tmp_path: Path) -> None:
    apk = tmp_path / "app-release.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        for entry in (
            *verifier.EXPECTED_ANDROID_MODELS,
            *verifier.EXPECTED_QNN_HTP_RUNTIME,
        ):
            archive.writestr(entry, b"x")
        archive.writestr("classes.dex", b"other-model-only")
        archive.writestr("resources.arsc", b"other_resource")

    report = verifier.inspect_apk_zip(apk)

    assert report["missing_required_entries"] == []
    assert verifier.CS2_MODEL_TOKEN in report["missing_cs2_dex_markers"]
    assert verifier.CS2_MODEL_TOKEN in report["missing_cs2_native_markers"]
    assert report["cs2_string_resource_name_present"] is False


def test_inspect_apk_zip_rejects_handshake_test_crypto_seam(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "app-release.apk"
    native_bridge = "lib/arm64-v8a/libvisionforge_qnn_htp.so"
    native_markers = " ".join(verifier.CS2_NATIVE_MARKERS).encode("ascii")
    with zipfile.ZipFile(apk, "w") as archive:
        for entry in (
            *verifier.EXPECTED_ANDROID_MODELS,
            *verifier.EXPECTED_QNN_HTP_RUNTIME,
        ):
            archive.writestr(
                entry,
                native_markers if entry == native_bridge else b"x",
            )
        dex_markers = " ".join(
            (
                *verifier.CS2_DEX_MARKERS,
                *verifier.FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS,
            )
        ).encode("ascii")
        archive.writestr("classes.dex", dex_markers)
        archive.writestr("resources.arsc", b"game_counter_strike_2")

    report = verifier.inspect_apk_zip(apk)

    assert report["forbidden_test_seam_markers"] == list(
        verifier.FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS
    )


def test_aapt_values_require_exact_cs2_chinese_display_name() -> None:
    valid = (
        "resource 0x7f05004b "
        "com.visionforge.mobile:string/game_counter_strike_2\n"
        '  (string8) "反恐精英2"\n'
    )

    assert verifier.aapt_values_include_cs2_display_name(valid)
    assert not verifier.aapt_values_include_cs2_display_name(
        valid.replace("反恐精英2", "三角洲行动")
    )


def test_device_evidence_requires_physical_full_chain_flags(tmp_path: Path) -> None:
    evidence = tmp_path / "device-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "device_serial": "adb-test._adb-tls-connect._tcp",
                "installed_package_name": "com.visionforge.mobile",
                "installed_package_version": "1.0.0-rc1",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "game_display_names": verifier.EXPECTED_GAME_DISPLAY_NAMES,
                "model_target_contracts": verifier.EXPECTED_MODEL_TARGET_CONTRACTS,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
    )

    assert not result.ok
    assert "physical_output_routes" in result.detail


def test_device_evidence_rejects_legacy_single_route_schema(tmp_path: Path) -> None:
    evidence = tmp_path / "legacy-device-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": "visionforge-dual-machine-device-evidence-v1",
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={},
    )

    assert not result.ok
    assert verifier.DEVICE_EVIDENCE_SCHEMA in result.detail


def test_device_evidence_requires_device_serial_and_installed_version(tmp_path: Path) -> None:
    evidence = tmp_path / "device-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "installed_package_name": "com.visionforge.mobile",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "game_display_names": verifier.EXPECTED_GAME_DISPLAY_NAMES,
                "model_target_contracts": verifier.EXPECTED_MODEL_TARGET_CONTRACTS,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
    )

    assert not result.ok
    assert "device_serial" in result.detail
    assert "installed_package_version" in result.detail


def test_device_evidence_rejects_installed_package_version_mismatch(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "device-evidence.json"
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "device_serial": "adb-test._adb-tls-connect._tcp",
                "installed_package_name": "com.visionforge.mobile",
                "installed_package_version": "0.9.0",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "game_display_names": verifier.EXPECTED_GAME_DISPLAY_NAMES,
                "model_target_contracts": verifier.EXPECTED_MODEL_TARGET_CONTRACTS,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
        expected_package_version="1.0.0-rc1",
    )

    assert not result.ok
    assert "installed_package_version does not match Android APK" in result.detail


def test_device_evidence_requires_chinese_game_display_names(tmp_path: Path) -> None:
    evidence = tmp_path / "device-evidence.json"
    names = dict(verifier.EXPECTED_GAME_DISPLAY_NAMES)
    names["overwatch2-416-yolov5"] = "Overwatch 2"
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "device_serial": "adb-test._adb-tls-connect._tcp",
                "installed_package_name": "com.visionforge.mobile",
                "installed_package_version": "1.0.0-rc1",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "game_display_names": names,
                "model_target_contracts": verifier.EXPECTED_MODEL_TARGET_CONTRACTS,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
    )

    assert not result.ok
    assert "game_display_names.overwatch2-416-yolov5" in result.detail


def test_device_evidence_requires_overwatch_enemy_class_contract(tmp_path: Path) -> None:
    evidence = tmp_path / "device-evidence.json"
    contracts = json.loads(json.dumps(verifier.EXPECTED_MODEL_TARGET_CONTRACTS))
    contracts["overwatch2-416-yolov5"]["lock_class_name"] = "non_enemy_body"
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "device_serial": "adb-test._adb-tls-connect._tcp",
                "installed_package_name": "com.visionforge.mobile",
                "installed_package_version": "1.0.0-rc1",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "model_target_contracts": contracts,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
    )

    assert not result.ok
    assert "model_target_contracts.overwatch2-416-yolov5.lock_class_name" in result.detail


def test_device_evidence_requires_cs2_faction_class_contract(tmp_path: Path) -> None:
    evidence = tmp_path / "device-evidence.json"
    contracts = json.loads(json.dumps(verifier.EXPECTED_MODEL_TARGET_CONTRACTS))
    contracts["counter-strike-2-vombit-416-v8s"][
        "cross_faction_pairing_allowed"
    ] = True
    evidence.write_text(
        json.dumps(
            {
                "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
                "device_serial": "adb-test._adb-tls-connect._tcp",
                "installed_package_name": "com.visionforge.mobile",
                "installed_package_version": "1.0.0-rc1",
                "windows_exe_sha256": "w" * 64,
                "android_apk_sha256": "a" * 64,
                "host_exe_sha256": "h" * 64,
                "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
                "game_display_names": verifier.EXPECTED_GAME_DISPLAY_NAMES,
                "model_target_contracts": contracts,
                "checks": {
                    key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_device_evidence(
        evidence,
        required=True,
        expected_hashes={
            "windows_exe_sha256": "w" * 64,
            "android_apk_sha256": "a" * 64,
            "host_exe_sha256": "h" * 64,
        },
    )

    assert not result.ok
    assert (
        "model_target_contracts.counter-strike-2-vombit-416-v8s."
        "cross_faction_pairing_allowed"
    ) in result.detail


def test_cs2_runtime_observation_requires_attributed_zero_failure_metrics() -> None:
    observation = {
        "event": "mobile_pipeline_metrics",
        "timestamp_unix_ms": 1_700_000_000_000,
        "model": "counter-strike-2-vombit-416-v8s",
        "aim_target": "t_head",
        "native_applied": True,
        "rendered_frames": 100,
        "qnn_executions": 99,
        "qnn_failures": 0,
        "qnn_fps": 140.0,
        "preprocess_p50_ms": 1.2,
        "qnn_p50_ms": 3.4,
        "inference_total_p50_ms": 3.7,
        "decode_queue_p50_ms": 6.5,
        "detail_sha256": "a" * 64,
    }

    errors = verifier.counter_strike_2_runtime_observation_errors(
        {"observations": {"counter_strike_2_qnn_full_chain": observation}}
    )

    assert errors == []


def test_cs2_runtime_observation_rejects_other_model_even_when_check_is_true() -> None:
    observation = {
        "event": "mobile_pipeline_metrics",
        "model": "delta-force-416-v8s",
        "aim_target": "t_head",
        "native_applied": True,
        "rendered_frames": 100,
        "qnn_executions": 99,
        "qnn_failures": 0,
        "qnn_fps": 140.0,
        "preprocess_p50_ms": 1.2,
        "qnn_p50_ms": 3.4,
        "inference_total_p50_ms": 3.7,
        "decode_queue_p50_ms": 6.5,
        "detail_sha256": "a" * 64,
    }

    errors = verifier.counter_strike_2_runtime_observation_errors(
        {"observations": {"counter_strike_2_qnn_full_chain": observation}}
    )

    assert "device evidence CS2 QNN model identity is invalid" in errors


def test_cs2_runtime_observation_must_come_from_archived_mobile_log() -> None:
    observation = {
        "event": "mobile_pipeline_metrics",
        "model": "counter-strike-2-vombit-416-v8s",
        "aim_target": "t_head",
        "native_applied": True,
        "rendered_frames": 100,
        "qnn_executions": 99,
        "qnn_failures": 0,
        "qnn_fps": 140.0,
        "preprocess_p50_ms": 1.2,
        "qnn_p50_ms": 3.4,
        "inference_total_p50_ms": 3.7,
        "decode_queue_p50_ms": 6.5,
        "detail_sha256": "a" * 64,
        "source_mobile_log_sha256": "b" * 64,
    }

    errors = verifier.counter_strike_2_runtime_observation_errors(
        {"observations": {"counter_strike_2_qnn_full_chain": observation}},
        allowed_mobile_log_hashes={"c" * 64},
    )

    assert "device evidence CS2 source is not an archived mobile log" in errors


def test_windows_release_report_must_match_current_exe_hash(tmp_path: Path) -> None:
    exe_bytes = b"MZformal"
    exe = tmp_path / "VisionForge_Protected.exe"
    exe.write_bytes(exe_bytes)
    digest = _sha256(exe_bytes)
    exe.with_suffix(".exe.sha256").write_text(f"{digest}  {exe.name}\n", encoding="utf-8")
    exe.with_suffix(".exe.verify.json").write_text(
        json.dumps(
            {
                "exe_sha256": digest,
                "published": {"sha256": digest},
                "checks": {
                    "binary_protection": {"ok": True},
                    "clean_profile": {"ok": True},
                    "resources": {"missing_required_resources": []},
                    "runtime_dll_boundary": {
                        "forbidden_native_runtime_dlls": [],
                        "missing_required_onnxruntime_dlls": [],
                        "unexpected_runtime_files": [],
                        "unexpected_top_level_dlls": [],
                    },
                    "runtime_ort_boundary": {
                        "missing": [],
                        "errors": [],
                        "validator": {"ok": True},
                    },
                    "self_test": {"returncode": 0},
                    "self_test_second": {"returncode": 0},
                    "diagnostics_json": {"returncode": 0},
                    "runtime_contract_json": {"returncode": 0},
                    "cpu_self_test": {"returncode": 0},
                    "integrity_json": {"returncode": 0},
                    "integrity_json_parse": {"ok": True},
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.verify_windows_release(exe)

    assert result.ok


def test_formal_host_requires_valid_timestamped_allowlisted_authenticode(
    tmp_path: Path,
) -> None:
    host = tmp_path / verifier.CANONICAL_HOST_EXE_NAME
    host.write_bytes(b"MZhost")
    signer = "a" * 64

    result = verifier.verify_host_release(
        host,
        expected_signer_sha256=(signer,),
        authenticode_inspector=lambda _path: {
            "status": "Valid",
            "timestamp_present": True,
            "signer_certificate_sha256": signer,
            "signer_subject": "CN=VisionForge Release",
        },
    )

    assert result.ok
    assert result.evidence["authenticode"]["status"] == "Valid"


def test_formal_host_rejects_unsigned_or_unpinned_artifact(
    tmp_path: Path,
) -> None:
    host = tmp_path / verifier.CANONICAL_HOST_EXE_NAME
    host.write_bytes(b"MZhost")

    result = verifier.verify_host_release(
        host,
        expected_signer_sha256=("a" * 64,),
        authenticode_inspector=lambda _path: {
            "status": "NotSigned",
            "timestamp_present": False,
            "signer_certificate_sha256": "b" * 64,
        },
    )

    assert not result.ok
    assert "Authenticode signature is not valid" in result.detail
    assert "timestamp is missing" in result.detail
    assert "not in the release allowlist" in result.detail


def test_unsigned_host_check_is_explicitly_non_formal(
    tmp_path: Path,
) -> None:
    host = tmp_path / verifier.CANONICAL_HOST_EXE_NAME
    host.write_bytes(b"MZhost")

    result = verifier.verify_host_release(
        host,
        require_authenticode=False,
    )

    assert result.ok
    assert result.evidence["authenticode_required"] is False


def test_formal_cli_rejects_development_bypass_before_writing_report(
    tmp_path: Path,
) -> None:
    output = tmp_path / "must-not-exist.json"

    exit_code = verifier.main(
        [
            "--allow-unsigned-development-host",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 2
    assert not output.exists()


def test_development_report_is_never_formal_eligible(tmp_path: Path) -> None:
    output = tmp_path / "development.json"

    verifier.write_report(
        [verifier.CheckResult("host", True, "development check passed", {})],
        output,
        mode="development",
        bypasses=("host_authenticode",),
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == "visionforge-development-bundle-check-v1"
    assert report["diagnostic_completed"] is True
    assert report["checks_ok"] is True
    assert report["strict_ok"] is False
    assert report["reverse_resistance_ok"] is False
    assert report["formal_eligible"] is False
    assert report["formal_ok"] is False
    assert report["formal_release_ok"] is False
    assert report["ok"] is False
    assert report["bypasses"] == ["host_authenticode"]


def test_formal_report_requires_and_exposes_reverse_resistance_success(
    tmp_path: Path,
) -> None:
    output = tmp_path / "formal.json"
    results = [
        verifier.CheckResult("windows_release", True, "ok", {}),
        verifier.CheckResult("android_release_apk", True, "ok", {}),
        verifier.CheckResult("host_release", True, "ok", {}),
        verifier.CheckResult(
            "source_contracts",
            True,
            "ok",
            {
                "base_checks_ok": True,
                "reverse_resistance_ok": True,
                "failed": [],
            },
        ),
        verifier.CheckResult("device_evidence", True, "ok", {}),
    ]

    verifier.write_report(results, output, mode="formal")

    report = json.loads(output.read_text(encoding="utf-8"))
    assert verifier.formal_bundle_report_errors(report) == []
    assert report["strict_ok"] is True
    assert report["reverse_resistance_ok"] is True
    assert report["formal_ok"] is True
    assert report["formal_release_ok"] is True
    assert report["ok"] is True


def test_authenticode_script_supports_windows_powershell_51() -> None:
    script = verifier.AUTHENTICODE_POWERSHELL_SCRIPT

    assert "[Security.Cryptography.SHA256]::Create()" in script
    assert ".ComputeHash(" in script
    assert "[Convert]::ToHexString" not in script
    assert "::HashData(" not in script
    assert "$PSHOME 'Modules\\Microsoft.PowerShell.Security" in script
    assert "Microsoft.PowerShell.Security\\Get-AuthenticodeSignature" in script


def test_real_windows_powershell_authenticode_integration() -> None:
    if os.name != "nt":
        return

    powershell_path = verifier._trusted_windows_powershell_path()
    evidence = verifier.inspect_authenticode_signature(powershell_path)

    assert powershell_path.is_absolute()
    assert evidence["status"] == "Valid"
    assert evidence["timestamp_present"] is True
    assert len(evidence["signer_certificate_sha256"]) == 64
