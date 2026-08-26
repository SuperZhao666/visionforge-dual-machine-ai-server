from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import package_formal_release_bundle as packager  # noqa: E402
from tools.verify_formal_release_bundle import (  # noqa: E402
    DEVICE_EVIDENCE_SCHEMA,
    EXPECTED_GAME_DISPLAY_NAMES,
    EXPECTED_GAME_TOKENS,
    EXPECTED_MODEL_TARGET_CONTRACTS,
    REQUIRED_DEVICE_EVIDENCE_FLAGS,
)
from tests._physical_output_route_fixture import (  # noqa: E402
    valid_physical_output_routes,
)
from tests._final_safe_idle_fixture import (  # noqa: E402
    final_safe_idle_ui_xml,
    valid_final_safe_idle_payload,
)
from tools.physical_output_route_evidence import canonical_sha256  # noqa: E402
from tools.formal_release_manifest_security import (  # noqa: E402
    ENVELOPE_SCHEMA,
    load_private_key,
    public_key_pem,
    verify_manifest_envelope,
)


_CREATE_BUNDLE = packager.create_publishable_release_bundle


def _signing_key_path(acceptance_report_path: Path) -> Path:
    key_path = acceptance_report_path.parent.parent / "offline-manifest-signing.pem"
    if not key_path.exists():
        key_path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return key_path


def _create_bundle(
    *,
    acceptance_report_path: Path,
    output_dir: Path,
    force: bool = False,
) -> Mapping[str, Any]:
    return _CREATE_BUNDLE(
        acceptance_report_path=acceptance_report_path,
        output_dir=output_dir,
        signing_private_key_path=_signing_key_path(acceptance_report_path),
        channel="stable",
        release_version="1.0.8",
        bundle_sequence=8,
        min_supported_version="1.0.0",
        revocation_epoch=0,
        force=force,
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_successful_acceptance(tmp_path: Path) -> Path:
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    windows = acceptance_dir / "VisionForge_Protected.exe"
    android = acceptance_dir / "VFMobile_1.0.0.apk"
    host = acceptance_dir / "VFHost.exe"
    android_sha = acceptance_dir / "VFMobile_1.0.0.apk.sha256"
    windows.write_bytes(b"MZwindows")
    android.write_bytes(b"apk")
    host.write_bytes(b"MZhost")
    android_sha.write_text(_sha(android) + f"  {android.name}\n", encoding="utf-8")
    evidence_source_root = acceptance_dir / "device_evidence_sources"
    device_ui = evidence_source_root / "device-ui"
    device_ui.mkdir(parents=True)
    control_xml = device_ui / "control.xml"
    control_xml.write_text(final_safe_idle_ui_xml(), encoding="utf-8")
    mobile_log = evidence_source_root / "mobile_logs" / "01-mobile-logcat.txt"
    mobile_log.parent.mkdir()
    mobile_log.write_text("QNN graphExecute control move smoke", encoding="utf-8")
    mobile_log_sha256 = _sha(mobile_log)
    android_apk_sha256 = _sha(android)
    physical_routes = valid_physical_output_routes(
        android_apk_sha256=android_apk_sha256,
        device_serial="R5CT",
        mobile_log_sha256=mobile_log_sha256,
    )
    safe_idle_payload = valid_final_safe_idle_payload(
        android_apk_sha256=android_apk_sha256,
        device_serial="R5CT",
        mobile_log_sha256=mobile_log_sha256,
        ui_xml_sha256=_sha(control_xml),
        ui_xml=control_xml.read_text(encoding="utf-8"),
        physical_output_routes=physical_routes,
    )

    device_evidence = _write_json(
        acceptance_dir / "formal_device_evidence.json",
        {
            "schema": DEVICE_EVIDENCE_SCHEMA,
            "device_serial": "R5CT",
            "installed_package_name": "com.visionforge.mobile",
            "installed_package_version": "1.0.0-rc1",
            "checks": {key: True for key in REQUIRED_DEVICE_EVIDENCE_FLAGS},
            "game_model_tokens": list(EXPECTED_GAME_TOKENS),
            "game_display_names": EXPECTED_GAME_DISPLAY_NAMES,
            "model_target_contracts": EXPECTED_MODEL_TARGET_CONTRACTS,
            "windows_exe_sha256": _sha(windows),
            "android_apk_sha256": android_apk_sha256,
            "host_exe_sha256": _sha(host),
            "physical_output_routes": physical_routes,
            "final_safe_idle": {
                "evidence_sha256": canonical_sha256(safe_idle_payload),
                "evidence": safe_idle_payload,
            },
            "sources": {
                "android_apk": str(android),
                "windows_exe": str(windows),
                "host_exe": str(host),
                "ui_evidence_dir": str(device_ui),
                "mobile_logs": [str(mobile_log)],
                "host_logs": [],
            },
        },
    )
    bundle_report = _write_json(
        acceptance_dir / "formal_release_bundle_verify.json",
        {
            "schema": "visionforge-formal-release-bundle-v1",
            "mode": "formal",
            "diagnostic_completed": True,
            "checks_ok": True,
            "strict_ok": True,
            "reverse_resistance_ok": True,
            "formal_eligible": True,
            "formal_ok": True,
            "formal_release_ok": True,
            "bypasses": [],
            "ok": True,
            "checks": [
                {
                    "name": "windows_release",
                    "ok": True,
                    "evidence": {"exe": str(windows), "sha256": _sha(windows)},
                },
                {
                    "name": "android_release_apk",
                    "ok": True,
                    "evidence": {"apk": str(android), "sha256": _sha(android)},
                },
                {
                    "name": "host_release",
                    "ok": True,
                    "evidence": {"host": str(host), "sha256": _sha(host)},
                },
                {
                    "name": "source_contracts",
                    "ok": True,
                    "evidence": {
                        "checked": 54,
                        "base_checks_ok": True,
                        "reverse_resistance_ok": True,
                        "failed": [],
                    },
                },
                {
                    "name": "device_evidence",
                    "ok": True,
                    "evidence": {"path": str(device_evidence), "errors": []},
                },
            ],
        },
    )
    android_signing_report_path = acceptance_dir / "android_production_signing_inputs.json"
    android_release_report = _write_json(
        acceptance_dir / "android_production_release_build.json",
        {
            "schema": "visionforge-android-production-release-build-v1",
            "ok": True,
            "stage": "complete",
            "signing_report_path": str(android_signing_report_path),
            "artifact": {
                "apk": str(android),
                "sha256_file": str(android_sha),
                "sha256": _sha(android),
                "source_apk": str(android),
            },
        },
    )
    android_signing_report = _write_json(
        android_signing_report_path,
        {
            "schema": "visionforge-android-production-signing-inputs-v1",
            "ok": True,
            "inputs_present": {
                "store_file": True,
                "store_password": True,
                "key_alias": True,
                "key_password": True,
                "allow_development_signing": False,
            },
            "signing": {
                "store_file_outside_repository": True,
                "android_debug_certificate": False,
            },
        },
    )
    android_apk_report = _write_json(
        acceptance_dir / "android_release_apk_preflight.json",
        {
            "schema": "visionforge-android-release-apk-artifact-v1",
            "ok": True,
            "apk": str(android),
            "require_production_signing": True,
            "check": {
                "name": "android_release_apk",
                "ok": True,
                "detail": "ok",
                "evidence": {
                    "sha256": _sha(android),
                    "badging": {
                        "package": "com.visionforge.mobile",
                        "version_name": "1.0.0-rc1",
                    },
                },
            },
        },
    )
    android_device_report = _write_json(
        acceptance_dir / "android_device_connectivity.json",
        {
            "schema": "visionforge-android-device-connectivity-v1",
            "ok": True,
            "reason": "selected_single_device",
            "requested_serial": "R5CT",
            "selected_serial": "R5CT",
            "devices": [
                {
                    "serial": "R5CT",
                    "state": "device",
                    "raw": "R5CT device product:xiaomi",
                },
            ],
            "adb_returncode": 0,
        },
    )
    return _write_json(
        acceptance_dir / "formal_release_acceptance.json",
        {
            "schema": "visionforge-formal-release-acceptance-v1",
            "ok": True,
            "artifacts": {
                "windows_exe": str(windows),
                "android_apk": str(android),
                "android_apk_input": str(android),
                "host_exe": str(host),
            },
            "run_parameters": {
                "windows_exe": str(windows),
                "android_apk_input": str(android),
                "host_exe": str(host),
                "adb_path": "",
                "device_serial": "R5CT",
                "build_apk": True,
                "expect_control_locked": False,
                "remove_legacy_benchmark_package": False,
                "timeouts_sec": {
                    "android_build": 10,
                    "device_preflight": 9,
                    "installer": 11,
                    "verifier": 12,
                },
            },
            "device_evidence": str(device_evidence),
            "bundle_report": str(bundle_report),
            "android_release_report": str(android_release_report),
            "android_signing_report": str(android_signing_report),
            "android_apk_report": str(android_apk_report),
            "android_device_report": str(android_device_report),
            "release_blockers": [],
            "next_actions": [],
            "android_signing_preflight": {"returncode": 0},
            "android_apk_preflight": {"returncode": 0},
            "android_device_preflight": {"returncode": 0},
            "android_release_builder": {"returncode": 0},
            "installer": {
                "returncode": 0,
                "cmd": [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(
                        ROOT
                        / "android_inference_benchmark"
                        / "tools"
                        / "install_mobile_release.ps1"
                    ),
                    "-ApkPath",
                    str(android),
                    "-Launch",
                    "-VerifyUi",
                    "-WindowsExePath",
                    str(windows),
                    "-HostExePath",
                    str(host),
                    "-DeviceSerial",
                    "R5CT",
                ],
            },
            "bundle_verifier": {"returncode": 0},
        },
    )


def test_package_formal_release_bundle_copies_only_verified_artifacts(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"

    manifest = _create_bundle(
        acceptance_report_path=acceptance,
        output_dir=output_dir,
    )

    manifest_path = output_dir / "formal_release_manifest.json"
    persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
    signing_key = load_private_key(
        (tmp_path / "offline-manifest-signing.pem").read_bytes()
    )
    signed_payload = verify_manifest_envelope(
        persisted,
        public_key_pem(signing_key.public_key()),
    )
    roles = {item["role"] for item in manifest["artifacts"]}
    assert manifest["ok"] is True
    assert persisted["schema"] == ENVELOPE_SCHEMA
    assert signed_payload["schema"] == packager.SCHEMA
    assert signed_payload["bundle_sequence"] == 8
    assert "acceptance_report" not in signed_payload
    assert "output_dir" not in signed_payload
    assert all("path" not in item for item in signed_payload["artifacts"])
    assert "path" not in signed_payload["evidence_sources"]
    assert "archive" not in persisted
    archive = Path(manifest["archive"]["path"])
    archive_sha = Path(manifest["archive"]["sha256_path"])
    assert archive.name == packager.ARCHIVE_NAME
    assert archive.is_file()
    assert archive_sha.is_file()
    archive_verifier = Path(manifest["archive_verifier"]["path"])
    assert archive_verifier.name == packager.PUBLISHABLE_ARCHIVE_VERIFY_NAME
    assert archive_verifier.is_file()
    verifier_report = json.loads(archive_verifier.read_text(encoding="utf-8"))
    assert verifier_report["ok"] is True
    assert manifest["archive"]["sha256"] == _sha(archive)
    assert archive_sha.read_text(encoding="utf-8") == (
        manifest["archive"]["sha256"] + "  " + archive.name + "\n"
    )
    evidence_sources = manifest["evidence_sources"]
    evidence_source_root = output_dir / "device_evidence_sources"
    assert evidence_sources["role"] == "device_evidence_sources"
    assert Path(evidence_sources["path"]) == evidence_source_root
    assert evidence_sources["archive_path"] == "device_evidence_sources"
    assert (evidence_source_root / "device-ui" / "control.xml").is_file()
    assert (evidence_source_root / "mobile_logs" / "01-mobile-logcat.txt").is_file()
    evidence_file_hashes = {
        item["archive_path"]: item["sha256"]
        for item in evidence_sources["files"]
    }
    assert evidence_file_hashes == {
        "device_evidence_sources/device-ui/control.xml": _sha(
            evidence_source_root / "device-ui" / "control.xml"
        ),
        "device_evidence_sources/mobile_logs/01-mobile-logcat.txt": _sha(
            evidence_source_root / "mobile_logs" / "01-mobile-logcat.txt"
        ),
    }
    assert {
        "windows_exe",
        "android_apk",
        "host_exe",
        "formal_acceptance_report",
        "formal_bundle_report",
        "formal_device_evidence",
        "android_release_report",
        "android_signing_report",
        "android_apk_report",
        "android_device_report",
    }.issubset(roles)
    for item in manifest["artifacts"]:
        copied = Path(item["path"])
        assert copied.is_file()
        assert item["archive_path"] == copied.name
        assert item["sha256"] == _sha(copied)
    copied_evidence = json.loads(
        (output_dir / "formal_device_evidence.json").read_text(encoding="utf-8")
    )
    copied_sources = copied_evidence["sources"]
    assert copied_sources["windows_exe"] == "VisionForge_Protected.exe"
    assert copied_sources["android_apk"] == "VFMobile_1.0.0.apk"
    assert copied_sources["host_exe"] == "VFHost.exe"
    assert copied_sources["ui_evidence_dir"] == "device_evidence_sources/device-ui"
    assert copied_sources["mobile_logs"] == [
        "device_evidence_sources/mobile_logs/01-mobile-logcat.txt"
    ]
    assert not Path(copied_sources["ui_evidence_dir"]).is_absolute()
    assert not Path(copied_sources["mobile_logs"][0]).is_absolute()
    assert str(acceptance.parent) not in json.dumps(copied_sources)
    expected_archive_names = {Path(item["path"]).name for item in manifest["artifacts"]}
    expected_archive_names.update(
        {
            "formal_release_manifest.json",
            "device_evidence_sources/device-ui/control.xml",
            "device_evidence_sources/mobile_logs/01-mobile-logcat.txt",
        }
    )
    with zipfile.ZipFile(archive) as release_archive:
        assert set(release_archive.namelist()) == expected_archive_names
        archive_names = set(release_archive.namelist())
        assert {item["archive_path"] for item in manifest["artifacts"]}.issubset(archive_names)
        assert {item["archive_path"] for item in evidence_sources["files"]}.issubset(archive_names)
        archived_evidence = json.loads(release_archive.read("formal_device_evidence.json"))
        assert archived_evidence["sources"] == copied_sources
        archived_text = b"\n".join(
            release_archive.read(name)
            for name in release_archive.namelist()
            if name.endswith((".json", ".txt", ".xml"))
        )
        assert b"PRIVATE KEY" not in archived_text
        assert str(tmp_path / "offline-manifest-signing.pem").encode() not in archived_text


def test_package_formal_release_bundle_requires_explicit_offline_signer(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)

    with pytest.raises(ValueError, match="explicit offline Ed25519"):
        _CREATE_BUNDLE(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
            bundle_sequence=8,
        )


def test_package_formal_release_bundle_rejects_missing_run_parameters(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    del payload["run_parameters"]
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="missing run_parameters"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_legacy_host_filename(
    tmp_path: Path,
) -> None:
    legacy_host = tmp_path / "VisionForgeHost.exe"
    legacy_host.write_bytes(b"MZlegacy")
    report = {
        "artifacts": {
            "windows_exe": str(tmp_path / "VisionForge_Protected.exe"),
            "android_apk": str(tmp_path / "VFMobile.apk"),
            "host_exe": str(legacy_host),
        }
    }

    with pytest.raises(ValueError, match="must be named VFHost.exe"):
        packager._acceptance_artifact_paths(report, tmp_path)


def test_package_formal_release_bundle_rejects_non_build_apk_input_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["run_parameters"]["build_apk"] = False
    payload["run_parameters"]["android_apk_input"] = str(acceptance.parent / "debug.apk")
    payload["artifacts"]["android_apk_input"] = payload["run_parameters"]["android_apk_input"]
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="non-build android_apk_input"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_device_serial_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["run_parameters"]["device_serial"] = "DIFFERENT"
    command = payload["installer"]["cmd"]
    command[command.index("-DeviceSerial") + 1] = "DIFFERENT"
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="requested_serial"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_device_evidence_serial_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["device_serial"] = "OTHER"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="device_serial"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_installed_package_version_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["installed_package_version"] = "0.9.0"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="installed_package_version"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_installed_package_name_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["installed_package_name"] = "com.example.other"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="installed_package_name"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_missing_device_evidence_sources(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    del evidence["sources"]
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="sources are missing"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


@pytest.mark.parametrize("source_field", ("android_apk", "windows_exe", "host_exe"))
def test_package_formal_release_bundle_rejects_device_evidence_source_mismatch(
    tmp_path: Path,
    source_field: str,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["sources"][source_field] = str(acceptance.parent / f"other-{source_field}")
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match=fr"sources\.{source_field}"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_external_ui_evidence_source(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    outside_ui = tmp_path / "old-device-ui"
    outside_ui.mkdir()
    (outside_ui / "control.xml").write_text("<hierarchy />", encoding="utf-8")
    evidence["sources"]["ui_evidence_dir"] = str(outside_ui)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match=r"sources\.ui_evidence_dir"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_unstaged_ui_evidence_source(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    unstaged_ui = Path(payload["device_evidence"]).parent / "old-device-ui"
    unstaged_ui.mkdir()
    (unstaged_ui / "control.xml").write_text("<hierarchy />", encoding="utf-8")
    evidence["sources"]["ui_evidence_dir"] = str(unstaged_ui)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match=r"sources\.ui_evidence_dir"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_external_mobile_log_source(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    outside_log = tmp_path / "old-mobile-logcat.txt"
    outside_log.write_text("old log", encoding="utf-8")
    evidence["sources"]["mobile_logs"] = [str(outside_log)]
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match=r"sources\.mobile_logs"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_accepts_matching_explicit_adb_path(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    adb_path = acceptance.parent / "platform-tools" / "adb.exe"
    payload["run_parameters"]["adb_path"] = str(adb_path)
    payload["installer"]["cmd"].extend(["-AdbPath", str(adb_path)])
    report_path = Path(payload["android_device_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["adb_path"] = str(adb_path)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    manifest = _create_bundle(
        acceptance_report_path=acceptance,
        output_dir=tmp_path / "publishable",
    )

    assert manifest["ok"] is True


def test_package_formal_release_bundle_rejects_adb_path_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["run_parameters"]["adb_path"] = str(acceptance.parent / "adb-a.exe")
    payload["installer"]["cmd"].extend(["-AdbPath", payload["run_parameters"]["adb_path"]])
    report_path = Path(payload["android_device_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["adb_path"] = str(acceptance.parent / "adb-b.exe")
    report_path.write_text(json.dumps(report), encoding="utf-8")
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="adb_path"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_installer_apk_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    command = payload["installer"]["cmd"]
    command[command.index("-ApkPath") + 1] = str(acceptance.parent / "wrong.apk")
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="installer command APK"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_installer_rebuild_flag(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["installer"]["cmd"].append("-Build")
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="must not rebuild"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_installer_control_flag_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["run_parameters"]["expect_control_locked"] = True
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="ExpectControlLocked"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_acceptance(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["ok"] = False
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="not successful"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_acceptance_with_release_blockers(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["release_blockers"] = [
        {
            "stage": "android_device_preflight",
            "returncode": 2,
            "report": str(acceptance.parent / "android_device_connectivity.json"),
        }
    ]
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="release_blockers must be empty"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_acceptance_with_next_actions(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["next_actions"] = [
        {
            "stage": "android_apk_preflight",
            "action": "Replace debug-signed APK",
            "command": "python tools\\run_formal_release_acceptance.py --build-apk",
        }
    ]
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="next_actions must be empty"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_cli_prints_acceptance_release_blockers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["release_blockers"] = [
        {
            "stage": "android_device_preflight",
            "returncode": 2,
            "report": str(acceptance.parent / "android_device_connectivity.json"),
            "detail": "[ERROR] Android ADB device is not ready; reason=no_authorized_device",
            "details": [
                "[ERROR] Android ADB device is not ready; reason=no_authorized_device",
            ],
            "stdout_tail": "[ERROR] stale fallback detail\n",
            "stderr_tail": "",
        }
    ]
    payload["next_actions"] = [
        {
            "stage": "android_device_preflight",
            "action": "Authorize or connect exactly one target phone before formal acceptance.",
            "reason": "no_authorized_device",
            "command": "adb devices -l",
            "commands": ["adb mdns services", "adb devices -l"],
            "hint": "No ADB mDNS services were discovered.",
        }
    ]
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    result = packager.main(
        [
            "--acceptance-report",
            str(acceptance),
            "--output-dir",
            str(tmp_path / "publishable"),
            "--private-key",
            str(_signing_key_path(acceptance)),
            "--bundle-sequence",
            "8",
        ],
    )

    output = capsys.readouterr().out
    assert result == 1
    assert "[ERROR] publishable release bundle rejected" in output
    assert "[ERROR] release blockers:" in output
    assert "- android_device_preflight returncode=2" in output
    assert "no_authorized_device" in output
    assert "stale fallback detail" not in output
    assert "[ERROR] next actions:" in output
    assert "- android_device_preflight: Authorize or connect exactly one target phone" in output
    assert "command=adb devices -l" in output
    assert "commands=adb mdns services, adb devices -l" in output
    assert "hint=No ADB mDNS services were discovered." in output
    rejection_reports = sorted(tmp_path.glob("publishable.rejected_*.json"))
    assert len(rejection_reports) == 1
    rejection = json.loads(rejection_reports[0].read_text(encoding="utf-8"))
    assert rejection["acceptance_report"] == str(acceptance.resolve())
    assert rejection["acceptance_ok"] is True
    assert rejection["acceptance_release_blockers_empty"] is False
    assert rejection["acceptance_next_actions_empty"] is False
    assert rejection["acceptance_packaging_ready"] is False
    assert rejection["release_blockers"][0]["detail"] == (
        "[ERROR] Android ADB device is not ready; reason=no_authorized_device"
    )
    assert rejection["next_actions"][0]["command"] == "adb devices -l"
    assert rejection["next_actions"][0]["commands"] == [
        "adb mdns services",
        "adb devices -l",
    ]


def test_package_formal_release_bundle_rejects_bundle_hash_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    Path(payload["artifacts"]["android_apk"]).write_bytes(b"tampered-apk")

    with pytest.raises(ValueError, match="android_apk sha256"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_missing_device_evidence_flag(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["checks"]["qnn_htp_graph_execute"] = False
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="qnn_htp_graph_execute"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_wrong_game_display_name(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["game_display_names"]["delta-force-416-v8s"] = "Delta Force"
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"game_display_names\.delta-force-416-v8s",
    ):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_wrong_overwatch_target_contract(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["model_target_contracts"]["overwatch2-416-yolov5"]["lock_class_id"] = 1
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match=r"model_target_contracts\.overwatch2-416-yolov5\.lock_class_id",
    ):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_device_evidence_hash_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    evidence_path = Path(payload["device_evidence"])
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["android_apk_sha256"] = "0" * 64
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(ValueError, match="android_apk_sha256"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_bundle_report(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["ok"] = False
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="bundle verifier report"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("mode", "development", "mode is not formal"),
        ("strict_ok", False, "strict_ok is not true"),
        ("formal_eligible", False, "formal_eligible is not true"),
        ("formal_ok", False, "formal_ok is not true"),
        ("formal_release_ok", False, "formal_release_ok is not true"),
        ("bypasses", ["host_authenticode"], "bypasses must be empty"),
    ),
)
def test_package_formal_release_bundle_rejects_non_formal_report_fields(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle[field] = value
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_bundle_report_without_device_check(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["checks"] = [
        check for check in bundle["checks"] if check["name"] != "device_evidence"
    ]
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="missing required checks: device_evidence"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_bundle_report_artifact_path_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for check in bundle["checks"]:
        if check["name"] == "android_release_apk":
            check["evidence"]["apk"] = str(bundle_path)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="android_release_apk path"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_bundle_report_device_path_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for check in bundle["checks"]:
        if check["name"] == "device_evidence":
            check["evidence"]["path"] = str(bundle_path)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    with pytest.raises(ValueError, match="device_evidence path"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_command_result(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["installer"]["returncode"] = 1
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="installer did not pass"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_device_preflight(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["android_device_preflight"]["returncode"] = 2
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="android_device_preflight did not pass"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_apk_preflight(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["android_apk_preflight"]["returncode"] = 2
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="android_apk_preflight did not pass"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_unsuccessful_apk_preflight_report(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    report_path = Path(payload["android_apk_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["ok"] = False
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="android_apk_report is not successful"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_apk_preflight_hash_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    report_path = Path(payload["android_apk_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["check"]["evidence"]["sha256"] = "0" * 64
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="android_apk_report sha256"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_android_release_source_apk_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    report_path = Path(payload["android_release_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["artifact"]["source_apk"] = str(acceptance.parent / "other-input.apk")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="source_apk"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_android_release_signing_report_mismatch(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    report_path = Path(payload["android_release_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["signing_report_path"] = str(acceptance.parent / "other-signing-report.json")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="signing_report_path"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_device_report_without_selected_device(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    report_path = Path(payload["android_device_report"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["selected_serial"] = ""
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="selected_serial"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_preflight_report_outside_acceptance_dir(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    outside = _write_json(
        tmp_path / "outside_android_release_apk_preflight.json",
        json.loads(Path(payload["android_apk_report"]).read_text(encoding="utf-8")),
    )
    payload["android_apk_report"] = str(outside)
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="inside the formal acceptance directory"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_device_evidence_outside_acceptance_dir(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    outside = _write_json(
        tmp_path / "outside_formal_device_evidence.json",
        json.loads(Path(payload["device_evidence"]).read_text(encoding="utf-8")),
    )
    payload["device_evidence"] = str(outside)
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="inside the formal acceptance directory"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_bundle_report_outside_acceptance_dir(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    outside = _write_json(
        tmp_path / "outside_formal_release_bundle_verify.json",
        json.loads(Path(payload["bundle_report"]).read_text(encoding="utf-8")),
    )
    payload["bundle_report"] = str(outside)
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="inside the formal acceptance directory"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_rejects_failed_signing_preflight(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    payload["android_signing_preflight"]["returncode"] = 1
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="android_signing_preflight did not pass"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )


def test_package_formal_release_bundle_refuses_manifest_overwrite(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"
    _create_bundle(
        acceptance_report_path=acceptance,
        output_dir=output_dir,
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
        )


def test_package_formal_release_bundle_cli_failure_does_not_overwrite_manifest(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"
    _create_bundle(
        acceptance_report_path=acceptance,
        output_dir=output_dir,
    )
    manifest_path = output_dir / "formal_release_manifest.json"
    original_manifest = manifest_path.read_text(encoding="utf-8")

    result = packager.main(
        [
            "--acceptance-report",
            str(acceptance),
            "--output-dir",
            str(output_dir),
            "--private-key",
            str(_signing_key_path(acceptance)),
            "--bundle-sequence",
            "8",
        ],
    )

    assert result == 1
    assert manifest_path.read_text(encoding="utf-8") == original_manifest
    rejection_reports = sorted(tmp_path.glob("publishable.rejected_*.json"))
    assert len(rejection_reports) == 1
    rejection = json.loads(rejection_reports[0].read_text(encoding="utf-8"))
    assert rejection["ok"] is False
    assert rejection["output_dir"] == str(output_dir.resolve())
    assert "refusing to overwrite" in rejection["error"]


def test_package_formal_release_bundle_removes_success_manifest_when_archive_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"

    def fail_archive(
        archive_output_dir: Path,
        artifacts: object,
        manifest_path: Path,
    ) -> object:
        assert manifest_path.is_file()
        (archive_output_dir / packager.ARCHIVE_NAME).write_bytes(b"partial")
        (archive_output_dir / packager.ARCHIVE_SHA256_NAME).write_text(
            "partial\n",
            encoding="utf-8",
        )
        raise RuntimeError("archive failed")

    monkeypatch.setattr(packager, "_create_release_archive", fail_archive)

    with pytest.raises(RuntimeError, match="archive failed"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
        )

    assert not (output_dir / "formal_release_manifest.json").exists()
    assert not (output_dir / packager.ARCHIVE_NAME).exists()
    assert not (output_dir / packager.ARCHIVE_SHA256_NAME).exists()
    assert not (output_dir / packager.PUBLISHABLE_ARCHIVE_VERIFY_NAME).exists()


def test_package_formal_release_bundle_removes_outputs_when_archive_verifier_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"

    def fail_verifier(
        archive_output_dir: Path,
        archive: object,
        **_: object,
    ) -> object:
        assert archive
        (archive_output_dir / packager.PUBLISHABLE_ARCHIVE_VERIFY_NAME).write_text(
            '{"ok": false}',
            encoding="utf-8",
        )
        raise RuntimeError("publishable archive verification failed")

    monkeypatch.setattr(packager, "_verify_publishable_archive", fail_verifier)

    with pytest.raises(RuntimeError, match="publishable archive verification failed"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
        )

    assert not (output_dir / "formal_release_manifest.json").exists()
    assert not (output_dir / packager.ARCHIVE_NAME).exists()
    assert not (output_dir / packager.ARCHIVE_SHA256_NAME).exists()
    assert not (output_dir / packager.PUBLISHABLE_ARCHIVE_VERIFY_NAME).exists()


def test_package_formal_release_bundle_refuses_archive_overwrite(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"
    output_dir.mkdir()
    (output_dir / packager.ARCHIVE_NAME).write_bytes(b"old-archive")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
        )


def test_package_formal_release_bundle_refuses_unrelated_existing_output(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"
    output_dir.mkdir()
    (output_dir / "old-manual-note.txt").write_text("stale", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
        )


def test_package_formal_release_bundle_force_rejects_unrelated_existing_output(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    output_dir = tmp_path / "publishable"
    output_dir.mkdir()
    (output_dir / "old-manual-note.txt").write_text("stale", encoding="utf-8")

    with pytest.raises(FileExistsError, match="unrelated existing files"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=output_dir,
            force=True,
        )


def test_package_formal_release_bundle_rejects_duplicate_output_names(
    tmp_path: Path,
) -> None:
    acceptance = _write_successful_acceptance(tmp_path)
    payload = json.loads(acceptance.read_text(encoding="utf-8"))
    host_path = Path(payload["artifacts"]["host_exe"])
    payload["artifacts"]["windows_exe"] = str(host_path)
    payload["run_parameters"]["windows_exe"] = str(host_path)
    command = payload["installer"]["cmd"]
    command[command.index("-WindowsExePath") + 1] = str(host_path)
    device_evidence_path = Path(payload["device_evidence"])
    device_evidence = json.loads(device_evidence_path.read_text(encoding="utf-8"))
    device_evidence["windows_exe_sha256"] = _sha(host_path)
    device_evidence["sources"]["windows_exe"] = str(host_path)
    device_evidence_path.write_text(json.dumps(device_evidence), encoding="utf-8")
    bundle_path = Path(payload["bundle_report"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for check in bundle["checks"]:
        if check["name"] == "windows_release":
            check["evidence"]["exe"] = str(host_path)
            check["evidence"]["sha256"] = _sha(host_path)
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    acceptance.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate output names"):
        _create_bundle(
            acceptance_report_path=acceptance,
            output_dir=tmp_path / "publishable",
        )
