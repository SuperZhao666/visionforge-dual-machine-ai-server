from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_publishable_release_bundle as verifier  # noqa: E402
from tests._physical_output_route_fixture import (  # noqa: E402
    valid_physical_output_routes,
)
from tests._final_safe_idle_fixture import (  # noqa: E402
    final_safe_idle_ui_xml,
    valid_final_safe_idle_payload,
)
from tools.physical_output_route_evidence import canonical_sha256  # noqa: E402
from tools.formal_release_manifest_security import sign_manifest_payload  # noqa: E402


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_bundle(
    tmp_path: Path,
    *,
    sidecar_hash: str | None = None,
    artifact_sha_override: str | None = None,
    acceptance_override: Mapping[str, Any] | None = None,
    bundle_report_override: Mapping[str, Any] | None = None,
    evidence_hash_override: Mapping[str, str] | None = None,
    evidence_source_override: Mapping[str, Any] | None = None,
    check_override: Mapping[str, bool] | None = None,
    game_display_name_override: Mapping[str, str] | None = None,
    model_target_contract_override: Mapping[str, Any] | None = None,
    omit_manifest_roles: set[str] | None = None,
    tamper_safe_idle_records: bool = False,
    host_archive_name: str = "VFHost.exe",
    manifest_envelope_override: Mapping[str, Any] | None = None,
    unsigned_manifest: bool = False,
    extra_archive_entries: Mapping[str, bytes] | None = None,
) -> tuple[Path, Path]:
    archive = tmp_path / "formal_release_bundle.zip"
    files: dict[str, bytes] = {
        "VisionForge_Protected.exe": b"MZwindows",
        "VFMobile_1.0.0.apk": b"apk",
        host_archive_name: b"MZhost",
        "device_evidence_sources/device-ui/control.xml": (
            final_safe_idle_ui_xml().encode("utf-8")
        ),
        "device_evidence_sources/mobile_logs/01-mobile-logcat.txt": b"QNN move smoke",
    }
    bundle_report: dict[str, Any] = {
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
            {"name": "windows_release", "ok": True, "evidence": {}},
            {"name": "android_release_apk", "ok": True, "evidence": {}},
            {"name": "host_release", "ok": True, "evidence": {}},
            {
                "name": "source_contracts",
                "ok": True,
                "evidence": {
                    "base_checks_ok": True,
                    "reverse_resistance_ok": True,
                    "failed": [],
                },
            },
            {"name": "device_evidence", "ok": True, "evidence": {}},
        ],
    }
    if bundle_report_override:
        bundle_report.update(bundle_report_override)
    files["formal_release_bundle_verify.json"] = json.dumps(bundle_report).encode(
        "utf-8"
    )
    acceptance = {
        "schema": "visionforge-formal-release-acceptance-v1",
        "ok": True,
        "release_blockers": [],
        "next_actions": [],
    }
    if acceptance_override:
        acceptance.update(acceptance_override)
    files["formal_release_acceptance.json"] = json.dumps(acceptance).encode("utf-8")
    sources = {
        "windows_exe": "VisionForge_Protected.exe",
        "android_apk": "VFMobile_1.0.0.apk",
        "host_exe": host_archive_name,
        "ui_evidence_dir": "device_evidence_sources/device-ui",
        "mobile_logs": ["device_evidence_sources/mobile_logs/01-mobile-logcat.txt"],
        "host_logs": [],
    }
    if evidence_source_override:
        sources.update(evidence_source_override)
    checks = {key: True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS}
    if check_override:
        checks.update(check_override)
    evidence_hashes = {
        "windows_exe_sha256": _sha(files["VisionForge_Protected.exe"]),
        "android_apk_sha256": _sha(files["VFMobile_1.0.0.apk"]),
        "host_exe_sha256": _sha(files[host_archive_name]),
    }
    if evidence_hash_override:
        evidence_hashes.update(evidence_hash_override)
    physical_routes = valid_physical_output_routes(
        android_apk_sha256=evidence_hashes["android_apk_sha256"],
        device_serial="R5CT",
        mobile_log_sha256=_sha(
            files["device_evidence_sources/mobile_logs/01-mobile-logcat.txt"]
        ),
    )
    safe_idle_payload = valid_final_safe_idle_payload(
        android_apk_sha256=evidence_hashes["android_apk_sha256"],
        device_serial="R5CT",
        mobile_log_sha256=_sha(
            files["device_evidence_sources/mobile_logs/01-mobile-logcat.txt"]
        ),
        ui_xml_sha256=_sha(
            files["device_evidence_sources/device-ui/control.xml"]
        ),
        ui_xml=files["device_evidence_sources/device-ui/control.xml"].decode("utf-8"),
        physical_output_routes=physical_routes,
    )
    if tamper_safe_idle_records:
        safe_idle_payload["mobile_events"].append(
            {
                "timestamp_unix_ms": (
                    int(
                        safe_idle_payload["metrics"][
                            "terminal_health_timestamp_unix_ms"
                        ]
                    )
                    + 1_000
                ),
                "sequence": 99,
                "event": "dual_machine_formal_data_plane_opened",
                "detail": "host_authorization=false",
            }
        )
    evidence = {
        "schema": verifier.DEVICE_EVIDENCE_SCHEMA,
        "device_serial": "R5CT",
        "installed_package_name": verifier.EXPECTED_ANDROID_PACKAGE,
        "installed_package_version": "1.0.0-rc1",
        "game_model_tokens": list(verifier.EXPECTED_GAME_TOKENS),
        "game_display_names": (
            game_display_name_override
            or verifier.EXPECTED_GAME_DISPLAY_NAMES
        ),
        "model_target_contracts": (
            model_target_contract_override
            or verifier.EXPECTED_MODEL_TARGET_CONTRACTS
        ),
        "checks": checks,
        **evidence_hashes,
        "physical_output_routes": physical_routes,
        "final_safe_idle": {
            "evidence_sha256": canonical_sha256(safe_idle_payload),
            "evidence": safe_idle_payload,
        },
        "sources": sources,
    }
    files["formal_device_evidence.json"] = json.dumps(evidence).encode("utf-8")
    artifact_sha = artifact_sha_override or _sha(files["VisionForge_Protected.exe"])
    artifacts = [
        {
            "role": "windows_exe",
            "archive_path": "VisionForge_Protected.exe",
            "size": len(files["VisionForge_Protected.exe"]),
            "sha256": artifact_sha,
        },
        {
            "role": "android_apk",
            "archive_path": "VFMobile_1.0.0.apk",
            "size": len(files["VFMobile_1.0.0.apk"]),
            "sha256": _sha(files["VFMobile_1.0.0.apk"]),
        },
        {
            "role": "host_exe",
            "archive_path": host_archive_name,
            "size": len(files[host_archive_name]),
            "sha256": _sha(files[host_archive_name]),
        },
        {
            "role": "formal_acceptance_report",
            "archive_path": "formal_release_acceptance.json",
            "size": len(files["formal_release_acceptance.json"]),
            "sha256": _sha(files["formal_release_acceptance.json"]),
        },
        {
            "role": "formal_bundle_report",
            "archive_path": "formal_release_bundle_verify.json",
            "size": len(files["formal_release_bundle_verify.json"]),
            "sha256": _sha(files["formal_release_bundle_verify.json"]),
        },
        {
            "role": "formal_device_evidence",
            "archive_path": "formal_device_evidence.json",
            "size": len(files["formal_device_evidence.json"]),
            "sha256": _sha(files["formal_device_evidence.json"]),
        },
    ]
    if omit_manifest_roles:
        artifacts = [
            item for item in artifacts
            if str(item.get("role") or "") not in omit_manifest_roles
        ]
    manifest = {
        "schema": verifier.MANIFEST_SCHEMA,
        "ok": True,
        "channel": "stable",
        "release_version": "1.0.8",
        "bundle_sequence": 8,
        "published_at": "2026-08-04T00:00:00Z",
        "min_supported_version": "1.0.0",
        "revocation_epoch": 0,
        "artifacts": artifacts,
        "evidence_sources": {
            "role": "device_evidence_sources",
            "archive_path": "device_evidence_sources",
            "file_count": 2,
            "size": (
                len(files["device_evidence_sources/device-ui/control.xml"])
                + len(
                    files[
                        "device_evidence_sources/mobile_logs/01-mobile-logcat.txt"
                    ]
                )
            ),
            "files": [
                {
                    "archive_path": "device_evidence_sources/device-ui/control.xml",
                    "size": len(files["device_evidence_sources/device-ui/control.xml"]),
                    "sha256": _sha(files["device_evidence_sources/device-ui/control.xml"]),
                },
                {
                    "archive_path": "device_evidence_sources/mobile_logs/01-mobile-logcat.txt",
                    "size": len(files["device_evidence_sources/mobile_logs/01-mobile-logcat.txt"]),
                    "sha256": _sha(files["device_evidence_sources/mobile_logs/01-mobile-logcat.txt"]),
                },
            ],
        },
    }
    signing_key = Ed25519PrivateKey.generate()
    envelope = sign_manifest_payload(manifest, signing_key)
    if manifest_envelope_override:
        envelope.update(manifest_envelope_override)
    files["formal_release_manifest.json"] = json.dumps(
        manifest if unsigned_manifest else envelope
    ).encode("utf-8")
    if extra_archive_entries:
        files.update(extra_archive_entries)
    (tmp_path / "trusted_manifest_public.pem").write_bytes(
        signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for archive_path, payload in files.items():
            package.writestr(archive_path, payload)
    sidecar = tmp_path / "formal_release_bundle.zip.sha256"
    sidecar.write_text(
        f"{sidecar_hash or _sha(archive.read_bytes())}  {archive.name}\n",
        encoding="utf-8",
    )
    return archive, sidecar


def _verify_bundle(archive: Path, sidecar: Path) -> Mapping[str, Any]:
    return verifier.verify_publishable_release_bundle(
        archive_path=archive,
        sha256_path=sidecar,
        trusted_public_key_pem=(archive.parent / "trusted_manifest_public.pem").read_bytes(),
        expected_channel="stable",
        minimum_release_version="1.0.0",
        minimum_bundle_sequence=8,
        minimum_revocation_epoch=0,
    )


def _check(report: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    for item in report["checks"]:
        if item["name"] == name:
            return item
    raise AssertionError(f"missing check: {name}")


def test_verify_publishable_release_bundle_accepts_self_contained_archive(tmp_path: Path) -> None:
    archive, sidecar = _write_bundle(tmp_path)

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is True
    assert _check(report, "archive-sha256-sidecar")["ok"] is True
    assert _check(report, "manifest-artifacts")["ok"] is True
    acceptance_check = _check(report, "formal-acceptance-report")
    assert acceptance_check["ok"] is True
    assert acceptance_check["evidence"]["release_blockers_empty"] is True
    assert acceptance_check["evidence"]["next_actions_empty"] is True
    assert acceptance_check["evidence"]["release_blocker_count"] == 0
    assert acceptance_check["evidence"]["next_action_count"] == 0
    assert _check(report, "formal-bundle-report")["ok"] is True
    assert _check(report, "evidence-source-files")["ok"] is True
    assert _check(report, "device-evidence-sources")["ok"] is True
    assert _check(report, "device-evidence-contract")["ok"] is True


def test_verify_publishable_release_bundle_rejects_wrong_external_key(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path)
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    report = verifier.verify_publishable_release_bundle(
        archive_path=archive,
        sha256_path=sidecar,
        trusted_public_key_pem=wrong_key,
        expected_channel="stable",
        minimum_release_version="1.0.0",
        minimum_bundle_sequence=8,
        minimum_revocation_epoch=0,
    )

    assert report["ok"] is False
    assert report["authenticated"] is False
    assert _check(report, "manifest-signature")["ok"] is False


def test_verify_publishable_release_bundle_rejects_tampered_signature(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        manifest_envelope_override={"signature_b64": "A" * 88},
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "manifest-signature")["ok"] is False


def test_verify_publishable_release_bundle_rejects_unsigned_legacy_manifest(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path, unsigned_manifest=True)

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert report["authenticated"] is False
    assert _check(report, "manifest-signature")["ok"] is False


def test_verify_publishable_release_bundle_rejects_unsigned_extra_zip_entry(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        extra_archive_entries={"unexpected/patch.dll": b"MZinjected"},
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    closure = _check(report, "archive-entry-closure")
    assert closure["ok"] is False
    assert closure["evidence"]["unexpected"] == ["unexpected/patch.dll"]


def test_verify_publishable_release_bundle_rejects_duplicate_zip_entry(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path)
    with zipfile.ZipFile(archive, "a") as package:
        package.writestr("VFHost.exe", b"MZduplicate")
    sidecar.write_text(f"{_sha(archive.read_bytes())}  {archive.name}\n", encoding="utf-8")

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    structure = _check(report, "archive-entry-structure")
    assert structure["ok"] is False
    assert structure["evidence"]["duplicates"] == ["VFHost.exe"]


def test_verify_publishable_release_bundle_requires_external_rollback_floor(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path)

    report = verifier.verify_publishable_release_bundle(
        archive_path=archive,
        sha256_path=sidecar,
        trusted_public_key_pem=(tmp_path / "trusted_manifest_public.pem").read_bytes(),
    )

    assert report["ok"] is False
    assert report["authenticated"] is True
    assert report["anti_rollback_enforced"] is False
    assert _check(report, "manifest-rollback-policy")["ok"] is False


def test_verify_publishable_release_bundle_rejects_embedded_development_report(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        bundle_report_override={
            "schema": "visionforge-development-bundle-check-v1",
            "mode": "development",
            "strict_ok": False,
            "formal_eligible": False,
            "formal_ok": False,
            "formal_release_ok": False,
            "ok": False,
        },
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "formal-bundle-report")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "mode is not formal" in check["detail"]


def test_verify_publishable_release_bundle_rejects_embedded_bypass_report(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        bundle_report_override={"bypasses": ["host_authenticode"]},
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "formal-bundle-report")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "bypasses must be empty" in check["detail"]


def test_verify_publishable_release_bundle_rejects_legacy_host_filename(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        host_archive_name="VisionForgeHost.exe",
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    artifact_check = _check(report, "manifest-artifacts")
    assert artifact_check["ok"] is False
    assert "host_exe must point to VFHost.exe" in artifact_check["detail"]


def test_verify_publishable_release_bundle_rejects_sidecar_mismatch(tmp_path: Path) -> None:
    archive, sidecar = _write_bundle(tmp_path, sidecar_hash="0" * 64)

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "archive-sha256-sidecar")["ok"] is False


def test_verify_publishable_release_bundle_rejects_artifact_hash_mismatch(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path, artifact_sha_override="0" * 64)

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "manifest-artifacts")["ok"] is False


def test_verify_publishable_release_bundle_rejects_unhashed_acceptance_report(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        omit_manifest_roles={"formal_acceptance_report"},
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "manifest-artifacts")
    assert report["ok"] is False
    assert check["ok"] is False
    assert (
        "manifest artifact role formal_acceptance_report "
        "must point to formal_release_acceptance.json"
    ) in check["detail"]


def test_verify_publishable_release_bundle_rejects_stale_acceptance_next_actions(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        acceptance_override={
            "next_actions": [
                {
                    "stage": "android_apk_preflight",
                    "action": "Replace stale debug-signed APK",
                }
            ],
        },
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "formal-acceptance-report")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "formal acceptance next_actions must be empty" in check["detail"]
    assert check["evidence"]["release_blockers_empty"] is True
    assert check["evidence"]["next_actions_empty"] is False
    assert check["evidence"]["release_blocker_count"] == 0
    assert check["evidence"]["next_action_count"] == 1


def test_verify_publishable_release_bundle_rejects_absolute_evidence_source(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        evidence_source_override={"mobile_logs": ["C:/old/mobile-logcat.txt"]},
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "device-evidence-sources")["ok"] is False


def test_verify_publishable_release_bundle_rejects_device_evidence_hash_mismatch(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        evidence_hash_override={"android_apk_sha256": "0" * 64},
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "device-evidence-contract")["ok"] is False


def test_verify_publishable_release_bundle_rejects_incomplete_device_evidence_checks(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(
        tmp_path,
        check_override={"control_move_lock_smoke": False},
    )

    report = _verify_bundle(archive, sidecar)

    assert report["ok"] is False
    assert _check(report, "device-evidence-contract")["ok"] is False


def test_verify_publishable_release_bundle_recomputes_final_safe_idle_records(
    tmp_path: Path,
) -> None:
    archive, sidecar = _write_bundle(tmp_path, tamper_safe_idle_records=True)

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "device-evidence-contract")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "final safe-idle checks do not match raw records" in check["detail"]


def test_verify_publishable_release_bundle_rejects_wrong_game_display_name(
    tmp_path: Path,
) -> None:
    names = dict(verifier.EXPECTED_GAME_DISPLAY_NAMES)
    names["valorant-yellow-416-v11s-no-flash"] = "Valorant"
    archive, sidecar = _write_bundle(
        tmp_path,
        game_display_name_override=names,
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "device-evidence-contract")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "game_display_names.valorant-yellow-416-v11s-no-flash" in check["detail"]


def test_verify_publishable_release_bundle_rejects_wrong_overwatch_target_contract(
    tmp_path: Path,
) -> None:
    contracts = json.loads(json.dumps(verifier.EXPECTED_MODEL_TARGET_CONTRACTS))
    contracts["overwatch2-416-yolov5"]["ignored_class_names"] = ["enemy_body"]
    archive, sidecar = _write_bundle(
        tmp_path,
        model_target_contract_override=contracts,
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "device-evidence-contract")
    assert report["ok"] is False
    assert check["ok"] is False
    assert "model_target_contracts.overwatch2-416-yolov5.ignored_class_names" in check["detail"]


def test_verify_publishable_release_bundle_rejects_wrong_cs2_target_contract(
    tmp_path: Path,
) -> None:
    contracts = json.loads(json.dumps(verifier.EXPECTED_MODEL_TARGET_CONTRACTS))
    contracts["counter-strike-2-vombit-416-v8s"]["t_head_class_id"] = 1
    archive, sidecar = _write_bundle(
        tmp_path,
        model_target_contract_override=contracts,
    )

    report = _verify_bundle(archive, sidecar)

    check = _check(report, "device-evidence-contract")
    assert report["ok"] is False
    assert check["ok"] is False
    assert (
        "model_target_contracts.counter-strike-2-vombit-416-v8s.t_head_class_id"
        in check["detail"]
    )


def test_verify_publishable_release_bundle_cli_writes_failure_report(tmp_path: Path) -> None:
    archive, sidecar = _write_bundle(tmp_path, sidecar_hash="0" * 64)
    output = tmp_path / "publishable_release_bundle_verify.json"

    result = verifier.main(
        [
            "--archive",
            str(archive),
            "--sha256-file",
            str(sidecar),
            "--public-key",
            str(tmp_path / "trusted_manifest_public.pem"),
            "--expected-channel",
            "stable",
            "--minimum-release-version",
            "1.0.0",
            "--minimum-bundle-sequence",
            "8",
            "--minimum-revocation-epoch",
            "0",
            "--output",
            str(output),
        ]
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert result == 2
    assert report["ok"] is False
    assert _check(report, "archive-sha256-sidecar")["ok"] is False
