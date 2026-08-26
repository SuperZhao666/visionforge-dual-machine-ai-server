from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Sequence

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import build_android_production_release as builder  # noqa: E402
from tools.verify_formal_release_bundle import CheckResult  # noqa: E402


PRODUCTION_SIGNER = "b79af6fd1197588e6438483fc0f3eb28c1fc4d3649f18b9ce5c17cd2dafff139"


def _pass_apk(apk: Path, *, require_production_signing: bool) -> CheckResult:
    assert require_production_signing is True
    return CheckResult(
        name="android_release_apk",
        ok=True,
        detail="ok",
        evidence={
            "sha256": "a" * 64,
            "badging": {"version_name": "1.0.0-rc1"},
            "signing": {"signer_sha256": [PRODUCTION_SIGNER]},
        },
    )


def _pass_signing(output: Path) -> dict[str, object]:
    return {
        "ok": True,
        "signing": {"certificate_sha256": PRODUCTION_SIGNER},
    }


def _pass_tls_pin() -> dict[str, object]:
    return {
        "ok": True,
        "configured_pins": ["sha256/" + "A" * 44, "sha256/" + "B" * 44],
        "live_leaf_spki_pin": "sha256/" + "A" * 44,
    }


def test_android_release_build_stops_when_signing_preflight_fails(tmp_path: Path) -> None:
    output_dir = tmp_path / "release"
    calls: list[Sequence[str]] = []

    def fake_runner(
        command: Sequence[str],
        cwd: Path,
        timeout: int,
    ) -> builder.CommandResult:
        calls.append(tuple(command))
        return builder.CommandResult(tuple(command), str(cwd), 0, "", "")

    result = builder.build_android_production_release(
        output_dir=output_dir,
        signing_checker=lambda output: {
            "ok": False,
            "env_names": {
                "store_file": "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
                "store_password": "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
                "key_alias": "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
                "key_password": "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
            },
            "errors": ["VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required"],
        },
        tls_pin_checker=_pass_tls_pin,
        runner=fake_runner,
        apk_verifier=_pass_apk,
    )

    report = json.loads((output_dir / "android_production_release_build.json").read_text())
    assert result == 2
    assert calls == []
    assert report["ok"] is False
    assert report["stage"] == "android_signing_preflight"
    assert report["signing_errors"] == [
        "VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required",
    ]
    assert report["next_actions"][0]["required_env"] == [
        "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
        "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
        "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
        "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
    ]
    assert "create_android_release_keystore.py" in report["next_actions"][0]["command"]


def test_android_release_build_copies_verified_apk_and_writes_sha256(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "release"
    apk = tmp_path / "app-release.apk"
    apk.write_bytes(b"release-apk")
    mapping = tmp_path / "mapping.txt"
    mapping.write_text("com.example.Real -> a:\n", encoding="utf-8")
    private_symbols = tmp_path / "private-symbols"
    calls: list[Sequence[str]] = []

    def fake_runner(
        command: Sequence[str],
        cwd: Path,
        timeout: int,
    ) -> builder.CommandResult:
        calls.append(tuple(command))
        assert "gradlew.bat" in command
        assert "-PvisionforgeAllowDevelopmentSigning=true" not in command
        assert "-PvisionforgeFormalSecureDataPlaneOnly=true" in command
        return builder.CommandResult(tuple(command), str(cwd), 0, "built", "")

    result = builder.build_android_production_release(
        output_dir=output_dir,
        apk_path=apk,
        r8_mapping_path=mapping,
        private_symbols_dir=private_symbols,
        signing_checker=_pass_signing,
        tls_pin_checker=_pass_tls_pin,
        runner=fake_runner,
        apk_verifier=_pass_apk,
        test_only_allow_noncanonical_inputs=True,
    )

    report = json.loads((output_dir / "android_production_release_build.json").read_text())
    artifact = Path(report["artifact"]["apk"])
    sha_file = Path(report["artifact"]["sha256_file"])
    symbols_reports = list(private_symbols.glob("*.symbols.json"))
    assert result == 0
    assert len(calls) == 1
    assert artifact.name.startswith("VFMobile_1.0.0-rc1_")
    assert artifact.read_bytes() == b"release-apk"
    assert report["ok"] is True
    assert report["stage"] == "complete"
    assert report["next_actions"] == []
    assert report["artifact"]["sha256"] in sha_file.read_text(encoding="utf-8")
    assert len(symbols_reports) == 1
    symbols = json.loads(symbols_reports[0].read_text(encoding="utf-8"))
    archived_mapping = Path(symbols["mapping"])
    mapping_sha_file = Path(symbols["mapping_sha256_file"])
    assert archived_mapping.parent == private_symbols
    assert archived_mapping.read_text(encoding="utf-8") == "com.example.Real -> a:\n"
    assert symbols["mapping_sha256"] in mapping_sha_file.read_text(encoding="utf-8")
    assert all("mapping" not in key for key in report["artifact"])


def test_android_release_build_stops_when_apk_static_verification_fails(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "release"
    apk = tmp_path / "app-release.apk"
    apk.write_bytes(b"release-apk")
    mapping = tmp_path / "mapping.txt"
    mapping.write_text("com.example.Real -> a:\n", encoding="utf-8")

    def fake_runner(
        command: Sequence[str],
        cwd: Path,
        timeout: int,
    ) -> builder.CommandResult:
        return builder.CommandResult(tuple(command), str(cwd), 0, "built", "")

    def fail_apk(apk_path: Path, *, require_production_signing: bool) -> CheckResult:
        return CheckResult(
            name="android_release_apk",
            ok=False,
            detail="APK is signed with Android Debug certificate",
            evidence={"errors": ["APK is signed with Android Debug certificate"]},
        )

    result = builder.build_android_production_release(
        output_dir=output_dir,
        apk_path=apk,
        r8_mapping_path=mapping,
        private_symbols_dir=tmp_path / "private-symbols",
        signing_checker=_pass_signing,
        tls_pin_checker=_pass_tls_pin,
        runner=fake_runner,
        apk_verifier=fail_apk,
        test_only_allow_noncanonical_inputs=True,
    )

    report = json.loads((output_dir / "android_production_release_build.json").read_text())
    assert result == 5
    assert report["ok"] is False
    assert report["stage"] == "android_apk_static_verification"
    assert report["artifact"] is None


def test_android_release_build_stops_when_r8_mapping_is_missing(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "release"
    apk = tmp_path / "app-release.apk"
    apk.write_bytes(b"release-apk")

    result = builder.build_android_production_release(
        output_dir=output_dir,
        apk_path=apk,
        r8_mapping_path=tmp_path / "missing-mapping.txt",
        private_symbols_dir=tmp_path / "private-symbols",
        signing_checker=_pass_signing,
        tls_pin_checker=_pass_tls_pin,
        runner=lambda command, cwd, timeout: builder.CommandResult(
            tuple(command), str(cwd), 0, "built", ""
        ),
        apk_verifier=_pass_apk,
        test_only_allow_noncanonical_inputs=True,
    )

    report = json.loads((output_dir / "android_production_release_build.json").read_text())
    assert result == 4
    assert report["ok"] is False
    assert report["stage"] == "r8_mapping_verification"
    assert report["artifact"]["error"] == "R8 mapping.txt is missing or empty"


def test_android_release_build_rejects_noncanonical_production_inputs(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="canonical release APK"):
        builder.build_android_production_release(
            output_dir=tmp_path / "release",
            apk_path=tmp_path / "old.apk",
            r8_mapping_path=tmp_path / "unrelated-mapping.txt",
            private_symbols_dir=tmp_path / "private-symbols",
            signing_checker=_pass_signing,
            apk_verifier=_pass_apk,
        )


def test_android_release_build_rejects_signer_different_from_preflight(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "release"
    apk = tmp_path / "app-release.apk"
    apk.write_bytes(b"release-apk")
    mapping = tmp_path / "mapping.txt"
    mapping.write_text("com.example.Real -> a:\n", encoding="utf-8")

    result = builder.build_android_production_release(
        output_dir=output_dir,
        apk_path=apk,
        r8_mapping_path=mapping,
        private_symbols_dir=tmp_path / "private-symbols",
        signing_checker=lambda output: {
            "ok": True,
            "signing": {"certificate_sha256": "c" * 64},
        },
        tls_pin_checker=_pass_tls_pin,
        runner=lambda command, cwd, timeout: builder.CommandResult(
            tuple(command), str(cwd), 0, "built", ""
        ),
        apk_verifier=_pass_apk,
        test_only_allow_noncanonical_inputs=True,
    )

    report = json.loads((output_dir / "android_production_release_build.json").read_text())
    assert result == 6
    assert report["ok"] is False
    assert report["stage"] == "android_signer_provenance"
    assert report["artifact"] is None


def test_android_formal_release_gate_is_fail_closed_until_secure_v2_exists() -> None:
    android_app = ROOT / "android_inference_benchmark" / "app"
    gradle = (android_app / "build.gradle").read_text(encoding="utf-8")
    loader = (android_app / "formal-security-loader.gradle").read_text(
        encoding="utf-8",
    )
    capability = (
        android_app / "formal-security-capability.properties"
    ).read_text(
        encoding="ascii",
    )

    assert "apply from: 'formal-security-loader.gradle'" in gradle
    assert "formal-security-capability.properties" not in gradle
    assert capability == "formalSecureDataPlaneImplemented=false\n"
    assert "visionforgeFormalSecureDataPlaneOnly" in loader
    assert "tasks.register('verifyFormalSecureDataPlaneImplemented')" in loader
    assert "Formal secure data plane is not implemented; refusing release APK" in loader
    assert "def formalReleaseArtifactTaskNames = ['packageRelease', 'bundleRelease']" in loader
    assert "if (task.name in formalReleaseArtifactTaskNames)" in loader
    assert "task.dependsOn(tasks.named('verifyFormalSecureDataPlaneImplemented'))" in loader
    assert "probeFormalSecurityReleaseGraphContract" in loader
