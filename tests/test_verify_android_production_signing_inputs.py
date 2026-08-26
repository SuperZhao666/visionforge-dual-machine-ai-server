from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_android_production_signing_inputs as signing  # noqa: E402


def _env(keystore: Path, **overrides: str) -> dict[str, str]:
    values = {
        signing.STORE_FILE_ENV: str(keystore),
        signing.STORE_PASSWORD_ENV: "store-password",
        signing.KEY_ALIAS_ENV: "release",
        signing.KEY_PASSWORD_ENV: "key-password",
    }
    values.update(overrides)
    return values


def test_production_signing_inputs_fail_when_material_is_missing(tmp_path: Path) -> None:
    calls: list[Sequence[str]] = []

    def fake_runner(command: Sequence[str], timeout: int) -> signing.CommandResult:
        calls.append(tuple(command))
        return signing.CommandResult(returncode=0, stdout="", stderr="")

    report = signing.verify_android_production_signing_inputs(
        env={},
        root=tmp_path,
        runner=fake_runner,
    )

    assert report["ok"] is False
    assert any(signing.STORE_FILE_ENV in error for error in report["errors"])
    assert calls == []


def test_production_signing_inputs_reject_development_signing_switch(tmp_path: Path) -> None:
    keystore = tmp_path / "offline" / "release.jks"
    keystore.parent.mkdir()
    keystore.write_bytes(b"keystore")

    report = signing.verify_android_production_signing_inputs(
        env=_env(
            keystore,
            **{signing.ALLOW_DEVELOPMENT_SIGNING_ENV: "true"},
        ),
        root=tmp_path / "repo",
        runner=lambda _command, _timeout: signing.CommandResult(0, "", ""),
    )

    assert report["ok"] is False
    assert any(signing.ALLOW_DEVELOPMENT_SIGNING_ENV in error for error in report["errors"])


def test_production_signing_inputs_reject_repository_keystore(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    keystore = repo / "release.jks"
    repo.mkdir()
    keystore.write_bytes(b"keystore")

    report = signing.verify_android_production_signing_inputs(
        env=_env(keystore),
        root=repo,
        runner=lambda _command, _timeout: signing.CommandResult(0, "", ""),
    )

    assert report["ok"] is False
    assert "outside the repository" in " ".join(report["errors"])


def test_production_signing_inputs_reject_android_debug_certificate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    keystore = tmp_path / "offline" / "release.jks"
    repo.mkdir()
    keystore.parent.mkdir()
    keystore.write_bytes(b"keystore")

    def fake_runner(command: Sequence[str], timeout: int) -> signing.CommandResult:
        assert "-J-Duser.language=en" in command
        assert "-storepass:env" in command
        assert "store-password" not in command
        assert str(keystore) in command
        return signing.CommandResult(
            returncode=0,
            stdout="\n".join(
                (
                    "Owner: C=US, O=Android, CN=Android Debug",
                    "SHA256: "
                    + ":".join(
                        signing.ANDROID_DEBUG_CERT_SHA256[index : index + 2].upper()
                        for index in range(0, 64, 2)
                    ),
                )
            ),
            stderr="",
        )

    report = signing.verify_android_production_signing_inputs(
        env=_env(keystore),
        root=repo,
        runner=fake_runner,
    )

    assert report["ok"] is False
    assert report["signing"]["android_debug_certificate"] is True


def test_production_signing_inputs_accept_non_debug_certificate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    keystore = tmp_path / "offline" / "release.jks"
    repo.mkdir()
    keystore.parent.mkdir()
    keystore.write_bytes(b"keystore")

    def fake_runner(command: Sequence[str], timeout: int) -> signing.CommandResult:
        return signing.CommandResult(
            returncode=0,
            stdout=(
                "Owner: CN=VisionForge Release, O=VisionForge\n"
                "SHA256: 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:"
                "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\n"
            ),
            stderr="",
        )

    report = signing.verify_android_production_signing_inputs(
        env=_env(keystore),
        root=repo,
        runner=fake_runner,
    )

    assert report["ok"] is True
    assert report["signing"]["certificate_owner"] == "CN=VisionForge Release, O=VisionForge"
