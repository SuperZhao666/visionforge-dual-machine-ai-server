from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import create_android_release_keystore as creator  # noqa: E402
from tools import verify_android_production_signing_inputs as signing  # noqa: E402


def _env() -> dict[str, str]:
    return {
        signing.STORE_PASSWORD_ENV: "store-secret",
        signing.KEY_PASSWORD_ENV: "key-secret",
    }


def _fake_runner(
    command: Sequence[str],
    timeout: int,
    process_env: Mapping[str, str],
) -> creator.CommandResult:
    assert "store-secret" not in command
    assert "key-secret" not in command
    assert "-storepass:env" in command
    assert signing.STORE_PASSWORD_ENV in command
    assert process_env[signing.STORE_PASSWORD_ENV] == "store-secret"
    if "-genkeypair" in command:
        keystore_path = Path(command[command.index("-keystore") + 1])
        keystore_path.write_bytes(b"fake-keystore")
        return creator.CommandResult(returncode=0, stdout="generated", stderr="")
    return creator.CommandResult(
        returncode=0,
        stdout=(
            "Owner: CN=VisionForge Android Release, O=VisionForge, C=CN\n"
            "SHA256: 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:"
            "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00\n"
        ),
        stderr="",
    )


def test_android_release_keystore_generator_creates_safe_release_inputs(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    secure_dir = tmp_path / "secure"
    repo.mkdir()

    report = creator.create_android_release_keystore(
        output_dir=secure_dir,
        root=repo,
        env=_env(),
        runner=_fake_runner,
    )

    keystore = Path(report["keystore"]["path"])
    template = Path(report["env_template"])
    command_file = Path(report["next_command_file"])
    report_file = secure_dir / "android-release-keystore.json"

    assert keystore.read_bytes() == b"fake-keystore"
    assert signing.STORE_FILE_ENV in template.read_text(encoding="utf-8")
    assert signing.KEY_ALIAS_ENV in template.read_text(encoding="utf-8")
    assert "verify_android_production_signing_inputs.py" in command_file.read_text(
        encoding="utf-8",
    )

    serialized = json.dumps(report, ensure_ascii=False)
    all_generated_text = "\n".join(
        (
            serialized,
            report_file.read_text(encoding="utf-8"),
            template.read_text(encoding="utf-8"),
            command_file.read_text(encoding="utf-8"),
        )
    )
    assert "store-secret" not in all_generated_text
    assert "key-secret" not in all_generated_text


def test_android_release_keystore_generator_refuses_repository_output(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(ValueError, match="repository"):
        creator.create_android_release_keystore(
            output_dir=repo / "owner_secrets",
            root=repo,
            env=_env(),
            runner=_fake_runner,
        )


def test_android_release_keystore_generator_requires_password_env(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    with pytest.raises(ValueError, match=signing.STORE_PASSWORD_ENV):
        creator.create_android_release_keystore(
            output_dir=tmp_path / "secure",
            root=repo,
            env={},
            runner=_fake_runner,
        )


def test_android_release_keystore_generator_refuses_overwrite(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    secure_dir = tmp_path / "secure"
    repo.mkdir()
    creator.create_android_release_keystore(
        output_dir=secure_dir,
        root=repo,
        env=_env(),
        runner=_fake_runner,
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        creator.create_android_release_keystore(
            output_dir=secure_dir,
            root=repo,
            env=_env(),
            runner=_fake_runner,
        )


def test_android_release_keystore_generator_rejects_debug_certificate(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def debug_runner(
        command: Sequence[str],
        timeout: int,
        process_env: Mapping[str, str],
    ) -> creator.CommandResult:
        if "-genkeypair" in command:
            Path(command[command.index("-keystore") + 1]).write_bytes(b"fake-keystore")
            return creator.CommandResult(0, "", "")
        return creator.CommandResult(
            0,
            "Owner: C=US, O=Android, CN=Android Debug\n"
            f"SHA256: {signing.ANDROID_DEBUG_CERT_SHA256}\n",
            "",
        )

    with pytest.raises(RuntimeError, match="Android Debug"):
        creator.create_android_release_keystore(
            output_dir=tmp_path / "secure",
            root=repo,
            env=_env(),
            runner=debug_runner,
        )
