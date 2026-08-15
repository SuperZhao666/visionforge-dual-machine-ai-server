from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-license-key-file-security")

from app.config import config
from app.services import license_service


@pytest.fixture(autouse=True)
def isolated_key_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    key_path = tmp_path / "owner_keys" / "license_private_key.pem"
    key_path.parent.mkdir()
    monkeypatch.setattr(config, "PRIVATE_KEY_PATH", str(key_path))
    monkeypatch.setattr(config, "PRIVATE_KEY_PASSWORD", "test-password")
    monkeypatch.setattr(license_service, "_cached_private_key", None)
    monkeypatch.setattr(license_service, "_cached_public_key", None)
    yield key_path.with_suffix(".pem.enc")
    license_service._cached_private_key = None
    license_service._cached_public_key = None


def test_init_creates_secure_file_and_refuses_to_overwrite(isolated_key_file: Path):
    license_service.init_platform_keys()
    original = isolated_key_file.read_bytes()

    with pytest.raises(FileExistsError, match="will not be overwritten"):
        license_service.init_platform_keys()

    assert isolated_key_file.read_bytes() == original
    if os.name != "nt":
        assert stat.S_IMODE(isolated_key_file.stat().st_mode) == 0o600


def test_load_rejects_symlink(isolated_key_file: Path, tmp_path: Path):
    target = tmp_path / "other.enc"
    target.write_bytes(b"VFP1")
    try:
        isolated_key_file.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="must not be a symlink"):
        license_service.load_private_key()


def test_load_rejects_hardlinked_or_oversized_file(isolated_key_file: Path, tmp_path: Path):
    license_service.init_platform_keys()
    linked = tmp_path / "linked.enc"
    try:
        os.link(isolated_key_file, linked)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(ValueError, match="multiple hard links"):
        license_service.load_private_key()


def test_load_rejects_group_or_other_readable_key_file(isolated_key_file: Path):
    if os.name == "nt":
        pytest.skip("POSIX mode policy is not applicable on Windows")
    license_service.init_platform_keys()
    isolated_key_file.chmod(0o640)

    with pytest.raises(PermissionError, match="permissions are too broad"):
        license_service.load_private_key()


def test_load_rejects_file_owned_by_another_account(isolated_key_file: Path, monkeypatch: pytest.MonkeyPatch):
    if os.name == "nt":
        pytest.skip("POSIX ownership policy is not applicable on Windows")
    license_service.init_platform_keys()
    monkeypatch.setattr(license_service.os, "geteuid", lambda: os.stat(isolated_key_file).st_uid + 1)

    with pytest.raises(PermissionError, match="owner is invalid"):
        license_service.load_private_key()


def test_load_rejects_file_larger_than_key_limit(isolated_key_file: Path):
    isolated_key_file.write_bytes(b"VFP1" + b"x" * license_service._MAX_ENCRYPTED_KEY_FILE_BYTES)
    if os.name != "nt":
        isolated_key_file.chmod(0o600)

    with pytest.raises(ValueError, match="too large"):
        license_service.load_private_key()
