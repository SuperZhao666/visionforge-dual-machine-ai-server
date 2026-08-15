from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from deploy.create_single_server_env import create_single_server_env
from deploy.validate_single_server_env import validate_single_server_env


def test_create_single_server_env_is_exclusive(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"

    create_single_server_env(env_path)

    assert validate_single_server_env(env_path) == ()
    assert not env_path.is_symlink()
    if os.name == "posix":
        assert stat.S_IMODE(env_path.stat().st_mode) == 0o600
    original_bytes = env_path.read_bytes()
    with pytest.raises(FileExistsError):
        create_single_server_env(env_path)
    assert env_path.read_bytes() == original_bytes


def test_create_single_server_env_does_not_follow_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.env"
    target.write_bytes(b"UNCHANGED")
    env_path = tmp_path / ".env"
    try:
        env_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(FileExistsError):
        create_single_server_env(env_path)

    assert target.read_bytes() == b"UNCHANGED"
