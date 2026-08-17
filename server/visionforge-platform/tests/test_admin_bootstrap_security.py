from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import sqlite3
import stat

import pytest


ROOT = Path(__file__).resolve().parents[1]
CREATE_ADMIN = ROOT / "deploy" / "create_admin.py"
FIX_ADMIN = ROOT / "deploy" / "fix_admin.py"


def _load_create_admin():
    spec = importlib.util.spec_from_file_location("visionforge_create_admin", CREATE_ADMIN)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_admin_bootstrap_never_prints_plaintext_password() -> None:
    source = CREATE_ADMIN.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", "")
        if name != "print":
            continue
        rendered = ast.unparse(node).lower()
        assert "password}" not in rendered
        assert "{password" not in rendered
    assert "getpass.getpass" in source
    assert "permissions must be 0600" in source
    assert "must be stored outside the repository" in source


def test_remote_password_ssh_admin_helper_is_disabled() -> None:
    source = FIX_ADMIN.read_text(encoding="utf-8")
    forbidden = [
        "paramiko",
        "AutoAddPolicy",
        "VISIONFORGE_SSH_PASSWORD",
        "password=",
        "exec_command",
    ]
    for token in forbidden:
        assert token not in source
    assert "REMOTE_ADMIN_REPAIR=DISABLED" in source
    assert "strict key-authenticated SSH" in source


def test_admin_bootstrap_preserves_row_identity_and_revokes_sessions() -> None:
    module = _load_create_admin()
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            auth_version INTEGER NOT NULL DEFAULT 0,
            login_device_code TEXT NOT NULL DEFAULT '',
            login_instance_id TEXT NOT NULL DEFAULT '',
            login_started_at TEXT,
            runtime_blocked_until_epoch INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            ban_reason TEXT NOT NULL DEFAULT '',
            deleted_at TEXT,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE time_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            ended_at TEXT,
            ended_reason TEXT NOT NULL DEFAULT '',
            revoked_at TEXT
        );
        INSERT INTO users (
            username, email, password_hash, is_admin, auth_version,
            login_device_code, login_instance_id, runtime_blocked_until_epoch,
            status, ban_reason, deleted_at
        ) VALUES (
            'superadmin', 'old@example.test', 'old-hash', 0, 4,
            'device', 'instance', 9999999999, 'banned', 'reason', datetime('now')
        );
        INSERT INTO time_sessions(user_id, status) VALUES (1, 'active');
        """
    )

    admin_id = module._upsert_admin(
        connection,
        username="superadmin",
        email="new@example.test",
        password_hash="new-hash",
    )
    row = connection.execute(
        "SELECT id, email, password_hash, is_admin, auth_version, status, "
        "ban_reason, deleted_at, login_device_code, login_instance_id, "
        "runtime_blocked_until_epoch FROM users WHERE username = 'superadmin'"
    ).fetchone()
    session = connection.execute(
        "SELECT status, ended_reason, revoked_at FROM time_sessions WHERE id = 1"
    ).fetchone()

    assert admin_id == 1
    assert row == (
        1,
        "new@example.test",
        "new-hash",
        1,
        5,
        "active",
        "",
        None,
        "",
        "",
        0,
    )
    assert session[0] == "ended"
    assert session[1] == "admin_credential_rotation"
    assert session[2] is not None


def test_generated_password_file_is_private_and_outside_repository(
    tmp_path: Path,
) -> None:
    module = _load_create_admin()
    target = tmp_path / "bootstrap-password.txt"
    written = module._write_generated_password(
        target, "A-secure-bootstrap-password-123"
    )
    metadata = written.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert (
        written.read_text(encoding="utf-8").strip()
        == "A-secure-bootstrap-password-123"
    )


def test_password_file_inside_repository_is_rejected() -> None:
    module = _load_create_admin()
    with pytest.raises(module.AdminBootstrapError, match="outside the repository"):
        module._outside_repository(ROOT / "password.txt")
