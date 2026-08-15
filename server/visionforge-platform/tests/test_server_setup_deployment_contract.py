from __future__ import annotations

import os
import re
from pathlib import Path


os.environ.setdefault("SECRET_KEY", "test-secret-key-for-server-setup-contract")


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SETUP_PATH = PROJECT_ROOT / "deploy" / "server_setup.sh"
SERVICE_PATH = PROJECT_ROOT / "deploy" / "vf-log-retention.service"
TIMER_PATH = PROJECT_ROOT / "deploy" / "vf-log-retention.timer"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _function_source(script: str, function_name: str) -> str:
    match = re.search(
        rf"^{re.escape(function_name)}\(\) \{{\n(.*?)^\}}$",
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"missing shell function: {function_name}"
    return match.group(1)


def test_server_setup_fails_fast_and_explicitly_restricts_sensitive_dirs() -> None:
    setup = _read(SETUP_PATH)
    first_lines = setup.splitlines()[:4]

    assert first_lines == ["#!/bin/bash", "set -Eeuo pipefail", "umask 077", ""]
    assert 'readonly PROJECT_ROOT="/home/ubuntu/vf-platform"' in setup
    assert 'readonly EXPECTED_DEPLOY_USER="ubuntu"' in setup
    assert "VF_PROJECT_ROOT" not in setup
    assert "VF_APP_ROOT" not in setup
    assert "VF_DEPLOY_USER" not in setup
    assert "mkdir -p owner_keys log_storage data" not in setup

    directory_setup = _function_source(setup, "configure_project_directories")
    sensitive_install = re.search(
        r"install -d \\\n"
        r"\s+-o \"\$\{DEPLOY_USER\}\" -g \"\$\{DEPLOY_PRIMARY_GROUP\}\" "
        r"-m 0700 \\\n"
        r"\s+\"\$\{PROJECT_ROOT\}/owner_keys\" \\\n"
        r"\s+\"\$\{PROJECT_ROOT\}/log_storage\" \\\n"
        r"\s+\"\$\{PROJECT_ROOT\}/data\"",
        directory_setup,
    )
    assert sensitive_install is not None

    assert 'DEPLOY_USER="${EXPECTED_DEPLOY_USER}"' in setup
    assert 'run_as_user "${DEPLOY_USER}"' in setup


def test_server_setup_builds_read_only_nginx_shared_group_contract() -> None:
    setup = _read(SETUP_PATH)
    group_setup = _function_source(setup, "ensure_runtime_group")
    group_member_setup = _function_source(setup, "ensure_user_runtime_group")
    directory_setup = _function_source(setup, "configure_project_directories")
    nginx_refresh = _function_source(setup, "refresh_nginx_group_membership")
    probe = _function_source(setup, "verify_runtime_group_access")

    assert 'readonly RUNTIME_GROUP="visionforge-runtime"' in setup
    assert 'readonly NGINX_USER="www-data"' in setup
    assert 'readonly OPTIONAL_SIDECAR_USER="vf-dual-machine"' in setup
    assert 'getent group "${RUNTIME_GROUP}"' in group_setup
    assert 'groupadd --system "${RUNTIME_GROUP}"' in group_setup
    assert (
        'usermod --append --groups "${RUNTIME_GROUP}" "${target_user}"'
        in group_member_setup
    )
    assert 'ensure_user_runtime_group "${NGINX_USER}"' in group_setup
    assert 'id "${OPTIONAL_SIDECAR_USER}"' in group_setup
    assert 'ensure_user_runtime_group "${OPTIONAL_SIDECAR_USER}"' in group_setup

    assert "systemctl is-active --quiet nginx" in nginx_refresh
    assert "systemctl try-reload-or-restart nginx" in nginx_refresh
    assert setup.rindex("refresh_nginx_group_membership") < setup.rindex(
        "verify_runtime_group_access"
    )

    assert '-g "${RUNTIME_GROUP}" -m 0750' in directory_setup
    assert (
        '"${PROJECT_ROOT}" "${PROJECT_ROOT}/app" "${PROJECT_ROOT}/app/static"'
        in directory_setup
    )
    assert '-g "${RUNTIME_GROUP}" -m 2750' in directory_setup
    assert '"${STATIC_IMG_DIR}"' in directory_setup

    assert ".visionforge-runtime-read-probe.XXXXXX" in probe
    assert 'chmod 0640 "${SHARED_READ_PROBE}"' in probe
    assert 'run_as_user "${NGINX_USER}" test -r "${SHARED_READ_PROBE}"' in probe
    assert 'run_as_user "${NGINX_USER}" test -w "${STATIC_IMG_DIR}"' in probe
    assert "cleanup_shared_read_probe" in probe
    assert "-m 2770" not in directory_setup
    assert "-m 0770" not in directory_setup


def test_server_setup_installs_and_verifies_retention_timer_transactionally() -> None:
    setup = _read(SETUP_PATH)
    deploy = _function_source(setup, "deploy_retention_units")
    smoke_test = _function_source(setup, "smoke_test_retention_entrypoint")
    prepare = _function_source(setup, "prepare_retention_transaction")
    rollback = _function_source(setup, "rollback_retention_units")
    exit_handler = _function_source(setup, "handle_exit")

    assert "vf-log-retention.service" in setup
    assert "vf-log-retention.timer" in setup
    assert 'require_file "${RETENTION_RUNNER_SOURCE}"' in setup
    assert '"${RETENTION_RUNNER_SOURCE}"' in smoke_test
    assert "--smoke-check" in smoke_test
    assert "--dry-run" not in smoke_test
    assert "--batch-size" not in smoke_test
    assert setup.rindex("smoke_test_retention_entrypoint") < setup.rindex(
        "deploy_retention_units"
    )
    assert "backup_existing_unit" in prepare
    assert "RETENTION_SERVICE_EXISTED=1" in prepare
    assert "RETENTION_TIMER_EXISTED=1" in prepare
    assert "RETENTION_TIMER_ENABLEMENT_STATE" in prepare
    assert "RETENTION_TIMER_ACTIVE_STATE" in prepare

    expected_steps = [
        "prepare_retention_transaction",
        'install_retention_unit "${RETENTION_SERVICE_SOURCE}"',
        'install_retention_unit "${RETENTION_TIMER_SOURCE}"',
        "systemd-analyze verify",
        "systemctl daemon-reload",
        'systemctl enable --now "${RETENTION_TIMER_UNIT}"',
        'systemctl is-enabled --quiet "${RETENTION_TIMER_UNIT}"',
        'systemctl is-active --quiet "${RETENTION_TIMER_UNIT}"',
        "--property=NextElapseUSecRealtime",
    ]
    positions = [deploy.index(step) for step in expected_steps]
    assert positions == sorted(positions)
    assert "-m 0644" in _function_source(setup, "install_retention_unit")

    assert rollback.count("restore_unit_target") == 2
    assert "systemctl daemon-reload" in rollback
    assert 'systemctl enable "${RETENTION_TIMER_UNIT}"' in rollback
    assert 'systemctl enable --runtime "${RETENTION_TIMER_UNIT}"' in rollback
    assert 'systemctl start "${RETENTION_TIMER_UNIT}"' in rollback
    assert rollback.count("unit_target_matches_backup") == 2
    assert "rollback_retention_units" in exit_handler
    assert "retention_units_rollback=verified" in exit_handler
    assert "retention_units_rollback=failed" in exit_handler


def test_retention_units_expose_a_persistent_daily_oneshot_contract() -> None:
    service = _read(SERVICE_PATH)
    timer = _read(TIMER_PATH)

    assert "Type=oneshot" in service
    assert "User=ubuntu" in service
    assert "Group=ubuntu" in service
    assert "WorkingDirectory=/home/ubuntu/vf-platform" in service
    assert "UMask=0077" in service
    assert (
        "ExecStart=/home/ubuntu/vf-platform/venv/bin/python deploy/purge_log_storage.py"
        in service
    )
    assert "OnCalendar=daily" in timer
    assert "Persistent=true" in timer
    assert "Unit=vf-log-retention.service" in timer
    assert "WantedBy=timers.target" in timer
