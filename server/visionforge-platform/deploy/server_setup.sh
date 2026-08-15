#!/bin/bash
set -Eeuo pipefail
umask 077

readonly PROJECT_ROOT="/home/ubuntu/vf-platform"
readonly EXPECTED_DEPLOY_USER="ubuntu"
readonly RUNTIME_GROUP="visionforge-runtime"
readonly NGINX_USER="www-data"
readonly OPTIONAL_SIDECAR_USER="vf-dual-machine"
readonly SYSTEMD_UNIT_DIR="/etc/systemd/system"
readonly RETENTION_SERVICE_UNIT="vf-log-retention.service"
readonly RETENTION_TIMER_UNIT="vf-log-retention.timer"
readonly RETENTION_SERVICE_SOURCE="${PROJECT_ROOT}/deploy/${RETENTION_SERVICE_UNIT}"
readonly RETENTION_TIMER_SOURCE="${PROJECT_ROOT}/deploy/${RETENTION_TIMER_UNIT}"
readonly RETENTION_RUNNER_SOURCE="${PROJECT_ROOT}/deploy/purge_log_storage.py"
readonly RETENTION_SERVICE_TARGET="${SYSTEMD_UNIT_DIR}/${RETENTION_SERVICE_UNIT}"
readonly RETENTION_TIMER_TARGET="${SYSTEMD_UNIT_DIR}/${RETENTION_TIMER_UNIT}"
readonly STATIC_IMG_DIR="${PROJECT_ROOT}/app/static/img"

declare -a PRIVILEGE_PREFIX=()
DEPLOY_USER=""
DEPLOY_PRIMARY_GROUP=""
SHARED_READ_PROBE=""
RETENTION_BACKUP_DIR=""
RETENTION_SERVICE_EXISTED=0
RETENTION_TIMER_EXISTED=0
RETENTION_TIMER_ENABLEMENT_STATE=""
RETENTION_TIMER_ACTIVE_STATE=""
RETENTION_TRANSACTION_ACTIVE=0

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

require_file() {
    [[ -f "$1" ]] || fail "Required file is missing: $1"
}

require_directory() {
    [[ -d "$1" ]] || fail "Required directory is missing: $1"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"
}

configure_privilege_context() {
    if [[ "${EUID}" -ne 0 ]]; then
        require_command sudo
        PRIVILEGE_PREFIX=(sudo)
    fi
}

run_privileged() {
    "${PRIVILEGE_PREFIX[@]}" "$@"
}

run_as_user() {
    local target_user="$1"
    shift

    if [[ "$(id -un)" == "${target_user}" ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -u "${target_user}" -- "$@"
    elif [[ "${EUID}" -eq 0 ]] && command -v runuser >/dev/null 2>&1; then
        runuser -u "${target_user}" -- "$@"
    else
        fail "Cannot execute a command as ${target_user}"
    fi
}

resolve_deploy_user() {
    # 生产 unit 与 env 所有者契约均固定为 ubuntu。禁止提供只影响部分
    # 步骤的伪 override，否则 timer 可能静默指向另一套应用目录。
    DEPLOY_USER="${EXPECTED_DEPLOY_USER}"
    id "${DEPLOY_USER}" >/dev/null 2>&1 \
        || fail "Deployment user does not exist: ${DEPLOY_USER}"
    [[ "${DEPLOY_USER}" != "${NGINX_USER}" ]] \
        || fail "The deployment user must not be the Nginx worker user"
    DEPLOY_PRIMARY_GROUP="$(id -gn "${DEPLOY_USER}")"
}

user_has_group() {
    local target_user="$1"
    local target_group="$2"
    local user_groups

    user_groups="$(id -nG "${target_user}")"
    [[ " ${user_groups} " == *" ${target_group} "* ]]
}

ensure_runtime_group() {
    if ! getent group "${RUNTIME_GROUP}" >/dev/null; then
        run_privileged groupadd --system "${RUNTIME_GROUP}"
    fi
    getent group "${RUNTIME_GROUP}" >/dev/null \
        || fail "Runtime group is unavailable after creation: ${RUNTIME_GROUP}"

    ensure_user_runtime_group "${NGINX_USER}"
    if id "${OPTIONAL_SIDECAR_USER}" >/dev/null 2>&1; then
        ensure_user_runtime_group "${OPTIONAL_SIDECAR_USER}"
    fi
}

ensure_user_runtime_group() {
    local target_user="$1"

    if ! user_has_group "${target_user}" "${RUNTIME_GROUP}"; then
        run_privileged usermod --append --groups "${RUNTIME_GROUP}" "${target_user}"
    fi
    user_has_group "${target_user}" "${RUNTIME_GROUP}" \
        || fail "${target_user} was not added to ${RUNTIME_GROUP}"
}

refresh_nginx_group_membership() {
    if run_privileged systemctl is-active --quiet nginx; then
        # Fresh/recovery deploy P1：重建 worker，使其重新加载 supplementary groups。
        run_privileged systemctl try-reload-or-restart nginx
        run_privileged systemctl is-active --quiet nginx \
            || fail "Nginx is not active after refreshing supplementary groups"
    fi
}

configure_project_directories() {
    run_privileged install -d \
        -o "${DEPLOY_USER}" -g "${RUNTIME_GROUP}" -m 0750 \
        "${PROJECT_ROOT}" "${PROJECT_ROOT}/app" "${PROJECT_ROOT}/app/static"
    run_privileged install -d \
        -o "${DEPLOY_USER}" -g "${RUNTIME_GROUP}" -m 2750 \
        "${STATIC_IMG_DIR}"

    run_privileged install -d \
        -o "${DEPLOY_USER}" -g "${DEPLOY_PRIMARY_GROUP}" -m 0700 \
        "${PROJECT_ROOT}/owner_keys" \
        "${PROJECT_ROOT}/log_storage" \
        "${PROJECT_ROOT}/data"
}

cleanup_shared_read_probe() {
    if [[ -z "${SHARED_READ_PROBE}" ]]; then
        return 0
    fi
    case "${SHARED_READ_PROBE}" in
        "${STATIC_IMG_DIR}"/.visionforge-runtime-read-probe.*)
            run_privileged rm -f -- "${SHARED_READ_PROBE}"
            SHARED_READ_PROBE=""
            ;;
        *)
            echo "Refusing to remove unexpected probe path: ${SHARED_READ_PROBE}" >&2
            return 1
            ;;
    esac
}

verify_runtime_group_access() {
    SHARED_READ_PROBE="$(
        run_privileged mktemp \
            "${STATIC_IMG_DIR}/.visionforge-runtime-read-probe.XXXXXX"
    )"
    run_privileged chown "${DEPLOY_USER}:${RUNTIME_GROUP}" "${SHARED_READ_PROBE}"
    run_privileged chmod 0640 "${SHARED_READ_PROBE}"

    run_as_user "${NGINX_USER}" test -r "${SHARED_READ_PROBE}" \
        || fail "${NGINX_USER} cannot read a 0640 ${RUNTIME_GROUP} probe"
    if run_as_user "${NGINX_USER}" test -w "${STATIC_IMG_DIR}"; then
        fail "${NGINX_USER} unexpectedly has write access to ${STATIC_IMG_DIR}"
    fi
    cleanup_shared_read_probe
}

backup_existing_unit() {
    local unit_target="$1"
    local backup_target="$2"

    if run_privileged test -e "${unit_target}" \
        || run_privileged test -L "${unit_target}"; then
        run_privileged cp -a -- "${unit_target}" "${backup_target}"
        return 0
    fi
    return 1
}

prepare_retention_transaction() {
    RETENTION_BACKUP_DIR="$(
        run_privileged mktemp -d \
            /var/tmp/visionforge-retention-units.XXXXXX
    )"
    run_privileged chmod 0700 "${RETENTION_BACKUP_DIR}"

    if backup_existing_unit \
        "${RETENTION_SERVICE_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_SERVICE_UNIT}"; then
        RETENTION_SERVICE_EXISTED=1
    fi
    if backup_existing_unit \
        "${RETENTION_TIMER_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_TIMER_UNIT}"; then
        RETENTION_TIMER_EXISTED=1
    fi
    RETENTION_TIMER_ENABLEMENT_STATE="$(
        run_privileged systemctl is-enabled "${RETENTION_TIMER_UNIT}" \
            2>/dev/null || true
    )"
    [[ -n "${RETENTION_TIMER_ENABLEMENT_STATE}" ]] \
        || fail "Cannot capture ${RETENTION_TIMER_UNIT} enablement state"
    RETENTION_TIMER_ACTIVE_STATE="$(
        run_privileged systemctl is-active "${RETENTION_TIMER_UNIT}" \
            2>/dev/null || true
    )"
    [[ -n "${RETENTION_TIMER_ACTIVE_STATE}" ]] \
        || fail "Cannot capture ${RETENTION_TIMER_UNIT} active state"

    RETENTION_TRANSACTION_ACTIVE=1
}

install_retention_unit() {
    local unit_source="$1"
    local unit_target="$2"

    # Fresh/recovery deploy P1：先移除 mask/symlink，禁止 install 跟随旧链接。
    run_privileged rm -f -- "${unit_target}"
    run_privileged install -o root -g root -m 0644 \
        "${unit_source}" "${unit_target}"
}

unit_target_matches_backup() {
    local unit_target="$1"
    local backup_target="$2"
    local unit_existed="$3"
    local backup_link
    local restored_link

    if [[ "${unit_existed}" -eq 0 ]]; then
        ! run_privileged test -e "${unit_target}" \
            && ! run_privileged test -L "${unit_target}"
        return
    fi
    if run_privileged test -L "${backup_target}"; then
        run_privileged test -L "${unit_target}" || return 1
        backup_link="$(run_privileged readlink -- "${backup_target}")"
        restored_link="$(run_privileged readlink -- "${unit_target}")"
        [[ "${backup_link}" == "${restored_link}" ]]
        return
    fi
    run_privileged cmp -s -- "${backup_target}" "${unit_target}"
}

restore_unit_target() {
    local unit_target="$1"
    local backup_target="$2"
    local unit_existed="$3"

    run_privileged rm -f -- "${unit_target}" || return 1
    if [[ "${unit_existed}" -eq 1 ]]; then
        run_privileged cp -a -- "${backup_target}" "${unit_target}" || return 1
    fi
}

rollback_retention_units() {
    local rollback_failed=0

    run_privileged systemctl disable --now "${RETENTION_TIMER_UNIT}" \
        >/dev/null 2>&1 || true
    restore_unit_target \
        "${RETENTION_SERVICE_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_SERVICE_UNIT}" \
        "${RETENTION_SERVICE_EXISTED}" || rollback_failed=1
    restore_unit_target \
        "${RETENTION_TIMER_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_TIMER_UNIT}" \
        "${RETENTION_TIMER_EXISTED}" || rollback_failed=1
    run_privileged systemctl daemon-reload || rollback_failed=1

    case "${RETENTION_TIMER_ENABLEMENT_STATE}" in
        enabled)
            run_privileged systemctl enable "${RETENTION_TIMER_UNIT}" \
                >/dev/null || rollback_failed=1
            ;;
        enabled-runtime)
            run_privileged systemctl enable --runtime "${RETENTION_TIMER_UNIT}" \
                >/dev/null || rollback_failed=1
            ;;
    esac
    if [[ "${RETENTION_TIMER_ACTIVE_STATE}" == "active" ]]; then
        run_privileged systemctl start "${RETENTION_TIMER_UNIT}" \
            || rollback_failed=1
    fi

    unit_target_matches_backup \
        "${RETENTION_SERVICE_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_SERVICE_UNIT}" \
        "${RETENTION_SERVICE_EXISTED}" || rollback_failed=1
    unit_target_matches_backup \
        "${RETENTION_TIMER_TARGET}" \
        "${RETENTION_BACKUP_DIR}/${RETENTION_TIMER_UNIT}" \
        "${RETENTION_TIMER_EXISTED}" || rollback_failed=1
    if [[ "$(
        run_privileged systemctl is-enabled "${RETENTION_TIMER_UNIT}" \
            2>/dev/null || true
    )" != "${RETENTION_TIMER_ENABLEMENT_STATE}" ]]; then
        rollback_failed=1
    fi
    if [[ "$(
        run_privileged systemctl is-active "${RETENTION_TIMER_UNIT}" \
            2>/dev/null || true
    )" != "${RETENTION_TIMER_ACTIVE_STATE}" ]]; then
        rollback_failed=1
    fi

    [[ "${rollback_failed}" -eq 0 ]]
}

cleanup_retention_backup() {
    if [[ -z "${RETENTION_BACKUP_DIR}" ]]; then
        return 0
    fi
    case "${RETENTION_BACKUP_DIR}" in
        /var/tmp/visionforge-retention-units.*)
            run_privileged rm -f -- \
                "${RETENTION_BACKUP_DIR}/${RETENTION_SERVICE_UNIT}" \
                "${RETENTION_BACKUP_DIR}/${RETENTION_TIMER_UNIT}"
            run_privileged rmdir -- "${RETENTION_BACKUP_DIR}"
            RETENTION_BACKUP_DIR=""
            ;;
        *)
            echo "Refusing to remove unexpected backup path: ${RETENTION_BACKUP_DIR}" >&2
            return 1
            ;;
    esac
}

handle_exit() {
    local exit_code=$?
    local cleanup_failed=0

    trap - EXIT
    set +e
    cleanup_shared_read_probe || cleanup_failed=1
    if [[ "${RETENTION_TRANSACTION_ACTIVE}" -eq 1 ]]; then
        echo "Retention unit deployment failed; restoring the previous units and timer state." >&2
        if rollback_retention_units; then
            echo "retention_units_rollback=verified" >&2
        else
            echo "retention_units_rollback=failed" >&2
            exit_code=2
        fi
    fi
    cleanup_retention_backup || cleanup_failed=1
    if [[ "${cleanup_failed}" -eq 1 && "${exit_code}" -eq 0 ]]; then
        exit_code=2
    fi
    exit "${exit_code}"
}

deploy_retention_units() {
    local next_elapse

    prepare_retention_transaction
    install_retention_unit "${RETENTION_SERVICE_SOURCE}" "${RETENTION_SERVICE_TARGET}"
    install_retention_unit "${RETENTION_TIMER_SOURCE}" "${RETENTION_TIMER_TARGET}"
    run_privileged systemd-analyze verify \
        "${RETENTION_SERVICE_TARGET}" "${RETENTION_TIMER_TARGET}"
    run_privileged systemctl daemon-reload
    run_privileged systemctl enable --now "${RETENTION_TIMER_UNIT}"
    run_privileged systemctl is-enabled --quiet "${RETENTION_TIMER_UNIT}" \
        || fail "${RETENTION_TIMER_UNIT} is not enabled"
    run_privileged systemctl is-active --quiet "${RETENTION_TIMER_UNIT}" \
        || fail "${RETENTION_TIMER_UNIT} is not active"
    next_elapse="$(
        run_privileged systemctl show \
            --property=NextElapseUSecRealtime \
            --value "${RETENTION_TIMER_UNIT}"
    )"
    case "${next_elapse,,}" in
        "" | 0 | n/a | never)
            fail "${RETENTION_TIMER_UNIT} has no next elapse"
            ;;
    esac

    RETENTION_TRANSACTION_ACTIVE=0
    if ! cleanup_retention_backup; then
        echo "WARNING: retention unit backup cleanup requires manual attention" >&2
    fi
    echo "Retention timer next elapse: ${next_elapse}"
}

smoke_test_retention_entrypoint() {
    # 专用 smoke 模式只读检查入口、依赖和既有 schema；不运行迁移或扫描候选。
    run_as_user "${DEPLOY_USER}" \
        "${PROJECT_ROOT}/venv/bin/python" \
        "${RETENTION_RUNNER_SOURCE}" \
        --smoke-check
}

trap handle_exit EXIT

configure_privilege_context
resolve_deploy_user
require_command getent
require_command id
require_command install
require_command mktemp
require_command systemctl
require_command systemd-analyze
require_directory "${PROJECT_ROOT}"
require_directory "${PROJECT_ROOT}/app"
require_directory "${PROJECT_ROOT}/app/static"
require_file "${PROJECT_ROOT}/requirements.txt"
require_file "${PROJECT_ROOT}/venv/bin/pip"
require_file "${PROJECT_ROOT}/venv/bin/python"
require_file "${PROJECT_ROOT}/deploy/create_single_server_env.py"
require_file "${PROJECT_ROOT}/deploy/validate_single_server_env.py"
require_file "${RETENTION_RUNNER_SOURCE}"
require_file "${RETENTION_SERVICE_SOURCE}"
require_file "${RETENTION_TIMER_SOURCE}"
id "${NGINX_USER}" >/dev/null 2>&1 \
    || fail "Nginx worker user does not exist: ${NGINX_USER}"

ensure_runtime_group
configure_project_directories
refresh_nginx_group_membership
verify_runtime_group_access
cd "${PROJECT_ROOT}"

echo "=== Install Python deps ==="
run_as_user "${DEPLOY_USER}" venv/bin/pip install -r requirements.txt -q
echo "PIP OK"

echo "=== Configure .env ==="
if [[ -e .env || -L .env ]]; then
    run_as_user "${DEPLOY_USER}" \
        venv/bin/python deploy/validate_single_server_env.py .env
    echo "Existing .env preserved"
else
    run_as_user "${DEPLOY_USER}" \
        venv/bin/python deploy/create_single_server_env.py .env
    run_as_user "${DEPLOY_USER}" \
        venv/bin/python deploy/validate_single_server_env.py .env
    echo "New .env created atomically with exclusive no-follow semantics"
fi

echo "=== Init RSA keys ==="
if [[ -e owner_keys/license_private_key.pem.enc \
    || -L owner_keys/license_private_key.pem.enc ]]; then
    run_as_user "${DEPLOY_USER}" venv/bin/python -c \
        "from app.services.license_service import load_private_key; load_private_key()"
    echo "Existing encrypted RSA key validated and preserved"
else
    run_as_user "${DEPLOY_USER}" venv/bin/python -c \
        "from app.services.license_service import init_platform_keys; init_platform_keys()"
fi
echo "KEYS OK"

echo "=== Verify app ==="
run_as_user "${DEPLOY_USER}" venv/bin/python -c \
    "from app.main import app; print(len(app.routes), 'routes loaded')"
echo "APP OK"

echo "=== Install log retention timer ==="
smoke_test_retention_entrypoint
deploy_retention_units
echo "RETENTION TIMER OK"

echo "=== Start app (test) ==="
run_as_user "${DEPLOY_USER}" venv/bin/python -c "
import uvicorn, sys
sys.path.insert(0, '.')
from app.main import app
print('App is ready to serve')
"
echo "ALL DONE"
