#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly APP_ROOT="${APP_ROOT:-/home/ubuntu/vf-platform}"
readonly APP_HEALTH_URL="${APP_HEALTH_URL:-http://127.0.0.1:8000/}"
readonly DB_PATH="${DB_PATH:-${APP_ROOT}/data/vf.db}"
readonly OWNER_KEYS="${APP_ROOT}/owner_keys"
readonly LOG_STORAGE="${APP_ROOT}/log_storage"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-permissions-$(date -u +%Y%m%dT%H%M%SZ)"

require_root() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    [[ -f "$DB_PATH" && -d "$OWNER_KEYS" && -d "$LOG_STORAGE" ]]
}

capture_modes() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    find "$DB_PATH" "$OWNER_KEYS" "$LOG_STORAGE" -xdev -printf '%m %p\n' \
        >"${BACKUP_DIR}/modes.before"
}

restore_modes() {
    local mode path
    while read -r mode path; do
        [[ -e "$path" ]] && chmod "$mode" "$path"
    done <"${BACKUP_DIR}/modes.before"
}

apply_modes() {
    chmod 600 "$DB_PATH"
    find "$OWNER_KEYS" "$LOG_STORAGE" -xdev -type d -exec chmod 700 {} +
    find "$OWNER_KEYS" "$LOG_STORAGE" -xdev -type f -exec chmod 600 {} +
}

validate_application() {
    local unexpected_directory unexpected_file
    [[ "$(stat -c '%a' "$DB_PATH")" == 600 ]]
    unexpected_directory="$(find "$OWNER_KEYS" "$LOG_STORAGE" -xdev -type d ! -perm 700 -print -quit)"
    unexpected_file="$(find "$OWNER_KEYS" "$LOG_STORAGE" -xdev -type f ! -perm 600 -print -quit)"
    [[ -z "$unexpected_directory" && -z "$unexpected_file" ]]
    curl --fail --silent --show-error --output /dev/null "$APP_HEALTH_URL"
}

main() {
    require_root
    capture_modes
    trap restore_modes ERR
    apply_modes
    validate_application
    trap - ERR
    printf 'application_permissions=hardened\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
