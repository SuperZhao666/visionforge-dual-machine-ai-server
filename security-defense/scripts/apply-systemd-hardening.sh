#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly APP_SERVICE="${APP_SERVICE:-vf.service}"
readonly APP_HEALTH_URL="${APP_HEALTH_URL:-http://127.0.0.1:8000/}"
readonly APP_OPENAPI_URL="${APP_OPENAPI_URL:-http://127.0.0.1:8000/openapi.json}"
readonly DROPIN_DIR="/etc/systemd/system/${APP_SERVICE}.d"
readonly DROPIN_FILE="${DROPIN_DIR}/security.conf"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-systemd-$(date -u +%Y%m%dT%H%M%SZ)"
readonly CONFIG_SOURCE="${1:-}"

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ -z "$CONFIG_SOURCE" || ! -f "$CONFIG_SOURCE" ]]; then
        printf 'error=missing-config-source\n' >&2
        exit 1
    fi
}

backup_current_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    if [[ -e "$DROPIN_FILE" ]]; then
        cp -a "$DROPIN_FILE" "${BACKUP_DIR}/security.conf"
        printf 'present\n' >"${BACKUP_DIR}/dropin.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/dropin.state"
    fi
}

restore_configuration() {
    if grep -qx 'present' "${BACKUP_DIR}/dropin.state"; then
        cp -a "${BACKUP_DIR}/security.conf" "$DROPIN_FILE"
    else
        rm -f "$DROPIN_FILE"
    fi
    systemctl daemon-reload
    systemctl restart "$APP_SERVICE" || true
}

validate_service() {
    systemd-analyze verify "/etc/systemd/system/${APP_SERVICE}"
    systemctl restart "$APP_SERVICE"
    systemctl is-active --quiet "$APP_SERVICE"
    wait_for_url "$APP_HEALTH_URL"
    wait_for_url "$APP_OPENAPI_URL"
}

wait_for_url() {
    local url="$1"
    local attempt
    for attempt in {1..50}; do
        if curl --fail --silent --show-error --max-time 1 --output /dev/null "$url"; then
            return 0
        fi
        sleep 0.2
    done
    printf 'error=service-health-timeout url=%s\n' "$url" >&2
    return 1
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    install -d -m 755 -o root -g root "$DROPIN_DIR"
    install -m 644 -o root -g root "$CONFIG_SOURCE" "$DROPIN_FILE"
    systemctl daemon-reload
    validate_service
    trap - ERR
    printf 'systemd_hardening=applied\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
    systemctl show "$APP_SERVICE" --property=MainPID,ActiveState,SubState
}

main "$@"
