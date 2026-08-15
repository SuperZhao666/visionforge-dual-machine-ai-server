#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly MANAGED_CONFIG="/etc/sysctl.d/99-visionforge-security.conf"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-sysctl-$(date -u +%Y%m%dT%H%M%SZ)"
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
    sysctl -a >"${BACKUP_DIR}/sysctl.before" 2>/dev/null
    if [[ -e "$MANAGED_CONFIG" ]]; then
        cp -a "$MANAGED_CONFIG" "${BACKUP_DIR}/managed-config"
        printf 'present\n' >"${BACKUP_DIR}/managed-config.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/managed-config.state"
    fi
}

restore_configuration() {
    if grep -qx 'present' "${BACKUP_DIR}/managed-config.state"; then
        cp -a "${BACKUP_DIR}/managed-config" "$MANAGED_CONFIG"
    else
        rm -f "$MANAGED_CONFIG"
    fi
    sysctl --system >/dev/null 2>&1 || true
}

validate_values() {
    local key expected actual
    while IFS='=' read -r key expected; do
        key="${key//[[:space:]]/}"
        expected="${expected//[[:space:]]/}"
        [[ -z "$key" || "$key" == \#* ]] && continue
        actual="$(sysctl -n "$key")"
        if [[ "$actual" != "$expected" ]]; then
            printf 'error=sysctl-mismatch key=%s expected=%s actual=%s\n' \
                "$key" "$expected" "$actual" >&2
            return 1
        fi
    done <"$MANAGED_CONFIG"
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    install -m 644 -o root -g root "$CONFIG_SOURCE" "$MANAGED_CONFIG"
    sysctl --system >"${BACKUP_DIR}/sysctl-apply.log"
    validate_values
    trap - ERR
    printf 'sysctl_hardening=applied\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
