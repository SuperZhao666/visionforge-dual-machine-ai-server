#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly CONFIG_SOURCE="${1:-}"
readonly MANAGED_CONFIG="/etc/default/apport"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-apport-$(date -u +%Y%m%dT%H%M%SZ)"
readonly APPORT_UNITS=(
    apport.service
    apport-autoreport.path
    apport-autoreport.timer
    apport-forward.socket
)

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ -z "$CONFIG_SOURCE" || ! -f "$CONFIG_SOURCE" ]]; then
        printf 'error=missing-apport-config\n' >&2
        exit 1
    fi
    grep -Fx 'enabled=0' "$CONFIG_SOURCE" >/dev/null
}

backup_current_state() {
    local unit
    local state_name

    install -d -m 700 -o root -g root "$BACKUP_DIR"
    cp -a "$MANAGED_CONFIG" "$BACKUP_DIR/apport.before"
    for unit in "${APPORT_UNITS[@]}"; do
        state_name="${unit//[^A-Za-z0-9_.-]/_}"
        systemctl is-active "$unit" >"$BACKUP_DIR/${state_name}.active" 2>/dev/null || true
        systemctl is-enabled "$unit" >"$BACKUP_DIR/${state_name}.enabled" 2>/dev/null || true
    done
    sysctl -n fs.suid_dumpable >"$BACKUP_DIR/suid-dumpable.before"
}

restore_state() {
    local unit
    local state_name

    trap - ERR
    cp -a "$BACKUP_DIR/apport.before" "$MANAGED_CONFIG"
    for unit in "${APPORT_UNITS[@]}"; do
        state_name="${unit//[^A-Za-z0-9_.-]/_}"
        if grep -E '^(enabled|generated)$' "$BACKUP_DIR/${state_name}.enabled" >/dev/null 2>&1; then
            systemctl enable "$unit" >/dev/null 2>&1 || true
        fi
        if grep -Fx 'active' "$BACKUP_DIR/${state_name}.active" >/dev/null 2>&1; then
            systemctl start "$unit" >/dev/null 2>&1 || true
        fi
    done
    sysctl -w "fs.suid_dumpable=$(<"$BACKUP_DIR/suid-dumpable.before")" \
        >/dev/null 2>&1 || true
}

apply_and_validate() {
    local unit

    install -m 644 -o root -g root "$CONFIG_SOURCE" "$MANAGED_CONFIG"
    systemctl disable "${APPORT_UNITS[@]}"
    systemctl stop "${APPORT_UNITS[@]}"
    sysctl -w fs.suid_dumpable=0 >/dev/null
    for unit in "${APPORT_UNITS[@]}"; do
        ! systemctl is-active --quiet "$unit"
        ! systemctl is-enabled --quiet "$unit"
    done
    [[ "$(sysctl -n fs.suid_dumpable)" == "0" ]]
}

main() {
    require_inputs
    backup_current_state
    trap restore_state ERR
    apply_and_validate
    trap - ERR
    printf 'apport=disabled\n'
    printf 'fs.suid_dumpable=0\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
