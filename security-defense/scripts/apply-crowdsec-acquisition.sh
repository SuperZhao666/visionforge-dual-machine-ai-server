#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly ACQUISITION_SOURCE="${1:-}"
readonly MANAGED_ACQUISITION="/etc/crowdsec/acquis.d/visionforge.yaml"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-crowdsec-acquisition-$(date -u +%Y%m%dT%H%M%SZ)"

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ -z "$ACQUISITION_SOURCE" || ! -f "$ACQUISITION_SOURCE" ]]; then
        printf 'error=missing-acquisition-config\n' >&2
        exit 1
    fi
    systemctl is-active --quiet crowdsec
}

backup_current_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    if [[ -f "$MANAGED_ACQUISITION" ]]; then
        cp -a "$MANAGED_ACQUISITION" "$BACKUP_DIR/visionforge.yaml"
        printf 'present\n' >"$BACKUP_DIR/config.state"
    else
        printf 'absent\n' >"$BACKUP_DIR/config.state"
    fi
}

restore_configuration() {
    trap - ERR
    if grep -Fx 'present' "$BACKUP_DIR/config.state" >/dev/null; then
        cp -a "$BACKUP_DIR/visionforge.yaml" "$MANAGED_ACQUISITION"
    else
        rm -f "$MANAGED_ACQUISITION"
    fi
    crowdsec -t >/dev/null 2>&1 && systemctl restart crowdsec || true
}

install_and_validate_configuration() {
    install -m 640 -o root -g root "$ACQUISITION_SOURCE" "$MANAGED_ACQUISITION"
    crowdsec -t
    systemctl restart crowdsec
    systemctl is-active --quiet crowdsec
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    install_and_validate_configuration
    trap - ERR
    printf 'crowdsec_acquisition=applied\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
