#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly MANAGED_CONFIG="/etc/apt/apt.conf.d/52-security-defense-unattended-upgrades"
readonly SOURCES_FILE="/etc/apt/sources.list"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-apt-$(date -u +%Y%m%dT%H%M%SZ)"
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
    cp -a "$SOURCES_FILE" "${BACKUP_DIR}/sources.list"
    if [[ -e "$MANAGED_CONFIG" ]]; then
        cp -a "$MANAGED_CONFIG" "${BACKUP_DIR}/managed-config"
        printf 'present\n' >"${BACKUP_DIR}/managed-config.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/managed-config.state"
    fi
}

restore_configuration() {
    cp -a "${BACKUP_DIR}/sources.list" "$SOURCES_FILE"
    if grep -qx 'present' "${BACKUP_DIR}/managed-config.state"; then
        cp -a "${BACKUP_DIR}/managed-config" "$MANAGED_CONFIG"
    else
        rm -f "$MANAGED_CONFIG"
    fi
    apt-get update >/dev/null 2>&1 || true
}

enable_https_mirror() {
    local http_origin='http://mirrors.tencentyun.com/ubuntu'
    local https_origin='https://mirrors.tencentyun.com/ubuntu'
    if grep -Fq "$http_origin" "$SOURCES_FILE"; then
        sed -i "s|${http_origin}|${https_origin}|g" "$SOURCES_FILE"
    fi
    grep -Fq "$https_origin" "$SOURCES_FILE"
    if grep -Fq "$http_origin" "$SOURCES_FILE"; then
        printf 'error=plaintext-ubuntu-mirror-remains\n' >&2
        return 1
    fi
}

install_unattended_configuration() {
    install -m 644 -o root -g root "$CONFIG_SOURCE" "$MANAGED_CONFIG"
    apt-get update
    apt-config dump >"${BACKUP_DIR}/apt-config.after"
    grep -Fq '${distro_id}:${distro_codename}-security' "${BACKUP_DIR}/apt-config.after"
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    enable_https_mirror
    install_unattended_configuration
    trap - ERR
    printf 'apt_security_config=applied\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
