#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly MANAGED_RULES="/etc/audit/rules.d/70-visionforge.rules"
readonly LEGACY_MANAGED_RULES="/etc/audit/rules.d/99-visionforge.rules"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-auditd-$(date -u +%Y%m%dT%H%M%SZ)"
readonly RULES_SOURCE="${1:-}"

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ -z "$RULES_SOURCE" || ! -f "$RULES_SOURCE" ]]; then
        printf 'error=missing-rules-source\n' >&2
        exit 1
    fi
}

backup_rule_path() {
    local path="$1"
    local name="$2"
    if [[ -e "$path" ]]; then
        cp -a "$path" "${BACKUP_DIR}/${name}"
        printf 'present\n' >"${BACKUP_DIR}/${name}.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/${name}.state"
    fi
}

restore_rule_path() {
    local path="$1"
    local name="$2"
    if grep -qx 'present' "${BACKUP_DIR}/${name}.state"; then
        rm -f "$path"
        cp -a "${BACKUP_DIR}/${name}" "$path"
    else
        rm -f "$path"
    fi
}

backup_current_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    backup_rule_path "$MANAGED_RULES" managed-rules
    backup_rule_path "$LEGACY_MANAGED_RULES" legacy-managed-rules
}

restore_configuration() {
    restore_rule_path "$MANAGED_RULES" managed-rules
    restore_rule_path "$LEGACY_MANAGED_RULES" legacy-managed-rules
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || true
    fi
}

install_audit_service() {
    env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
        apt-get -y install auditd audispd-plugins
    systemctl enable auditd
    systemctl is-active --quiet auditd || service auditd start
}

install_and_validate_rules() {
    install -m 640 -o root -g root "$RULES_SOURCE" "$MANAGED_RULES"
    rm -f "$LEGACY_MANAGED_RULES"
    augenrules --check
    augenrules --load
    auditctl -l >"${BACKUP_DIR}/rules.after"
    grep -Eq '(-k |key=)vf_ssh_config' "${BACKUP_DIR}/rules.after"
    grep -Eq '(-k |key=)vf_signing_keys' "${BACKUP_DIR}/rules.after"
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    install_audit_service
    install_and_validate_rules
    trap - ERR
    printf 'auditd=active\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
