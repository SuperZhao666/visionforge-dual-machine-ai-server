#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly RULE_SCRIPT_SOURCE="${1:-}"
readonly ROLLBACK_SCRIPT_SOURCE="${2:-}"
readonly UNIT_SOURCE="${3:-}"
readonly RULE_SCRIPT="/usr/local/sbin/visionforge-docker-firewall"
readonly ROLLBACK_SCRIPT="/usr/local/sbin/visionforge-firewall-rollback"
readonly UNIT_FILE="/etc/systemd/system/visionforge-docker-firewall.service"
readonly CONFIG_FILE="/etc/default/visionforge-docker-firewall"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-firewall-$(date -u +%Y%m%dT%H%M%SZ)"
readonly HEALTH_CONNECT_TIMEOUT_SECONDS=2
readonly HEALTH_MAX_TIME_SECONDS=5
readonly IPTABLES_WAIT_SECONDS=10

require_inputs() {
    local source
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    for source in "$RULE_SCRIPT_SOURCE" "$ROLLBACK_SCRIPT_SOURCE" "$UNIT_SOURCE"; do
        if [[ -z "$source" || ! -f "$source" ]]; then
            printf 'error=missing-source\n' >&2
            exit 1
        fi
    done
}

detect_external_interface() {
    local route
    route="$(ip -4 route get 1.1.1.1)"
    if [[ ! "$route" =~ dev[[:space:]]+([A-Za-z0-9_.:-]+) ]]; then
        printf 'error=external-interface-not-found\n' >&2
        return 1
    fi
    printf '%s\n' "${BASH_REMATCH[1]}"
}

capture_state() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    iptables-save >"${BACKUP_DIR}/iptables.before"
    ip6tables-save >"${BACKUP_DIR}/ip6tables.before"
    nft list ruleset >"${BACKUP_DIR}/nftables.before" 2>/dev/null || true
    ufw status >"${BACKUP_DIR}/ufw.before"
    systemctl is-enabled visionforge-docker-firewall.service \
        >"${BACKUP_DIR}/service-enabled.before" 2>/dev/null || true
}

rollback_changes() {
    systemctl disable --now visionforge-docker-firewall.service >/dev/null 2>&1 || true
    ufw disable >/dev/null 2>&1 || true
}

install_managed_files() {
    local external_interface="$1"
    install -m 750 -o root -g root "$RULE_SCRIPT_SOURCE" "$RULE_SCRIPT"
    install -m 750 -o root -g root "$ROLLBACK_SCRIPT_SOURCE" "$ROLLBACK_SCRIPT"
    install -m 644 -o root -g root "$UNIT_SOURCE" "$UNIT_FILE"
    printf 'EXT_IF=%s\n' "$external_interface" >"$CONFIG_FILE"
    chown root:root "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    systemctl daemon-reload
}

schedule_automatic_rollback() {
    systemctl stop vf-firewall-rollback.timer vf-firewall-rollback.service >/dev/null 2>&1 || true
    systemd-run --quiet --unit=vf-firewall-rollback --on-active=2m --collect "$ROLLBACK_SCRIPT"
}

enable_ufw() {
    local external_interface="$1"
    ufw allow in on "$external_interface" proto tcp to any port 22 comment SSH
    ufw allow in on "$external_interface" proto tcp to any port 80 comment HTTP
    ufw allow in on "$external_interface" proto tcp to any port 443 comment HTTPS
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    ufw --force enable
}

validate_local_runtime() {
    systemctl enable --now visionforge-docker-firewall.service
    curl --fail --silent --show-error \
        --connect-timeout "$HEALTH_CONNECT_TIMEOUT_SECONDS" \
        --max-time "$HEALTH_MAX_TIME_SECONDS" \
        --output /dev/null http://127.0.0.1:8000/
    curl --fail --silent --show-error \
        --connect-timeout "$HEALTH_CONNECT_TIMEOUT_SECONDS" \
        --max-time "$HEALTH_MAX_TIME_SECONDS" \
        --output /dev/null http://127.0.0.1:6185/
    docker exec vf-qq-steward python -c \
        'import socket; s=socket.create_connection(("api.deepseek.com", 443), 10); s.close()'
    assert_pending_firewall_state "$1"
}

assert_pending_firewall_state() {
    local external_interface="$1"
    ufw status verbose >"${BACKUP_DIR}/ufw.after"
    grep -q '^Status: active' "${BACKUP_DIR}/ufw.after"
    systemctl is-active --quiet visionforge-docker-firewall.service
    iptables -w "$IPTABLES_WAIT_SECONDS" -C DOCKER-USER -i "$external_interface" -m comment \
        --comment vf-drop-untrusted-forwarding -j DROP
    systemctl is-active --quiet vf-firewall-rollback.timer
}

main() {
    local external_interface
    require_inputs
    external_interface="$(detect_external_interface)"
    capture_state
    trap rollback_changes ERR
    install_managed_files "$external_interface"
    schedule_automatic_rollback
    enable_ufw "$external_interface"
    validate_local_runtime "$external_interface"
    trap - ERR
    printf 'firewall=pending-external-validation\n'
    printf 'external_interface=%s\n' "$external_interface"
    printf 'rollback_timer=vf-firewall-rollback.timer\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
