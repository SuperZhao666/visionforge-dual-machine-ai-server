#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly PACKAGE_NAME="crowdsec-firewall-bouncer-nftables"
readonly EXPECTED_VERSION="0.0.34"
readonly EXPECTED_SHA256="0d8817cd8bb5e1e7970cc1ff4969347653af5d4acd3c2215d1b6f541dbfb1ee4"
readonly PACKAGE_PATH="${1:-/var/cache/visionforge-security/crowdsec/crowdsec-firewall-bouncer-nftables_0.0.34_amd64.deb}"
readonly SERVICE_NAME="crowdsec-firewall-bouncer.service"
readonly SERVICE_GUARD_DIR="/etc/systemd/system/${SERVICE_NAME}.d"
readonly SERVICE_GUARD="${SERVICE_GUARD_DIR}/00-install-guard.conf"
readonly BOUNCER_CONFIG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-crowdsec-bouncer-$(date -u +%Y%m%dT%H%M%SZ)"
readonly TEST_DECISION_IP="192.0.2.1"
readonly ROLLBACK_UNIT="vf-crowdsec-bouncer-rollback"

ADMIN_IP=""
PACKAGE_INSTALL_STARTED="no"
TEST_DECISION_CREATED="no"

require_environment() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ ! -f "$PACKAGE_PATH" ]]; then
        printf 'error=missing-package\n' >&2
        exit 1
    fi
    printf '%s  %s\n' "$EXPECTED_SHA256" "$PACKAGE_PATH" | sha256sum --check --status
    [[ "$(dpkg-query -W -f='${Version}' crowdsec)" == "1.7.8" ]]
    systemctl is-active --quiet crowdsec
    dpkg-query -W gettext-base nftables >/dev/null
    iptables -V | grep -F 'nf_tables' >/dev/null
    if dpkg-query -W "$PACKAGE_NAME" >/dev/null 2>&1; then
        printf 'error=bouncer-package-already-installed\n' >&2
        exit 1
    fi
}

read_and_validate_admin_ip() {
    if ! IFS= read -r ADMIN_IP || [[ -z "$ADMIN_IP" ]]; then
        printf 'error=missing-admin-ip-on-stdin\n' >&2
        exit 1
    fi
    ADMIN_IP="$ADMIN_IP" python3 -c \
        'import ipaddress, os; ipaddress.ip_address(os.environ["ADMIN_IP"])'
    if [[ "$ADMIN_IP" == "$TEST_DECISION_IP" ]]; then
        printf 'error=invalid-admin-ip\n' >&2
        exit 1
    fi
}

backup_current_state() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    nft list ruleset >"$BACKUP_DIR/nft-before.rules"
    iptables-save >"$BACKUP_DIR/iptables-before.rules"
    ip6tables-save >"$BACKUP_DIR/ip6tables-before.rules"
    cscli allowlists list -o json >"$BACKUP_DIR/allowlists-before.json"
    cscli bouncers list -o json >"$BACKUP_DIR/bouncers-before.json"
    if [[ -f /var/lib/crowdsec/data/crowdsec.db ]]; then
        python3 - /var/lib/crowdsec/data/crowdsec.db \
            "$BACKUP_DIR/crowdsec-before.db" <<'PY'
import sqlite3
import sys

source_path, backup_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
backup = sqlite3.connect(backup_path)
try:
    source.backup(backup)
finally:
    backup.close()
    source.close()
PY
        chmod 600 "$BACKUP_DIR/crowdsec-before.db"
    fi
    if [[ -d /etc/crowdsec/bouncers ]]; then
        tar --acls --xattrs -C /etc/crowdsec -czf \
            "$BACKUP_DIR/crowdsec-bouncers-before.tar.gz" bouncers
        printf 'present\n' >"$BACKUP_DIR/bouncer-directory.state"
    else
        printf 'absent\n' >"$BACKUP_DIR/bouncer-directory.state"
    fi
    if dpkg-query -W "$PACKAGE_NAME" >/dev/null 2>&1; then
        dpkg-query -W -f='${Package} ${Version}\n' "$PACKAGE_NAME" \
            >"$BACKUP_DIR/package-before.txt"
    else
        printf 'absent\n' >"$BACKUP_DIR/package-before.txt"
    fi
}

configure_admin_allowlist() {
    if ! cscli allowlists inspect admin-access >/dev/null 2>&1; then
        cscli allowlists create admin-access \
            --description 'SSH administrative access'
    fi
    if ! cscli allowlists check "$ADMIN_IP" 2>/dev/null | grep -F 'admin-access' >/dev/null; then
        cscli allowlists add admin-access "$ADMIN_IP" \
            --comment 'verified deployment source'
    fi
    cscli allowlists check "$ADMIN_IP" | grep -F 'admin-access' >/dev/null
}

install_service_guard() {
    install -d -m 755 -o root -g root "$SERVICE_GUARD_DIR"
    {
        printf '[Service]\n'
        printf 'Type=oneshot\n'
        printf 'ExecStartPre=\n'
        printf 'ExecStart=\n'
        printf 'ExecStart=/usr/bin/true\n'
        printf 'ExecStartPost=\n'
        printf 'Restart=no\n'
        printf 'RemainAfterExit=yes\n'
    } >"$SERVICE_GUARD"
    chmod 644 "$SERVICE_GUARD"
    systemctl daemon-reload
}

install_package_without_enforcement() {
    install_service_guard
    PACKAGE_INSTALL_STARTED="yes"
    dpkg --install "$PACKAGE_PATH"
    [[ "$(dpkg-query -W -f='${Version}' "$PACKAGE_NAME")" == "$EXPECTED_VERSION" ]]
}

validate_generated_configuration() {
    [[ -f "$BOUNCER_CONFIG" ]]
    [[ "$(stat -c '%a %U:%G' "$BOUNCER_CONFIG")" == "600 root:root" ]]
    grep -Fx 'mode: nftables' "$BOUNCER_CONFIG" >/dev/null
    grep -Fx 'api_url: http://127.0.0.1:8080/' "$BOUNCER_CONFIG" >/dev/null
    grep -Fx 'insecure_skip_verify: false' "$BOUNCER_CONFIG" >/dev/null
    grep -Eq '^api_key: [^[:space:]]+$' "$BOUNCER_CONFIG"
    grep -Fx '  - input' "$BOUNCER_CONFIG" >/dev/null
    grep -Fx '  - forward' "$BOUNCER_CONFIG" >/dev/null
}

enable_enforcement() {
    rm -f "$SERVICE_GUARD"
    rmdir "$SERVICE_GUARD_DIR" 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    systemctl is-active --quiet "$SERVICE_NAME"
    nft list table ip crowdsec >/dev/null
    nft list table ip6 crowdsec6 >/dev/null
    apt-mark hold "$PACKAGE_NAME" >/dev/null
}

schedule_automatic_rollback() {
    systemctl stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" \
        >/dev/null 2>&1 || true
    systemctl reset-failed "${ROLLBACK_UNIT}.service" >/dev/null 2>&1 || true
    systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active=3m --collect \
        /bin/systemctl disable --now "$SERVICE_NAME"
    systemctl is-active --quiet "${ROLLBACK_UNIT}.timer"
}

verify_existing_boundaries() {
    local external_interface

    # shellcheck source=/dev/null
    source /etc/default/visionforge-docker-firewall
    external_interface="${EXT_IF:-}"
    [[ "$external_interface" =~ ^[A-Za-z0-9_.:-]+$ ]]
    ufw status | grep -F 'Status: active' >/dev/null
    iptables -C FORWARD -j DOCKER-USER
    iptables -C DOCKER-USER -i "$external_interface" \
        -m conntrack --ctstate RELATED,ESTABLISHED \
        -m comment --comment 'vf-allow-container-egress-replies' -j ACCEPT
    iptables -C DOCKER-USER -i "$external_interface" \
        -m comment --comment 'vf-drop-untrusted-forwarding' -j DROP
    docker network inspect qq-steward_default >/dev/null
    docker network inspect qq-steward_default |
        grep -F '"Name": "vf-qq-steward"' >/dev/null
    docker network inspect qq-steward_default |
        grep -F '"Name": "vf-qq-napcat"' >/dev/null
    docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
        vf-qq-steward | grep -Fx 'running healthy' >/dev/null
    docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
        vf-qq-napcat | grep -Fx 'running healthy' >/dev/null
    systemctl is-active --quiet vf.service
    ss -lnt | grep -E '127\.0\.0\.1:6185[[:space:]]' >/dev/null
    ss -lnt | grep -E '127\.0\.0\.1:6099[[:space:]]' >/dev/null
    ss -lnt | grep -E '127\.0\.0\.1:8000[[:space:]]' >/dev/null
}

cleanup_test_decision() {
    if [[ "$TEST_DECISION_CREATED" == "yes" ]]; then
        cscli decisions delete --ip "$TEST_DECISION_IP" >/dev/null 2>&1 || true
    fi
}

wait_for_test_decision_state() {
    local expected_state="$1"
    local attempt
    local actual_state

    for attempt in {1..15}; do
        if nft list table ip crowdsec |
            grep -F "$TEST_DECISION_IP" >/dev/null; then
            actual_state="present"
        else
            actual_state="absent"
        fi
        if [[ "$actual_state" == "$expected_state" ]]; then
            return 0
        fi
        sleep 2
    done
    return 1
}

verify_test_decision_enforcement() {
    cscli decisions add --ip "$TEST_DECISION_IP" --duration 2m \
        --reason 'crowdsec-smoke-test'
    TEST_DECISION_CREATED="yes"
    wait_for_test_decision_state present
    cscli decisions delete --ip "$TEST_DECISION_IP"
    wait_for_test_decision_state absent
    TEST_DECISION_CREATED="no"
    cscli metrics show bouncers >"$BACKUP_DIR/bouncer-metrics-after.txt"
    cscli bouncers list -o json >"$BACKUP_DIR/bouncers-after.json"
}

remove_bouncer_directory() {
    local resolved_path

    resolved_path="$(realpath -m /etc/crowdsec/bouncers)"
    [[ "$resolved_path" == "/etc/crowdsec/bouncers" ]]
    if [[ -d "$resolved_path" ]]; then
        find "$resolved_path" -xdev -depth -mindepth 1 -delete
        rmdir "$resolved_path"
    fi
}

delete_generated_bouncer_credential() {
    local bouncer_id

    if [[ ! -f "${BOUNCER_CONFIG}.id" ]]; then
        return
    fi
    bouncer_id="$(<"${BOUNCER_CONFIG}.id")"
    if [[ "$bouncer_id" =~ ^cs-firewall-bouncer-[0-9]+$ ]]; then
        cscli bouncers delete "$bouncer_id" >/dev/null 2>&1 || true
    fi
}

stop_bouncer_after_failure() {
    local exit_code="$?"
    local purge_succeeded="no"

    trap - ERR
    systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl stop "${ROLLBACK_UNIT}.timer" "${ROLLBACK_UNIT}.service" \
        >/dev/null 2>&1 || true
    if [[ "$PACKAGE_INSTALL_STARTED" == "yes" ]]; then
        delete_generated_bouncer_credential
        apt-mark unhold "$PACKAGE_NAME" >/dev/null 2>&1 || true
        if dpkg --purge "$PACKAGE_NAME" >/dev/null 2>&1; then
            purge_succeeded="yes"
        fi
        if nft list table ip crowdsec >/dev/null 2>&1; then
            nft delete table ip crowdsec || true
        fi
        if nft list table ip6 crowdsec6 >/dev/null 2>&1; then
            nft delete table ip6 crowdsec6 || true
        fi
        if grep -Fx 'present' "$BACKUP_DIR/bouncer-directory.state" >/dev/null; then
            remove_bouncer_directory
            tar --acls --xattrs -C /etc/crowdsec -xzf \
                "$BACKUP_DIR/crowdsec-bouncers-before.tar.gz"
        else
            remove_bouncer_directory
        fi
    fi
    if [[ "$PACKAGE_INSTALL_STARTED" == "yes" && "$purge_succeeded" == "no" ]]; then
        install_service_guard
        systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    if [[ "$purge_succeeded" == "yes" || "$PACKAGE_INSTALL_STARTED" == "no" ]]; then
        rm -f "$SERVICE_GUARD"
        rmdir "$SERVICE_GUARD_DIR" 2>/dev/null || true
        systemctl daemon-reload
    fi
    printf 'error=crowdsec-bouncer-installation-failed\n' >&2
    printf 'rollback_path=%s\n' "$BACKUP_DIR" >&2
    exit "$exit_code"
}

main() {
    require_environment
    trap cleanup_test_decision EXIT
    read_and_validate_admin_ip
    backup_current_state
    trap stop_bouncer_after_failure ERR
    configure_admin_allowlist
    install_package_without_enforcement
    validate_generated_configuration
    schedule_automatic_rollback
    enable_enforcement
    verify_existing_boundaries
    verify_test_decision_enforcement
    trap - ERR
    printf 'crowdsec_bouncer=active\n'
    printf 'bouncer_version=%s\n' "$EXPECTED_VERSION"
    printf 'admin_allowlist=verified\n'
    printf 'package_hold=enabled\n'
    printf 'rollback_timer=%s.timer\n' "$ROLLBACK_UNIT"
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
