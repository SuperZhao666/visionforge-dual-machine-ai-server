#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly EXPECTED_VERSION="1.7.8"
readonly EXPECTED_SHA256="d93c47d5c25bee9461f5afdef6af513eae4c4b64f3a2e28ea2f7d173a5aa0ba9"
readonly PACKAGE_PATH="${1:-/var/cache/visionforge-security/crowdsec/crowdsec_1.7.8_amd64.deb}"
readonly ACQUISITION_SOURCE="${2:-}"
readonly MANAGED_ACQUISITION="/etc/crowdsec/acquis.d/visionforge.yaml"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-crowdsec-engine-$(date -u +%Y%m%dT%H%M%SZ)"
readonly SERVICE_GUARD_DIR="/etc/systemd/system/crowdsec.service.d"
readonly SERVICE_GUARD="${SERVICE_GUARD_DIR}/00-install-guard.conf"

INSTALL_PACKAGE_PATH=""
PACKAGE_INSTALL_STARTED="no"

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ ! -f "$PACKAGE_PATH" ]]; then
        printf 'error=missing-package\n' >&2
        exit 1
    fi
    if [[ -z "$ACQUISITION_SOURCE" || ! -f "$ACQUISITION_SOURCE" ]]; then
        printf 'error=missing-acquisition-config\n' >&2
        exit 1
    fi
    printf '%s  %s\n' "$EXPECTED_SHA256" "$PACKAGE_PATH" | sha256sum --check --status
    grep -Fq '/var/log/auth.log' "$ACQUISITION_SOURCE"
    grep -Fq '/var/log/nginx/access.log' "$ACQUISITION_SOURCE"
    if dpkg-query -W crowdsec >/dev/null 2>&1; then
        printf 'error=crowdsec-package-already-installed\n' >&2
        exit 1
    fi
}

backup_current_state() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    printf 'absent\n' >"$BACKUP_DIR/package-before.txt"
    if [[ -d /etc/crowdsec ]]; then
        tar --acls --xattrs -C /etc -czf "$BACKUP_DIR/crowdsec-etc-before.tar.gz" crowdsec
    fi
    nft list ruleset >"$BACKUP_DIR/nft-before.rules"
    iptables-save >"$BACKUP_DIR/iptables-before.rules"
}

install_service_guard() {
    install -d -m 755 -o root -g root "$SERVICE_GUARD_DIR"
    {
        printf '[Service]\n'
        printf 'Type=oneshot\n'
        printf 'ExecStartPre=\n'
        printf 'ExecStart=\n'
        printf 'ExecStart=/usr/bin/true\n'
        printf 'ExecReload=\n'
        printf 'Restart=no\n'
        printf 'RemainAfterExit=yes\n'
    } >"$SERVICE_GUARD"
    chmod 644 "$SERVICE_GUARD"
    systemctl daemon-reload
}

stage_package_for_apt() {
    INSTALL_PACKAGE_PATH="$(mktemp --tmpdir=/tmp crowdsec_1.7.8_amd64.XXXXXX --suffix=.deb)"
    install -m 644 -o root -g root "$PACKAGE_PATH" "$INSTALL_PACKAGE_PATH"
}

cleanup_staged_package() {
    if [[ -n "$INSTALL_PACKAGE_PATH" ]]; then
        rm -f -- "$INSTALL_PACKAGE_PATH"
    fi
}

simulate_package_installation() {
    env DEBIAN_FRONTEND=noninteractive apt-get -s install "$INSTALL_PACKAGE_PATH" \
        >"$BACKUP_DIR/apt-simulation.txt"
    if grep -E '^Remv ' "$BACKUP_DIR/apt-simulation.txt" >/dev/null; then
        printf 'error=package-simulation-removes-software\n' >&2
        exit 1
    fi
}

install_package() {
    install_service_guard
    PACKAGE_INSTALL_STARTED="yes"
    env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
        apt-get -o Acquire::https::Timeout=30 -o Acquire::Retries=3 \
        -y install "$INSTALL_PACKAGE_PATH"
    [[ "$(dpkg-query -W -f='${Version}' crowdsec)" == "$EXPECTED_VERSION" ]]
    systemctl stop crowdsec
    tar --acls --xattrs -C /etc -czf "$BACKUP_DIR/crowdsec-etc-package-default.tar.gz" crowdsec
}

disable_fresh_package_acquisitions() {
    local acquisition_path

    if [[ -f /etc/crowdsec/acquis.yaml ]]; then
        mv /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.yaml.package-default.disabled
    fi
    if [[ -d /etc/crowdsec/acquis.d ]]; then
        while IFS= read -r -d '' acquisition_path; do
            mv "$acquisition_path" "${acquisition_path}.package-default.disabled"
        done < <(
            find /etc/crowdsec/acquis.d -maxdepth 1 -type f -name '*.yaml' \
                ! -name 'visionforge.yaml' -print0
        )
    fi
}

configure_engine() {
    disable_fresh_package_acquisitions
    install -d -m 755 -o root -g root /etc/crowdsec/acquis.d
    install -m 640 -o root -g root "$ACQUISITION_SOURCE" "$MANAGED_ACQUISITION"
    cscli hub update
    cscli collections install crowdsecurity/linux
    cscli collections install crowdsecurity/nginx
    cscli collections install crowdsecurity/auditd
    crowdsec -t
}

start_and_verify_engine() {
    systemctl stop crowdsec
    rm -f "$SERVICE_GUARD"
    rmdir "$SERVICE_GUARD_DIR" 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable crowdsec
    systemctl restart crowdsec
    systemctl is-active --quiet crowdsec
    cscli lapi status >"$BACKUP_DIR/lapi-status.txt"
    ss -lnt | grep -E '127\.0\.0\.1:8080[[:space:]]' >/dev/null
    apt-mark hold crowdsec >/dev/null
}

stop_engine_after_failure() {
    local exit_code="$?"
    local purge_succeeded="no"

    trap - ERR
    systemctl disable --now crowdsec >/dev/null 2>&1 || true
    if [[ "$PACKAGE_INSTALL_STARTED" == "yes" ]]; then
        apt-mark unhold crowdsec >/dev/null 2>&1 || true
        if dpkg --purge crowdsec >/dev/null 2>&1; then
            purge_succeeded="yes"
        fi
    fi
    if [[ "$PACKAGE_INSTALL_STARTED" == "yes" && "$purge_succeeded" == "no" ]]; then
        install_service_guard
        systemctl disable --now crowdsec >/dev/null 2>&1 || true
    fi
    if [[ "$purge_succeeded" == "yes" || "$PACKAGE_INSTALL_STARTED" == "no" ]]; then
        rm -f "$SERVICE_GUARD"
        rmdir "$SERVICE_GUARD_DIR" 2>/dev/null || true
        systemctl daemon-reload
    fi
    printf 'error=crowdsec-engine-installation-failed\n' >&2
    printf 'rollback_path=%s\n' "$BACKUP_DIR" >&2
    exit "$exit_code"
}

main() {
    require_inputs
    backup_current_state
    stage_package_for_apt
    trap cleanup_staged_package EXIT
    trap stop_engine_after_failure ERR
    simulate_package_installation
    install_package
    configure_engine
    start_and_verify_engine
    trap - ERR
    printf 'crowdsec_engine=active\n'
    printf 'crowdsec_version=%s\n' "$EXPECTED_VERSION"
    printf 'package_hold=enabled\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
