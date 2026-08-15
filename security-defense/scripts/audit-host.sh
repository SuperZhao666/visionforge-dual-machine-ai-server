#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/report.sh
source "${SCRIPT_DIR}/lib/report.sh"

readonly APP_ROOT="${APP_ROOT:-/home/ubuntu/vf-platform}"
readonly APP_SERVICE="${APP_SERVICE:-vf.service}"
readonly APP_HEALTH_URL="${APP_HEALTH_URL:-http://127.0.0.1:8000/}"
readonly APP_OPENAPI_URL="${APP_OPENAPI_URL:-http://127.0.0.1:8000/openapi.json}"
readonly DB_PATH="${DB_PATH:-${APP_ROOT}/data/vf.db}"
readonly BOT_HEALTH_URL="${BOT_HEALTH_URL:-}"

print_identity() {
    section "identity"
    key_value "timestamp_utc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    key_value "hostname" "$(hostname --fqdn 2>/dev/null || hostname)"
    key_value "kernel" "$(uname -srmo)"
    key_value "uptime_seconds" "$(cut -d. -f1 /proc/uptime)"
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        key_value "os" "${PRETTY_NAME:-unknown}"
    fi
}

print_resources() {
    section "resources"
    run_optional "memory" free -h
    run_optional "filesystem" df -hT / "${APP_ROOT}"
    run_optional "load" uptime
    run_optional "swap" swapon --show
}

print_packages() {
    section "packages"
    local packages=(openssh-server nginx docker-ce docker.io containerd.io certbot unattended-upgrades auditd aide crowdsec crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables)
    local package
    for package in "${packages[@]}"; do
        dpkg-query -W -f='${binary:Package}=${Version}\n' "$package" 2>/dev/null || true
    done
    run_optional "pending-upgrades-from-current-cache" bash -c \
        "apt-get -s upgrade 2>/dev/null | awk '/^Inst / {print \$2\"=\"\$3}'"
    key_value "reboot_required" "$([[ -f /var/run/reboot-required ]] && printf yes || printf no)"
}

print_network() {
    section "network"
    run_optional "listening-tcp-udp" ss -lntup
    run_optional "addresses" ip -brief address
    run_optional "routes" ip route show
}

print_firewall() {
    section "firewall"
    if has_command ufw; then
        run_privileged "ufw" ufw status verbose
    fi
    if has_command iptables; then
        run_privileged "iptables-input" iptables -S INPUT
        run_privileged "iptables-forward" iptables -S FORWARD
        run_privileged "docker-user" iptables -S DOCKER-USER
    fi
    if has_command nft; then
        run_privileged "nft-ruleset-summary" bash -c \
            "nft list ruleset 2>/dev/null | awk '/^[[:space:]]*(table|chain) / {print}'"
    fi
}

print_ssh() {
    section "ssh"
    run_optional "client-banner" ssh -V
    run_privileged "server-effective-config" bash -c \
        "sshd -T 2>/dev/null | awk '\$1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups|x11forwarding|permituserenvironment|allowtcpforwarding|clientaliveinterval|clientalivecountmax)$/ {print}'"
    run_privileged "server-config-test" sshd -t
    if [[ -d "${HOME}/.ssh" ]]; then
        run_optional "authorized-key-metadata" find "${HOME}/.ssh" -maxdepth 1 -type f -printf '%m %u:%g %f\n'
    fi
}

print_nginx() {
    section "nginx"
    if ! has_command nginx; then
        key_value "installed" "no"
        return
    fi
    run_optional "version" nginx -v
    run_privileged "configuration-test" nginx -t
    run_privileged "configuration-files" find /etc/nginx -maxdepth 3 -type f \
        -printf '%m %u:%g %p\n'
    if has_command certbot; then
        run_privileged "certificates" certbot certificates
    fi
}

print_services() {
    section "services"
    run_optional "application" systemctl show "$APP_SERVICE" \
        --property=ActiveState,SubState,MainPID,User,Group,FragmentPath,DropInPaths,MemoryCurrent,TasksCurrent
    run_optional "failed-units" systemctl --failed --no-pager --no-legend
    run_optional "timers" systemctl list-timers --all --no-pager --no-legend
}

print_docker() {
    section "docker"
    if ! has_command docker; then
        key_value "installed" "no"
        return
    fi
    run_optional "version" docker version --format 'client={{.Client.Version}} server={{.Server.Version}}'
    run_privileged "containers" docker ps --no-trunc \
        --format 'name={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}} networks={{.Networks}}'
    run_privileged "container-security" bash -c \
        "docker ps -q | xargs -r docker inspect --format 'name={{.Name}} privileged={{.HostConfig.Privileged}} readonly={{.HostConfig.ReadonlyRootfs}} security_opt={{json .HostConfig.SecurityOpt}} cap_add={{json .HostConfig.CapAdd}} restart={{.HostConfig.RestartPolicy.Name}}'"
}

print_sensitive_metadata() {
    section "sensitive-path-metadata"
    local paths=("${APP_ROOT}/.env" "$DB_PATH" "${APP_ROOT}/owner_keys" "${APP_ROOT}/log_storage" "${APP_ROOT}/app/static/releases")
    local path
    for path in "${paths[@]}"; do
        if [[ -e "$path" ]]; then
            stat -c '%a %U:%G %F %n' "$path"
        else
            printf 'missing=%s\n' "$path"
        fi
    done
}

print_database_integrity() {
    section "database-integrity"
    if [[ ! -r "$DB_PATH" ]]; then
        key_value "status" "unreadable-or-missing"
        return
    fi
    local python_bin="${APP_ROOT}/venv/bin/python"
    [[ -x "$python_bin" ]] || python_bin="$(command -v python3 || true)"
    if [[ -z "$python_bin" ]]; then
        key_value "status" "python-unavailable"
        return
    fi
    if ! "$python_bin" - "$DB_PATH" <<'PY'
import sqlite3
import sys

database_path = sys.argv[1]
connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
try:
    connection.execute("PRAGMA query_only=ON")
    result = connection.execute("PRAGMA integrity_check").fetchone()
    print(f"integrity_check={result[0] if result else 'no-result'}")
finally:
    connection.close()
PY
    then
        key_value "status" "integrity-check-failed"
    fi
}

print_health() {
    section "health"
    run_optional "application-http" curl --fail --silent --show-error --output /dev/null \
        --write-out 'status=%{http_code} time_total=%{time_total}\n' "$APP_HEALTH_URL"
    run_optional "openapi-http" curl --fail --silent --show-error --output /dev/null \
        --write-out 'status=%{http_code} time_total=%{time_total}\n' "$APP_OPENAPI_URL"
    if [[ -n "$BOT_HEALTH_URL" ]]; then
        run_optional "bot-http" curl --fail --silent --show-error --output /dev/null \
            --write-out 'status=%{http_code} time_total=%{time_total}\n' "$BOT_HEALTH_URL"
    fi
}

print_crowdsec() {
    section "crowdsec"
    if ! has_command cscli; then
        key_value "installed" "no"
        return
    fi
    run_privileged "metrics" cscli metrics
    run_privileged "bouncers" cscli bouncers list
    run_privileged "decisions" cscli decisions list
}

main() {
    printf '# VisionForge host security audit\n'
    print_identity
    print_resources
    print_packages
    print_network
    print_firewall
    print_ssh
    print_nginx
    print_services
    print_docker
    print_sensitive_metadata
    print_database_integrity
    print_health
    print_crowdsec
}

main "$@"
