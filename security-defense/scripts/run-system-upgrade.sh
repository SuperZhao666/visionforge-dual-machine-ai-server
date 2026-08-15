#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly APP_ROOT="${APP_ROOT:-/home/ubuntu/vf-platform}"
readonly APP_SERVICE="${APP_SERVICE:-vf.service}"
readonly DB_PATH="${DB_PATH:-${APP_ROOT}/data/vf.db}"
readonly BACKUP_DIR="${1:-}"
readonly STATE_DIR="/var/lib/visionforge-security"
readonly STATUS_FILE="${STATE_DIR}/upgrade.status"
readonly SIMULATION_FILE="${STATE_DIR}/dist-upgrade.simulation"
readonly DOCKER_PACKAGES=(
    containerd.io
    docker-buildx-plugin
    docker-ce
    docker-ce-cli
    docker-ce-rootless-extras
    docker-compose-plugin
)

mark_failed() {
    local exit_code=$?
    printf 'failed exit_code=%s timestamp=%s\n' "$exit_code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >"$STATUS_FILE"
    exit "$exit_code"
}

require_preconditions() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    case "$BACKUP_DIR" in
        /var/backups/visionforge-security/security-*) ;;
        *) printf 'error=invalid-backup-path\n' >&2; exit 1 ;;
    esac
    [[ -d "$BACKUP_DIR" && ! -e "${BACKUP_DIR}/INCOMPLETE" ]]
    (
        cd "$BACKUP_DIR"
        sha256sum --check --quiet SHA256SUMS
    )
}

verify_docker_holds() {
    local package selection
    for package in "${DOCKER_PACKAGES[@]}"; do
        selection="$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)"
        [[ "$selection" == ii\ * ]] || continue
        if [[ "$(apt-mark showhold "$package")" != "$package" ]]; then
            printf 'error=docker-package-not-held package=%s\n' "$package" >&2
            return 1
        fi
    done
}

simulate_upgrade() {
    apt-get -s -o APT::Get::Always-Include-Phased-Updates=true dist-upgrade \
        >"$SIMULATION_FILE"
    if grep -q '^Remv ' "$SIMULATION_FILE"; then
        printf 'error=simulation-would-remove-packages\n' >&2
        grep '^Remv ' "$SIMULATION_FILE" >&2
        return 1
    fi
}

install_updates() {
    env \
        APT_LISTCHANGES_FRONTEND=none \
        DEBIAN_FRONTEND=noninteractive \
        NEEDRESTART_MODE=l \
        apt-get -y \
            -o APT::Get::Always-Include-Phased-Updates=true \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold \
            dist-upgrade
}

verify_database() {
    local python_bin="${APP_ROOT}/venv/bin/python"
    [[ -x "$python_bin" ]] || python_bin="$(command -v python3)"
    "$python_bin" - "$DB_PATH" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    result = connection.execute("PRAGMA integrity_check").fetchone()
    if result != ("ok",):
        raise RuntimeError(f"database integrity check failed: {result!r}")
finally:
    connection.close()
PY
}

verify_runtime() {
    dpkg --audit
    apt-get check
    sshd -t
    nginx -t
    systemctl is-active --quiet "$APP_SERVICE"
    systemctl is-active --quiet nginx
    systemctl is-active --quiet docker
    curl --fail --silent --show-error --output /dev/null http://127.0.0.1:8000/
    curl --fail --silent --show-error --output /dev/null http://127.0.0.1:6185/
    [[ "$(docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' vf-qq-steward)" == 'running healthy' ]]
    [[ "$(docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' vf-qq-napcat)" == 'running healthy' ]]
    [[ "$(docker inspect --format '{{.State.Status}}' vmq-itchat)" == 'running' ]]
    verify_database
}

main() {
    require_preconditions
    install -d -m 700 -o root -g root "$STATE_DIR"
    exec 9>/run/vf-security-upgrade.lock
    flock -n 9
    trap mark_failed ERR
    printf 'running timestamp=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATUS_FILE"
    verify_docker_holds
    simulate_upgrade
    install_updates
    verify_runtime
    dpkg-query -W -f='${binary:Package}\t${Version}\n' >"${STATE_DIR}/packages.after.tsv"
    printf 'complete timestamp=%s reboot_required=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$([[ -e /var/run/reboot-required ]] && printf yes || printf no)" \
        >"$STATUS_FILE"
    trap - ERR
    cat "$STATUS_FILE"
}

main "$@"
