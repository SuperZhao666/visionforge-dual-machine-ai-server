#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly APP_ROOT="${APP_ROOT:-/home/ubuntu/vf-platform}"
readonly APP_SERVICE="${APP_SERVICE:-vf.service}"
readonly DB_PATH="${DB_PATH:-${APP_ROOT}/data/vf.db}"
readonly BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/visionforge-security}"
readonly BACKUP_ID="security-$(date -u +%Y%m%dT%H%M%SZ)"
readonly BACKUP_DIR="${BACKUP_ROOT}/${BACKUP_ID}"

require_root() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
}

create_backup_directory() {
    install -d -m 700 -o root -g root "$BACKUP_ROOT"
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    printf 'backup_incomplete\n' >"${BACKUP_DIR}/INCOMPLETE"
}

collect_existing_paths() {
    local candidate
    for candidate in "$@"; do
        [[ -e "$candidate" ]] && printf '%s\0' "${candidate#/}"
    done
}

backup_system_configuration() {
    local paths=(
        /etc/apt
        /etc/audit
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.hourly
        /etc/cron.monthly
        /etc/cron.weekly
        /etc/crontab
        /etc/docker
        /etc/letsencrypt
        /etc/logrotate.conf
        /etc/logrotate.d
        /etc/nginx
        /etc/security
        /etc/ssh
        /etc/sysctl.conf
        /etc/sysctl.d
        /etc/systemd/system
        /etc/ufw
        /var/lib/letsencrypt
        /var/spool/cron/crontabs
    )
    mapfile -d '' -t existing_paths < <(collect_existing_paths "${paths[@]}")
    tar --acls --xattrs --numeric-owner -C / -czpf \
        "${BACKUP_DIR}/system-configs.tar.gz" "${existing_paths[@]}"
}

backup_database() {
    local python_bin="${APP_ROOT}/venv/bin/python"
    local backup_path="${BACKUP_DIR}/vf.db"
    [[ -x "$python_bin" ]] || python_bin="$(command -v python3)"
    "$python_bin" - "$DB_PATH" "$backup_path" <<'PY'
import sqlite3
import sys

source_path, backup_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
destination = sqlite3.connect(backup_path)
try:
    source.backup(destination)
    result = destination.execute("PRAGMA integrity_check").fetchone()
    if result != ("ok",):
        raise RuntimeError(f"backup integrity check failed: {result!r}")
finally:
    destination.close()
    source.close()
PY
    chmod 600 "$backup_path"
}

backup_application_assets() {
    local paths=(
        "${APP_ROOT}/.env"
        "${APP_ROOT}/owner_keys"
        "${APP_ROOT}/log_storage"
    )
    local relative_paths=()
    local path
    for path in "${paths[@]}"; do
        [[ -e "$path" ]] && relative_paths+=("${path#${APP_ROOT}/}")
    done
    tar --acls --xattrs --numeric-owner -C "$APP_ROOT" -czpf \
        "${BACKUP_DIR}/application-assets.tar.gz" "${relative_paths[@]}"
}

capture_release_manifest() {
    local release_root="${APP_ROOT}/app/static/releases"
    local manifest="${BACKUP_DIR}/release-files.sha256"
    if [[ ! -d "$release_root" ]]; then
        printf 'release_directory_missing\n' >"$manifest"
        return
    fi
    find "$release_root" -type f -print0 \
        | sort -z \
        | xargs -0 -r sha256sum >"$manifest"
}

capture_operating_state() {
    dpkg-query -W -f='${binary:Package}\t${Version}\n' >"${BACKUP_DIR}/packages.tsv"
    apt-mark showmanual >"${BACKUP_DIR}/apt-manual.txt"
    iptables-save >"${BACKUP_DIR}/iptables.rules"
    ip6tables-save >"${BACKUP_DIR}/ip6tables.rules"
    nft list ruleset >"${BACKUP_DIR}/nftables.rules" 2>/dev/null || true
    systemctl show "$APP_SERVICE" \
        --property=ActiveState,SubState,MainPID,User,Group,FragmentPath,DropInPaths \
        >"${BACKUP_DIR}/vf-service.state"
    docker ps --no-trunc \
        --format 'name={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}} networks={{.Networks}}' \
        >"${BACKUP_DIR}/docker-containers.txt" 2>/dev/null || true
}

verify_backup() {
    tar -tzf "${BACKUP_DIR}/system-configs.tar.gz" >/dev/null
    tar -tzf "${BACKUP_DIR}/application-assets.tar.gz" >/dev/null
    (
        cd "$BACKUP_DIR"
        find . -type f ! -name SHA256SUMS ! -name INCOMPLETE -print0 \
            | sort -z \
            | xargs -0 -r sha256sum >SHA256SUMS
        sha256sum --check --quiet SHA256SUMS
    )
    chmod -R go-rwx "$BACKUP_DIR"
    rm -f "${BACKUP_DIR}/INCOMPLETE"
}

main() {
    require_root
    create_backup_directory
    backup_system_configuration
    backup_database
    backup_application_assets
    capture_release_manifest
    capture_operating_state
    verify_backup
    printf 'backup_status=complete\n'
    printf 'backup_path=%s\n' "$BACKUP_DIR"
    du -sh "$BACKUP_DIR"
}

main "$@"
