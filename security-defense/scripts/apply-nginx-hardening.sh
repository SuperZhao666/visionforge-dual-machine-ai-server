#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly HTTP_CONFIG_SOURCE="${1:-}"
readonly DEFAULT_SITE_SOURCE="${2:-}"
readonly SERVER_SNIPPET_SOURCE="${3:-}"
readonly VF_SITE_SOURCE="${4:-}"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-nginx-$(date -u +%Y%m%dT%H%M%SZ)"

readonly HTTP_CONFIG="/etc/nginx/conf.d/00-security-defense.conf"
readonly DEFAULT_SITE="/etc/nginx/sites-available/00-default-deny"
readonly DEFAULT_SITE_LINK="/etc/nginx/sites-enabled/00-default-deny"
readonly SERVER_SNIPPET="/etc/nginx/snippets/vf-security-server.conf"
readonly VF_SITE="/etc/nginx/sites-available/vf"

require_inputs() {
    local source
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    for source in "$HTTP_CONFIG_SOURCE" "$DEFAULT_SITE_SOURCE" "$SERVER_SNIPPET_SOURCE" "$VF_SITE_SOURCE"; do
        if [[ -z "$source" || ! -f "$source" ]]; then
            printf 'error=missing-config-source\n' >&2
            exit 1
        fi
    done
}

backup_path() {
    local path="$1"
    local name="$2"
    if [[ -e "$path" || -L "$path" ]]; then
        cp -a "$path" "${BACKUP_DIR}/${name}"
        printf 'present\n' >"${BACKUP_DIR}/${name}.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/${name}.state"
    fi
}

restore_path() {
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
    backup_path "$HTTP_CONFIG" http-config
    backup_path "$DEFAULT_SITE" default-site
    backup_path "$DEFAULT_SITE_LINK" default-site-link
    backup_path "$SERVER_SNIPPET" server-snippet
    backup_path "$VF_SITE" vf-site
}

restore_configuration() {
    restore_path "$HTTP_CONFIG" http-config
    restore_path "$DEFAULT_SITE" default-site
    restore_path "$DEFAULT_SITE_LINK" default-site-link
    restore_path "$SERVER_SNIPPET" server-snippet
    restore_path "$VF_SITE" vf-site
    nginx -t && systemctl reload nginx || true
}

install_configuration() {
    install -m 644 -o root -g root "$HTTP_CONFIG_SOURCE" "$HTTP_CONFIG"
    install -m 644 -o root -g root "$DEFAULT_SITE_SOURCE" "$DEFAULT_SITE"
    install -m 644 -o root -g root "$SERVER_SNIPPET_SOURCE" "$SERVER_SNIPPET"
    install -m 644 -o root -g root "$VF_SITE_SOURCE" "$VF_SITE"
    ln -sfn "$DEFAULT_SITE" "$DEFAULT_SITE_LINK"
}

validate_nginx() {
    nginx -t
    systemctl reload nginx
    systemctl is-active --quiet nginx
    curl --fail --silent --show-error --output /dev/null https://www.visionforge.cloud/
}

main() {
    require_inputs
    backup_current_configuration
    trap restore_configuration ERR
    install_configuration
    validate_nginx
    trap - ERR
    printf 'nginx_hardening=applied\n'
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
