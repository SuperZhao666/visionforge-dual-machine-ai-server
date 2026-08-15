#!/bin/bash
set -euo pipefail

APP_ROOT="${VF_APP_ROOT:-/home/ubuntu/vf-platform}"
NGINX_SOURCE="${VF_NGINX_SITE_CONFIG:-${APP_ROOT}/deploy/nginx.conf}"
NGINX_SITE="/etc/nginx/sites-available/vf"
NGINX_LINK="/etc/nginx/sites-enabled/vf"
CERT_ROOT="/etc/letsencrypt/live/visionforge.cloud"

require_file() {
    if [[ ! -f "$1" ]]; then
        echo "Required file is missing: $1" >&2
        exit 1
    fi
}

require_file "${APP_ROOT}/deploy/vf.service"
require_file "${APP_ROOT}/deploy/validate_single_server_env.py"
require_file "${APP_ROOT}/venv/bin/python"
require_file "${NGINX_SOURCE}"
require_file "${CERT_ROOT}/fullchain.pem"
require_file "${CERT_ROOT}/privkey.pem"
command -v nginx >/dev/null
command -v curl >/dev/null

"${APP_ROOT}/venv/bin/python" \
    "${APP_ROOT}/deploy/validate_single_server_env.py" \
    "${APP_ROOT}/.env"

wait_for_url() {
    local attempt
    for attempt in {1..20}; do
        if curl --fail --silent --show-error "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

echo "=== Systemd ==="
sudo install -m 0644 "${APP_ROOT}/deploy/vf.service" /etc/systemd/system/vf.service
sudo systemctl daemon-reload
sudo systemctl enable vf
sudo systemctl restart vf
wait_for_url http://127.0.0.1:8000/
echo "Application loopback check OK"

echo "=== Nginx ==="
backup=""
if sudo test -e "${NGINX_SITE}"; then
    backup="${NGINX_SITE}.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    sudo cp --preserve=mode,ownership,timestamps "${NGINX_SITE}" "${backup}"
fi

sudo install -m 0644 "${NGINX_SOURCE}" "${NGINX_SITE}.new"
sudo mv "${NGINX_SITE}.new" "${NGINX_SITE}"
sudo ln -sfn "${NGINX_SITE}" "${NGINX_LINK}"

restore_nginx() {
    echo "Restoring the previous Nginx site." >&2
    if [[ -n "${backup}" ]]; then
        sudo cp --preserve=mode,ownership,timestamps "${backup}" "${NGINX_SITE}"
        sudo ln -sfn "${NGINX_SITE}" "${NGINX_LINK}"
    else
        sudo rm -f "${NGINX_SITE}" "${NGINX_LINK}"
    fi
    sudo nginx -t && sudo systemctl reload nginx || true
}

if ! sudo nginx -t; then
    echo "Nginx validation failed." >&2
    restore_nginx
    exit 1
fi

if ! sudo systemctl reload nginx; then
    restore_nginx
    exit 1
fi
if ! wait_for_url \
    --resolve www.visionforge.cloud:443:127.0.0.1 \
    https://www.visionforge.cloud/; then
    echo "HTTPS loopback check failed." >&2
    restore_nginx
    exit 1
fi
echo "HTTPS loopback check OK"

echo "=== Firewall ==="
sudo ufw --force allow 80/tcp
sudo ufw --force allow 443/tcp
sudo ufw --force allow 22/tcp

echo "=== DONE ==="
echo "Open: https://www.visionforge.cloud"
echo "Release storage: ${APP_ROOT}/app/static/releases"
