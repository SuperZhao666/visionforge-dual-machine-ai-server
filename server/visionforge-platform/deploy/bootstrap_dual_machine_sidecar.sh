#!/usr/bin/env bash
set -Eeuo pipefail

# First-time, additive deployment for the isolated dual-machine sidecar.
# Run as root and pass the already verified staging directory as the only
# argument. The script deliberately refuses to overwrite an existing install.

if [ "$#" -ne 1 ]; then
  echo "usage: bootstrap_dual_machine_sidecar.sh <verified-staging-directory>"
  exit 2
fi

umask 077

staging="$1"
app_root="/home/ubuntu/vf-platform"
sidecar_source="${staging}/dual_machine_service"
sidecar_target="${app_root}/dual_machine_service"
unit_source="${staging}/deploy/vf-dual-machine.service"
unit_target="/etc/systemd/system/vf-dual-machine.service"
config_dir="/etc/visionforge-dual-machine"
state_dir="/var/lib/visionforge-dual-machine"
service_user="vf-dual-machine"
site_link="/etc/nginx/sites-enabled/vf"
site_target="$(readlink -f "${site_link}")"
rate_conf="/etc/nginx/conf.d/vf-dual-machine-rate.conf"
location_conf="/etc/nginx/snippets/vf-dual-machine-location.conf"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="/var/backups/visionforge-dual-machine/${stamp}"

require_first_install_state() {
  test -d "${sidecar_source}"
  test -f "${unit_source}"
  test -f "${site_target}"
  case "${site_target}" in
    /etc/nginx/*) ;;
    *)
      echo "refusing_unexpected_nginx_target"
      exit 20
      ;;
  esac
  test ! -e "${sidecar_target}"
  test ! -e "${unit_target}"
  test ! -e "${config_dir}/service.env"
  test ! -e "${config_dir}/usage-ticket-private.pem"
  test ! -e "${config_dir}/usage-ticket-public.pem"
  test ! -e "${config_dir}/pair-credential-private.pem"
  test ! -e "${config_dir}/pair-credential-public.pem"
  test ! -e "${state_dir}/vf_dual_machine.db"
  test ! -e "${rate_conf}"
  test ! -e "${location_conf}"
  test "$(grep -c 'vf-dual-machine-location.conf' "${site_target}" || true)" = "0"
  test "$(grep -Ec '^[[:space:]]*include[[:space:]]+/etc/nginx/snippets/vf-code-issuance-internal\.conf;[[:space:]]*$' "${site_target}")" = "1"
  test -z "$(ss -ltnH '( sport = :8010 )')"
}

record_single_machine_baseline() {
  vf_pid_before="$(systemctl show -p MainPID --value vf)"
  vf_state_before="$(systemctl is-active vf)"
  root_http_before="$(
    curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
      https://www.visionforge.cloud/ || true
  )"
  test "${vf_state_before}" = "active"
  test -n "${vf_pid_before}"
  test "${vf_pid_before}" != "0"

  install -d -m 0700 "${backup_dir}"
  cp -a "${site_target}" "${backup_dir}/nginx-vf.before"
  cp -a /etc/systemd/system/vf.service \
    "${backup_dir}/vf.service.before" 2>/dev/null || true
  {
    printf 'created_utc=%s\n' "${stamp}"
    printf 'vf_state_before=%s\n' "${vf_state_before}"
    printf 'vf_pid_before=%s\n' "${vf_pid_before}"
    printf 'root_http_before=%s\n' "${root_http_before}"
    sha256sum "${site_target}"
    systemctl cat vf | sha256sum
  } > "${backup_dir}/predeploy-manifest.txt"
  chmod 0600 "${backup_dir}/predeploy-manifest.txt"
}

install_sidecar_identity_and_code() {
  if ! id -u "${service_user}" >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
      --user-group "${service_user}"
  fi

  install -d -m 0755 "${sidecar_target}"
  cp -a "${sidecar_source}/." "${sidecar_target}/"
  chown -R root:root "${sidecar_target}"
  find "${sidecar_target}" -type d -exec chmod 0755 {} +
  find "${sidecar_target}" -type f -exec chmod 0644 {} +

  install -o root -g root -m 0644 "${unit_source}" "${unit_target}"
  install -d -o "${service_user}" -g "${service_user}" -m 0700 \
    "${config_dir}" "${state_dir}"
}

create_sidecar_secrets() {
  ticket_private_key="${config_dir}/usage-ticket-private.pem"
  ticket_public_key="${config_dir}/usage-ticket-public.pem"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${ticket_private_key}" >/dev/null 2>&1
  openssl pkey -in "${ticket_private_key}" -pubout \
    -out "${ticket_public_key}" >/dev/null 2>&1

  pair_credential_private_key="${config_dir}/pair-credential-private.pem"
  pair_credential_public_key="${config_dir}/pair-credential-public.pem"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${pair_credential_private_key}" >/dev/null 2>&1
  openssl pkey -in "${pair_credential_private_key}" -pubout \
    -out "${pair_credential_public_key}" >/dev/null 2>&1

  chown "${service_user}:${service_user}" \
    "${ticket_private_key}" "${ticket_public_key}" \
    "${pair_credential_private_key}" "${pair_credential_public_key}"
  chmod 0600 \
    "${ticket_private_key}" "${ticket_public_key}" \
    "${pair_credential_private_key}" "${pair_credential_public_key}"

  license_secret="$(openssl rand -hex 32)"
  token_secret="$(openssl rand -hex 32)"
  admin_bridge_secret="$(openssl rand -hex 32)"
  env_tmp="${config_dir}/.service.env.${stamp}"
  {
    printf 'DUAL_MACHINE_BIND_HOST=127.0.0.1\n'
    printf 'DUAL_MACHINE_BIND_PORT=8010\n'
    printf 'DUAL_MACHINE_DATABASE_PATH=/var/lib/visionforge-dual-machine/vf_dual_machine.db\n'
    printf 'DUAL_MACHINE_LICENSE_CODE_SECRET=%s\n' "${license_secret}"
    printf 'DUAL_MACHINE_TOKEN_SECRET=%s\n' "${token_secret}"
    printf 'DUAL_MACHINE_ADMIN_BRIDGE_SECRET=%s\n' "${admin_bridge_secret}"
    printf 'DUAL_MACHINE_ADMIN_BRIDGE_MAX_SKEW_SECONDS=30\n'
    printf 'DUAL_MACHINE_LICENSE_CODE_KEY_VERSION=1\n'
    printf 'DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON={}\n'
    printf 'DUAL_MACHINE_MIN_HOST_CLIENT_VERSION=1.0.0\n'
    printf 'DUAL_MACHINE_MIN_ANDROID_CLIENT_VERSION=1.0.0\n'
    printf 'DUAL_MACHINE_TICKET_PRIVATE_KEY_PATH=/etc/visionforge-dual-machine/usage-ticket-private.pem\n'
    printf 'DUAL_MACHINE_TICKET_PUBLIC_KEY_PATH=/etc/visionforge-dual-machine/usage-ticket-public.pem\n'
    printf 'DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON=[]\n'
    printf 'DUAL_MACHINE_TICKET_PRIVATE_KEY_PASSWORD=\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH=/etc/visionforge-dual-machine/pair-credential-private.pem\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH=/etc/visionforge-dual-machine/pair-credential-public.pem\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON=[]\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON=[]\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PASSWORD=\n'
    printf 'DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS=15\n'
    printf 'DUAL_MACHINE_USAGE_LEASE_TTL_SECONDS=5\n'
    # A successor remains contiguous (nbf=current expiry); this wider window
    # only absorbs WAN/TLS/signing latency before the five-second lease closes.
    printf 'DUAL_MACHINE_USAGE_RENEWAL_WINDOW_SECONDS=4\n'
  } > "${env_tmp}"
  unset license_secret token_secret admin_bridge_secret
  chown "${service_user}:${service_user}" "${env_tmp}"
  chmod 0600 "${env_tmp}"
  mv "${env_tmp}" "${config_dir}/service.env"
}

start_and_verify_loopback_sidecar() {
  systemctl daemon-reload
  systemctl enable vf-dual-machine.service >/dev/null
  systemctl start vf-dual-machine.service

  healthy=0
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 2 http://127.0.0.1:8010/healthz >/dev/null; then
      healthy=1
      break
    fi
    sleep 0.5
  done
  if [ "${healthy}" != "1" ]; then
    systemctl status vf-dual-machine.service --no-pager || true
    journalctl -u vf-dual-machine.service -n 80 --no-pager || true
    echo "sidecar_local_health_failed"
    exit 30
  fi
}

install_nginx_sidecar_route() {
  cat > "${rate_conf}" <<'EOF_RATE'
# Independent dual-machine API limiter in nginx http context.
limit_req_zone $binary_remote_addr zone=vf_dual_machine:10m rate=30r/s;
EOF_RATE
  chmod 0644 "${rate_conf}"
  chown root:root "${rate_conf}"

  cat > "${location_conf}" <<'EOF_LOCATION'
# Dual-machine sidecar only. Host video packets never pass through this API.
location = /api/dual-machine/v1 {
    return 404;
}

location ^~ /api/dual-machine/v1/ {
    client_max_body_size 16k;
    limit_req zone=vf_dual_machine burst=60 nodelay;

    proxy_pass http://127.0.0.1:8010;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Request-ID $request_id;

    proxy_connect_timeout 3s;
    proxy_send_timeout 10s;
    proxy_read_timeout 10s;
}
EOF_LOCATION
  chmod 0644 "${location_conf}"
  chown root:root "${location_conf}"

  site_tmp="${site_target}.vf-dual-machine.${stamp}.tmp"
  python3 - "${site_target}" "${site_tmp}" <<'PY_SITE'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
text = source.read_text(encoding="utf-8")
pattern = re.compile(
    r"^(?P<indent>[ \t]*)include[ \t]+"
    r"/etc/nginx/snippets/vf-code-issuance-internal\.conf;"
    r"[ \t]*$",
    re.MULTILINE,
)
matches = list(pattern.finditer(text))
if len(matches) != 1:
    raise SystemExit("unexpected nginx include marker count")
match = matches[0]
insert = (
    match.group(0)
    + "\n"
    + match.group("indent")
    + "include /etc/nginx/snippets/vf-dual-machine-location.conf;"
)
updated = text[: match.start()] + insert + text[match.end() :]
target.write_text(updated, encoding="utf-8")
PY_SITE
  chown --reference="${site_target}" "${site_tmp}"
  chmod --reference="${site_target}" "${site_tmp}"
  mv "${site_tmp}" "${site_target}"

  if ! nginx -t; then
    cp -a "${backup_dir}/nginx-vf.before" "${site_target}"
    rm -f "${rate_conf}" "${location_conf}"
    nginx -t
    echo "nginx_validation_failed_rolled_back"
    exit 40
  fi
  systemctl reload nginx
}

rollback_nginx_sidecar_route() {
  if [ -f "${backup_dir}/nginx-vf.before" ]; then
    cp -a "${backup_dir}/nginx-vf.before" "${site_target}"
  fi
  rm -f "${rate_conf}" "${location_conf}"
  nginx -t >/dev/null
  systemctl reload nginx
}

verify_final_state() {
  # A graceful Nginx reload briefly leaves old workers accepting connections.
  # Wait for the new location contract instead of treating that handover as a
  # deployment failure.
  public_status="000"
  for _ in $(seq 1 40); do
    public_status="$(
      curl -sS -o "${backup_dir}/public-validation.json" -w '%{http_code}' \
        --max-time 3 -H 'Content-Type: application/json' -d '{}' \
        https://www.visionforge.cloud/api/dual-machine/v1/license-activations/challenges \
        || true
    )"
    if [ "${public_status}" = "422" ]; then
      break
    fi
    sleep 0.25
  done
  public_health_status="$(
    curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
      https://www.visionforge.cloud/api/dual-machine/v1/healthz || true
  )"
  root_http_after="$(
    curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
      https://www.visionforge.cloud/ || true
  )"
  vf_pid_after="$(systemctl show -p MainPID --value vf)"
  vf_state_after="$(systemctl is-active vf)"
  sidecar_state="$(systemctl is-active vf-dual-machine)"
  sidecar_enabled="$(systemctl is-enabled vf-dual-machine)"
  nginx_state="$(systemctl is-active nginx)"

  test "${public_status}" = "422"
  test "${public_health_status}" = "404"
  test "${vf_state_after}" = "active"
  test "${vf_pid_after}" = "${vf_pid_before}"
  test "${sidecar_state}" = "active"
  test "${sidecar_enabled}" = "enabled"
  test "${nginx_state}" = "active"
  test "${root_http_after}" = "${root_http_before}"
  test "$(grep -c 'vf-dual-machine-location.conf' "${site_target}")" = "1"
  test ! -L "${state_dir}/vf_dual_machine.db"
  test "$(readlink -f "${state_dir}/vf_dual_machine.db")" = \
    "${state_dir}/vf_dual_machine.db"
  ss -ltnH '( sport = :8010 )' | grep -Eq '127\.0\.0\.1:8010[[:space:]]'

  python3 - "${state_dir}/vf_dual_machine.db" <<'PY_DB'
import sqlite3
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
if path.name.casefold() == "vf.db":
    raise SystemExit("single-machine database name rejected")
connection = sqlite3.connect(str(path))
try:
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    tables = [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    ]
finally:
    connection.close()
if integrity != "ok":
    raise SystemExit("sidecar database integrity failed")
bad = [name for name in tables if not name.startswith(("dm_", "sqlite_"))]
if bad:
    raise SystemExit("non-sidecar tables detected")
if not tables:
    raise SystemExit("sidecar schema missing")
print("sidecar_db_integrity=ok")
print("sidecar_table_count=" + str(len(tables)))
PY_DB

  rm -f "${backup_dir}/public-validation.json"
  {
    printf 'vf_state_after=%s\n' "${vf_state_after}"
    printf 'vf_pid_after=%s\n' "${vf_pid_after}"
    printf 'sidecar_state=%s\n' "${sidecar_state}"
    printf 'sidecar_enabled=%s\n' "${sidecar_enabled}"
    printf 'nginx_state=%s\n' "${nginx_state}"
    printf 'public_validation_status=%s\n' "${public_status}"
    printf 'public_sidecar_health_status=%s\n' "${public_health_status}"
    printf 'root_http_after=%s\n' "${root_http_after}"
    sha256sum "${site_target}"
    sha256sum "${unit_target}"
    sha256sum "${ticket_public_key}"
    sha256sum "${pair_credential_public_key}"
  } > "${backup_dir}/postdeploy-manifest.txt"
  chmod 0600 "${backup_dir}/postdeploy-manifest.txt"

  echo "deployment_status=ok"
  echo "backup_dir=${backup_dir}"
  echo "vf_pid_unchanged=${vf_pid_after}"
  echo "sidecar_state=${sidecar_state}"
  echo "sidecar_enabled=${sidecar_enabled}"
  echo "public_validation_status=${public_status}"
  echo "public_sidecar_health_status=${public_health_status}"
  echo "original_root_status=${root_http_after}"
  echo "nginx_state=${nginx_state}"
}

deploy_nginx_and_verify() {
  routing_committed=0
  trap 'if [ "${routing_committed}" != "1" ]; then rollback_nginx_sidecar_route; fi' EXIT
  install_nginx_sidecar_route
  verify_final_state
  routing_committed=1
  trap - EXIT
}

resume_routing_after_verified_sidecar() {
  backup_dir="${VF_DUAL_MACHINE_BACKUP_DIR:?backup directory is required}"
  test -f "${backup_dir}/predeploy-manifest.txt"
  test -f "${backup_dir}/nginx-vf.before"
  test -d "${sidecar_target}"
  test -f "${unit_target}"
  test -f "${config_dir}/service.env"
  test -f "${state_dir}/vf_dual_machine.db"
  test "$(systemctl is-active vf-dual-machine.service)" = "active"
  curl -fsS --max-time 2 http://127.0.0.1:8010/healthz >/dev/null

  vf_pid_before="$(
    sed -n 's/^vf_pid_before=//p' "${backup_dir}/predeploy-manifest.txt"
  )"
  root_http_before="$(
    sed -n 's/^root_http_before=//p' "${backup_dir}/predeploy-manifest.txt"
  )"
  ticket_public_key="${config_dir}/usage-ticket-public.pem"
  pair_credential_public_key="${config_dir}/pair-credential-public.pem"
  test -f "${ticket_public_key}"
  test -f "${pair_credential_public_key}"
  test -n "${vf_pid_before}"
  test -n "${root_http_before}"
  test "$(systemctl show -p MainPID --value vf)" = "${vf_pid_before}"
  deploy_nginx_and_verify
}

case "${VF_DUAL_MACHINE_DEPLOY_PHASE:-bootstrap}" in
  bootstrap)
    require_first_install_state
    record_single_machine_baseline
    install_sidecar_identity_and_code
    create_sidecar_secrets
    start_and_verify_loopback_sidecar
    deploy_nginx_and_verify
    ;;
  resume-routing)
    resume_routing_after_verified_sidecar
    ;;
  *)
    echo "unsupported deployment phase"
    exit 3
    ;;
esac
