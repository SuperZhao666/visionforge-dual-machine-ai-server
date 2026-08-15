#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENV_FILE="${DEPLOY_DIR}/.env"
readonly DATABASE_PATH="${DEPLOY_DIR}/runtime/data/xianyu_data.db"
readonly BACKUP_DIRECTORY="${DEPLOY_DIR}/runtime/backups"
readonly SNAPSHOT_TOOL="${DEPLOY_DIR}/sqlite_snapshot.py"
readonly PREFLIGHT_TOOL="${DEPLOY_DIR}/preflight_xianyu_host.py"
readonly APP_CONTAINER="visionforge-xianyu-fulfillment"
readonly BRIDGE_CONTAINER="visionforge-fulfillment-bridge"
readonly IMAGE_REFERENCE="${1:-visionforge/xianyu-auto-reply:837497d576b1-hardened}"

IMAGE_ID=""
PREVIOUS_IMAGE_ID=""
PREVIOUS_APP_RUNNING=false
PREVIOUS_BRIDGE_RUNNING=false
DATABASE_EXISTED=false
DATABASE_SNAPSHOT_READY=false
DATABASE_OWNER=""
DATABASE_MODE=""
CANDIDATE_STARTED=false
ROLLBACK_REQUIRED=false
ENV_SNAPSHOT=""
ENV_CANDIDATE=""
DATABASE_SNAPSHOT=""
PRIVILEGED_COMMAND=()

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command is unavailable: $1" >&2
    exit 1
  fi
}

get_env_value() {
  local key="$1"
  awk -F= -v key="${key}" '
    $0 ~ "^" key "=" { value = substr($0, index($0, "=") + 1) }
    END { print value }
  ' "${ENV_FILE}"
}

unquote_env_value() {
  local value="$1"
  local first_character="${value:0:1}"
  local last_character="${value: -1}"
  if [[ ( "${first_character}" == "'" && "${last_character}" == "'" ) \
    || ( "${first_character}" == '"' && "${last_character}" == '"' ) ]]; then
    printf '%s' "${value:1:-1}"
    return
  fi
  printf '%s' "${value}"
}

is_placeholder() {
  local lowered="${1,,}"
  [[ "${lowered}" == *"replace-with"* \
    || "${lowered}" == *"replace_with"* \
    || "${lowered}" == *"placeholder"* \
    || "${lowered}" == *"change-me"* \
    || "${lowered}" == *"changeme"* \
    || "${lowered}" == "admin123" ]]
}

require_env_value() {
  local name="$1"
  local minimum_length="$2"
  local value
  value="$(get_env_value "${name}")"
  if [[ ${#value} -lt ${minimum_length} ]] || is_placeholder "${value}"; then
    echo "${name} is missing, too short, or still a placeholder" >&2
    exit 1
  fi
}

container_is_running() {
  [[ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || printf 'false')" == "true" ]]
}

container_health() {
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null \
    || printf 'missing'
}

wait_for_healthy() {
  local container_name="$1"
  local attempts="${2:-60}"
  local state=""
  for _ in $(seq 1 "${attempts}"); do
    state="$(container_health "${container_name}")"
    if [[ "${state}" == "healthy" ]]; then
      return 0
    fi
    if [[ "${state}" == "missing" ]]; then
      break
    fi
    sleep 2
  done
  echo "container did not become healthy: ${container_name} state=${state}" >&2
  return 1
}

stop_container() {
  local container_name="$1"
  local running_state=""
  if ! docker container inspect "${container_name}" >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      echo "Docker became unavailable while stopping ${container_name}" >&2
      return 1
    fi
    return 0
  fi
  if ! running_state="$(docker inspect --format '{{.State.Running}}' "${container_name}")"; then
    return 1
  fi
  if [[ "${running_state}" == "true" ]] \
    && ! docker stop --time 30 "${container_name}" >/dev/null; then
    return 1
  fi
  if ! running_state="$(docker inspect --format '{{.State.Running}}' "${container_name}")"; then
    return 1
  fi
  if [[ "${running_state}" == "true" ]]; then
    echo "container is still running after stop: ${container_name}" >&2
    return 1
  fi
  return 0
}

run_privileged() {
  "${PRIVILEGED_COMMAND[@]}" "$@"
}

verify_database_if_present() {
  if run_privileged test -f "${DATABASE_PATH}"; then
    run_privileged python3 "${SNAPSHOT_TOOL}" verify --database "${DATABASE_PATH}" >/dev/null
    return
  fi
  if [[ "${DATABASE_EXISTED}" == "true" ]]; then
    echo "expected Xianyu database is missing" >&2
    return 1
  fi
  return 0
}

restore_database_state() {
  if [[ "${DATABASE_EXISTED}" == "true" ]]; then
    if [[ "${DATABASE_SNAPSHOT_READY}" == "true" ]]; then
      if ! run_privileged python3 "${SNAPSHOT_TOOL}" restore \
        --snapshot "${DATABASE_SNAPSHOT}" \
        --destination "${DATABASE_PATH}" >/dev/null; then
        return 1
      fi
      if ! run_privileged chown "${DATABASE_OWNER}" "${DATABASE_PATH}"; then
        return 1
      fi
      if ! run_privileged chmod "${DATABASE_MODE}" "${DATABASE_PATH}"; then
        return 1
      fi
    else
      if ! run_privileged test -f "${DATABASE_PATH}"; then
        echo "original database disappeared before a snapshot was available" >&2
        return 1
      fi
      if ! verify_database_if_present; then
        return 1
      fi
    fi
    return
  fi

  if [[ "${CANDIDATE_STARTED}" != "true" ]]; then
    return
  fi

  local resolved_data_directory
  resolved_data_directory="$(run_privileged realpath "${DEPLOY_DIR}/runtime/data")"
  if [[ "${resolved_data_directory}" != "${DEPLOY_DIR}/runtime/data" ]]; then
    echo "refusing to remove a database outside runtime/data" >&2
    return 1
  fi
  run_privileged rm -f -- \
    "${DATABASE_PATH}" \
    "${DATABASE_PATH}-wal" \
    "${DATABASE_PATH}-shm"
}

restore_previous_runtime() {
  local rollback_failed=false

  if ! docker info >/dev/null 2>&1; then
    echo "Docker is unavailable; automated rollback cannot stop the candidate safely" >&2
    return 1
  fi
  if ! stop_container "${APP_CONTAINER}"; then
    rollback_failed=true
  fi
  if ! stop_container "${BRIDGE_CONTAINER}"; then
    rollback_failed=true
  fi
  if [[ "${rollback_failed}" == "false" ]] && ! restore_database_state; then
    echo "database rollback failed" >&2
    rollback_failed=true
  fi
  if ! cp -p -- "${ENV_SNAPSHOT}" "${ENV_FILE}"; then
    echo "environment rollback failed" >&2
    rollback_failed=true
  elif ! cmp -s -- "${ENV_SNAPSHOT}" "${ENV_FILE}"; then
    echo "restored environment does not match the original" >&2
    rollback_failed=true
  fi

  if [[ "${rollback_failed}" == "false" ]]; then
    if ! (
      cd "${DEPLOY_DIR}"
      docker compose --env-file "${ENV_FILE}" --profile live create --force-recreate \
        fulfillment-bridge xianyu-app >/dev/null
    ); then
      echo "previous fulfillment image definitions failed to restore" >&2
      rollback_failed=true
    fi
  fi

  if [[ "${rollback_failed}" == "false" ]]; then
    if [[ "${PREVIOUS_APP_RUNNING}" == "true" ]]; then
      if ! (
        cd "${DEPLOY_DIR}"
        docker compose --env-file "${ENV_FILE}" --profile live up -d --force-recreate \
          fulfillment-bridge xianyu-app >/dev/null
      ); then
        echo "previous fulfillment stack failed to restart" >&2
        rollback_failed=true
      elif ! wait_for_healthy "${BRIDGE_CONTAINER}" 60 \
        || ! wait_for_healthy "${APP_CONTAINER}" 60; then
        rollback_failed=true
      elif [[ "$(docker inspect --format '{{.Image}}' "${APP_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" \
        || "$(docker inspect --format '{{.Image}}' "${BRIDGE_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" ]]; then
        echo "rollback restarted an unexpected image" >&2
        rollback_failed=true
      fi
    elif [[ "${PREVIOUS_BRIDGE_RUNNING}" == "true" ]]; then
      if ! (
        cd "${DEPLOY_DIR}"
        docker compose --env-file "${ENV_FILE}" --profile live up -d --force-recreate \
          fulfillment-bridge >/dev/null
      ); then
        echo "previous fulfillment bridge failed to restart" >&2
        rollback_failed=true
      elif ! wait_for_healthy "${BRIDGE_CONTAINER}" 60; then
        rollback_failed=true
      elif [[ "$(docker inspect --format '{{.Image}}' "${BRIDGE_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" ]]; then
        echo "rollback restarted an unexpected bridge image" >&2
        rollback_failed=true
      elif [[ "$(docker inspect --format '{{.Image}}' "${APP_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" ]]; then
        echo "rollback restored an unexpected stopped application image" >&2
        rollback_failed=true
      fi
    elif ! docker info >/dev/null 2>&1; then
      echo "Docker became unavailable while verifying the stopped prior state" >&2
      rollback_failed=true
    elif container_is_running "${APP_CONTAINER}" || container_is_running "${BRIDGE_CONTAINER}"; then
      echo "rollback restarted a service that was previously stopped" >&2
      rollback_failed=true
    elif [[ "$(docker inspect --format '{{.Image}}' "${APP_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" \
      || "$(docker inspect --format '{{.Image}}' "${BRIDGE_CONTAINER}")" != "${PREVIOUS_IMAGE_ID}" ]]; then
      echo "rollback restored an unexpected stopped image" >&2
      rollback_failed=true
    fi
  fi

  if [[ "${rollback_failed}" == "false" ]] && ! verify_database_if_present; then
    echo "restored database verification failed" >&2
    rollback_failed=true
  fi
  [[ "${rollback_failed}" == "false" ]]
}

cleanup() {
  local original_exit_code=$?
  local rollback_exit_code=0
  local cleanup_exit_code=0
  trap - EXIT INT TERM
  set +e

  if [[ ${original_exit_code} -ne 0 && "${ROLLBACK_REQUIRED}" == "true" ]]; then
    if restore_previous_runtime; then
      echo "activation_failed_rollback=verified" >&2
    else
      rollback_exit_code=2
      echo "activation_failed_rollback=failed" >&2
      if [[ -n "${ENV_SNAPSHOT}" && -f "${ENV_SNAPSHOT}" ]]; then
        echo "rollback_environment_snapshot=retained_for_manual_recovery" >&2
      fi
    fi
  fi

  if [[ ${rollback_exit_code} -eq 0 && -n "${ENV_SNAPSHOT}" ]] \
    && ! rm -f -- "${ENV_SNAPSHOT}"; then
    cleanup_exit_code=3
    echo "activation_cleanup=failed_to_remove_environment_snapshot" >&2
  fi
  if [[ -n "${ENV_CANDIDATE}" ]] && ! rm -f -- "${ENV_CANDIDATE}"; then
    cleanup_exit_code=3
    echo "activation_cleanup=failed_to_remove_candidate_environment" >&2
  fi

  if [[ ${rollback_exit_code} -ne 0 ]]; then
    exit "${rollback_exit_code}"
  fi
  if [[ ${cleanup_exit_code} -ne 0 ]]; then
    exit "${cleanup_exit_code}"
  fi
  exit "${original_exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command_name in awk chmod chown cmp cp date docker grep id mktemp mv python3 realpath rm seq stat; do
  require_command "${command_name}"
done
if [[ ! -f "${ENV_FILE}" || -L "${ENV_FILE}" ]]; then
  echo ".env must be a regular non-symlink file" >&2
  exit 1
fi
environment_mode="$(stat -c '%a' "${ENV_FILE}")"
if (( (8#${environment_mode} & 8#077) != 0 )); then
  echo ".env must not be readable or writable by group or other users" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "Docker Engine and Docker Compose must be available" >&2
  exit 1
fi

require_env_value XIANYU_IMAGE 8
require_env_value XIANYU_PROVIDER_ACCOUNT 3
require_env_value XIANYU_ADMIN_PASSWORD 20
require_env_value XIANYU_JWT_SECRET 32
require_env_value BRIDGE_INTERNAL_TOKEN 32
require_env_value CODE_ISSUANCE_HMAC_SECRET 32
require_env_value CODE_ISSUANCE_SERVICE_ID 3
require_env_value PLATFORM_HOSTNAME 3
require_env_value PLATFORM_CODE_ISSUANCE_URL 20
require_env_value VISIONFORGE_MANAGED_BRIDGE_URL 20
require_env_value VISIONFORGE_PACKAGE_PRODUCT_KEYS 20

if [[ "$(get_env_value XIANYU_ADMIN_USERNAME)" != "admin" ]]; then
  echo "XIANYU_ADMIN_USERNAME must be admin for the pinned upstream" >&2
  exit 1
fi
admin_port="$(get_env_value XIANYU_ADMIN_PORT)"
admin_port="${admin_port:-6202}"
platform_hostname="$(get_env_value PLATFORM_HOSTNAME)"
platform_url="$(get_env_value PLATFORM_CODE_ISSUANCE_URL)"
managed_bridge_url="$(get_env_value VISIONFORGE_MANAGED_BRIDGE_URL)"
product_keys_json="$(unquote_env_value "$(get_env_value VISIONFORGE_PACKAGE_PRODUCT_KEYS)")"

IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE_REFERENCE}")"
previous_image_reference="$(get_env_value XIANYU_IMAGE)"
if [[ "${previous_image_reference}" != sha256:* ]]; then
  echo "XIANYU_IMAGE must be an immutable local sha256 image id" >&2
  exit 1
fi
PREVIOUS_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${previous_image_reference}")"

if container_is_running "${APP_CONTAINER}"; then
  PREVIOUS_APP_RUNNING=true
fi
if container_is_running "${BRIDGE_CONTAINER}"; then
  PREVIOUS_BRIDGE_RUNNING=true
fi
if [[ "${PREVIOUS_APP_RUNNING}" == "true" && "${PREVIOUS_BRIDGE_RUNNING}" != "true" ]]; then
  echo "existing Xianyu writer is running without its bridge" >&2
  exit 1
fi
if [[ "${PREVIOUS_APP_RUNNING}" == "true" ]]; then
  test "$(container_health "${APP_CONTAINER}")" = "healthy"
  test "$(container_health "${BRIDGE_CONTAINER}")" = "healthy"
  test "$(docker inspect --format '{{.Image}}' "${APP_CONTAINER}")" = "${PREVIOUS_IMAGE_ID}"
  test "$(docker inspect --format '{{.Image}}' "${BRIDGE_CONTAINER}")" = "${PREVIOUS_IMAGE_ID}"
elif [[ "${PREVIOUS_BRIDGE_RUNNING}" == "true" ]]; then
  test "$(container_health "${BRIDGE_CONTAINER}")" = "healthy"
  test "$(docker inspect --format '{{.Image}}' "${BRIDGE_CONTAINER}")" = "${PREVIOUS_IMAGE_ID}"
fi

if [[ -w "${DEPLOY_DIR}/runtime/data" && -w "${BACKUP_DIRECTORY}" ]]; then
  PRIVILEGED_COMMAND=()
elif [[ "$(id -u)" == "0" ]]; then
  PRIVILEGED_COMMAND=()
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  PRIVILEGED_COMMAND=(sudo -n)
else
  echo "runtime backup requires root or non-interactive sudo access" >&2
  exit 1
fi

run_privileged python3 "${PREFLIGHT_TOOL}" \
  --deploy-directory "${DEPLOY_DIR}" \
  --admin-port "${admin_port}" \
  --platform-url "${platform_url}" \
  --platform-hostname "${platform_hostname}" \
  --managed-bridge-url "${managed_bridge_url}" \
  --product-keys-json "${product_keys_json}"
(
  cd "${DEPLOY_DIR}"
  docker compose --env-file "${ENV_FILE}" --profile live config --quiet
)

ENV_SNAPSHOT="$(mktemp "${DEPLOY_DIR}/.env.rollback.XXXXXX")"
cp -p -- "${ENV_FILE}" "${ENV_SNAPSHOT}"
chmod 600 "${ENV_SNAPSHOT}"
ROLLBACK_REQUIRED=true

if [[ "${PREVIOUS_APP_RUNNING}" == "true" ]]; then
  stop_container "${APP_CONTAINER}"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
DATABASE_SNAPSHOT="${BACKUP_DIRECTORY}/xianyu-pre-activation-${timestamp}-$$.db"
if run_privileged test -f "${DATABASE_PATH}"; then
  if run_privileged test -L "${DATABASE_PATH}"; then
    echo "refusing to back up a symlinked Xianyu database" >&2
    exit 1
  fi
  DATABASE_EXISTED=true
  DATABASE_OWNER="$(run_privileged stat -c '%u:%g' "${DATABASE_PATH}")"
  DATABASE_MODE="$(run_privileged stat -c '%a' "${DATABASE_PATH}")"
  run_privileged python3 "${SNAPSHOT_TOOL}" backup \
    --source "${DATABASE_PATH}" \
    --destination "${DATABASE_SNAPSHOT}" >/dev/null
  DATABASE_SNAPSHOT_READY=true
  echo "pre_activation_database_backup=verified"
else
  if run_privileged test -e "${DATABASE_PATH}-wal" \
    || run_privileged test -e "${DATABASE_PATH}-shm"; then
    echo "orphan SQLite WAL/SHM files block safe activation" >&2
    exit 1
  fi
  echo "pre_activation_database_backup=fresh_database"
fi

ENV_CANDIDATE="$(mktemp "${DEPLOY_DIR}/.env.candidate.XXXXXX")"
awk -v image_id="${IMAGE_ID}" '
  BEGIN { image = mode = delivery = 0 }
  /^XIANYU_IMAGE=/ {
    print "XIANYU_IMAGE=" image_id
    image = 1
    next
  }
  /^VISIONFORGE_MANAGED_FULFILLMENT_MODE=/ {
    print "VISIONFORGE_MANAGED_FULFILLMENT_MODE=shadow"
    mode = 1
    next
  }
  /^XIANYU_AUTO_DELIVERY_ENABLED=/ {
    print "XIANYU_AUTO_DELIVERY_ENABLED=false"
    delivery = 1
    next
  }
  { print }
  END {
    if (!image) print "XIANYU_IMAGE=" image_id
    if (!mode) print "VISIONFORGE_MANAGED_FULFILLMENT_MODE=shadow"
    if (!delivery) print "XIANYU_AUTO_DELIVERY_ENABLED=false"
  }
' "${ENV_FILE}" >"${ENV_CANDIDATE}"
chmod 600 "${ENV_CANDIDATE}"
mv -- "${ENV_CANDIDATE}" "${ENV_FILE}"
ENV_CANDIDATE=""

cd "${DEPLOY_DIR}"
CANDIDATE_STARTED=true
docker compose --env-file "${ENV_FILE}" --profile live up -d --force-recreate >/dev/null
wait_for_healthy "${BRIDGE_CONTAINER}" 60
wait_for_healthy "${APP_CONTAINER}" 60

docker exec "${APP_CONTAINER}" python -c \
  'import os; assert os.environ.get("VISIONFORGE_MANAGED_FULFILLMENT_MODE") == "shadow"; assert os.environ.get("AUTO_DELIVERY_ENABLED") == "false"'
if docker inspect --format '{{range .Mounts}}{{println .Destination}}{{end}}' "${BRIDGE_CONTAINER}" \
  | grep -Eq '^/opt/visionforge($|/)'; then
  echo "immutable bridge path must not be shadowed by a host mount" >&2
  exit 1
fi
test "$(docker inspect --format '{{json .Config.Entrypoint}}' "${BRIDGE_CONTAINER}")" \
  = '["python","/opt/visionforge/bridge.py"]'
docker exec "${BRIDGE_CONTAINER}" python -c \
  'from pathlib import Path; path = Path("/opt/visionforge/bridge.py"); assert path.is_file(); assert "VisionForgeCodeIssuanceBridge/2" in path.read_text(encoding="utf-8")'
docker exec "${APP_CONTAINER}" grep -q "visionforge-redacted-sql-parameters" /app/db_manager.py
docker exec "${APP_CONTAINER}" grep -q "visionforge-redacted-card-update-log" /app/db_manager.py
docker exec "${APP_CONTAINER}" \
  grep -qF "VISIONFORGE_GENERIC_AUTO_DELIVERY_RUNTIME_GUARD_V1" /app/XianyuAutoAsync.py
docker exec "${APP_CONTAINER}" \
  grep -qF "is_generic_auto_delivery_enabled" \
  /app/infrastructure/visionforge_fulfillment_config.py
if docker exec "${APP_CONTAINER}" grep -qF "formatted_params.append(repr(param))" /app/db_manager.py; then
  echo "unsafe SQL parameter logging remains" >&2
  exit 1
fi
docker exec -i "${APP_CONTAINER}" python - --mode runtime \
  < "${DEPLOY_DIR}/verify_xianyu_state.py"

ROLLBACK_REQUIRED=false
echo "hardened_image_activation=ok"
echo "candidate_managed_mode=shadow"
echo "candidate_generic_auto_delivery=false"
echo "generic_auto_delivery_runtime_guard=verified"
echo "database_parameter_logging=redacted"
echo "fulfillment_containers=healthy"
