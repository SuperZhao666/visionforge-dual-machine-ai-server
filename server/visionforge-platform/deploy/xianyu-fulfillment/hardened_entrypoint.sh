#!/usr/bin/env bash
set -euo pipefail
umask 077

is_placeholder() {
  local lowered="${1,,}"
  [[ "${lowered}" == *"replace-with"* \
    || "${lowered}" == *"replace_with"* \
    || "${lowered}" == *"placeholder"* \
    || "${lowered}" == *"change-me"* \
    || "${lowered}" == *"changeme"* \
    || "${lowered}" == "admin123" ]]
}

require_secret() {
  local name="$1"
  local minimum_length="$2"
  local error_message="${3:-${name} is missing, too short, or still a placeholder}"
  local value="${!name:-}"
  if [[ ${#value} -lt ${minimum_length} ]] || is_placeholder "${value}"; then
    echo "${error_message}" >&2
    exit 1
  fi
}

if [[ "${ADMIN_USERNAME:-}" != "admin" ]]; then
  echo "ADMIN_USERNAME must be admin for this pinned upstream version" >&2
  exit 1
fi
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
if [[ "${ADMIN_PASSWORD}" == "admin123" ]]; then
  echo "ADMIN_PASSWORD must not use the upstream default" >&2
  exit 1
fi
require_secret ADMIN_PASSWORD 20
require_secret JWT_SECRET_KEY 32 "JWT_SECRET_KEY must be at least 32 characters and not a placeholder"
require_secret BRIDGE_INTERNAL_TOKEN 32

case "${VISIONFORGE_MANAGED_FULFILLMENT_MODE:-shadow}" in
  off|shadow|live) ;;
  *)
    echo "VISIONFORGE_MANAGED_FULFILLMENT_MODE is invalid" >&2
    exit 1
    ;;
esac
if [[ "${AUTO_DELIVERY_ENABLED:-false}" != "false" ]]; then
  echo "generic AUTO_DELIVERY_ENABLED must remain false" >&2
  exit 1
fi

required_directories=(
  /app/data
  /app/logs
  /app/backups
  /app/static/uploads/images
  /app/trajectory_history
  /home/visionforge/.cache
)
for directory in "${required_directories[@]}"; do
  mkdir -p "$directory"
  if [[ ! -w "$directory" ]]; then
    echo "runtime directory is not writable: $directory" >&2
    exit 1
  fi
done

if [[ "${USE_XVFB:-false}" == "true" || "${ENABLE_HEADFUL:-false}" == "true" ]]; then
  xvfb_started=false
  for display_number in $(seq 99 108); do
    export DISPLAY=":${display_number}"
    Xvfb "$DISPLAY" -screen 0 1920x1080x24 -ac +extension GLX +render -noreset >/tmp/xvfb.log 2>&1 &
    xvfb_pid=$!
    sleep 1
    if kill -0 "$xvfb_pid" 2>/dev/null; then
      xvfb_started=true
      break
    fi
  done
  if [[ "$xvfb_started" != "true" ]]; then
    echo "Xvfb failed to start" >&2
    exit 1
  fi
  if command -v fluxbox >/dev/null 2>&1; then
    fluxbox >/tmp/fluxbox.log 2>&1 &
  fi
fi

exec python Start.py
