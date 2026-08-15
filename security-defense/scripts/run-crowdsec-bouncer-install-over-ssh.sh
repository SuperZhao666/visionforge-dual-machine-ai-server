#!/usr/bin/env bash
set -Eeuo pipefail

readonly INSTALLER_PATH="${1:-}"
readonly PACKAGE_PATH="${2:-/var/cache/visionforge-security/crowdsec/crowdsec-firewall-bouncer-nftables_0.0.34_amd64.deb}"

if (( EUID == 0 )); then
    printf 'error=run-wrapper-as-ssh-user\n' >&2
    exit 1
fi
if [[ -z "${SSH_CONNECTION:-}" ]]; then
    printf 'error=missing-ssh-connection-context\n' >&2
    exit 1
fi
if [[ -z "$INSTALLER_PATH" || ! -f "$INSTALLER_PATH" ]]; then
    printf 'error=missing-installer\n' >&2
    exit 1
fi

admin_ip="${SSH_CONNECTION%% *}"
[[ -n "$admin_ip" ]]
printf '%s\n' "$admin_ip" | sudo -n bash "$INSTALLER_PATH" "$PACKAGE_PATH"
