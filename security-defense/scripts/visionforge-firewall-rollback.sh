#!/usr/bin/env bash
set -Eeuo pipefail

systemctl disable --now visionforge-docker-firewall.service >/dev/null 2>&1 || true
ufw disable >/dev/null 2>&1 || true
logger --tag visionforge-security "automatic firewall rollback executed"
