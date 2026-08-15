#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-root-account-$(date -u +%Y%m%dT%H%M%SZ)"

if (( EUID != 0 )); then
    printf 'error=run-as-root\n' >&2
    exit 1
fi

install -d -m 700 -o root -g root "$BACKUP_DIR"
cp -a /etc/shadow "$BACKUP_DIR/shadow.before"
cp -a /etc/gshadow "$BACKUP_DIR/gshadow.before"
passwd -S root >"$BACKUP_DIR/root-status.before"

restore_account_files() {
    trap - ERR
    cp -a "$BACKUP_DIR/shadow.before" /etc/shadow
    cp -a "$BACKUP_DIR/gshadow.before" /etc/gshadow
}

trap restore_account_files ERR
passwd --lock root >/dev/null
passwd -S root | grep -E '^root L ' >/dev/null
sshd -T | grep -Fx 'permitrootlogin no' >/dev/null
trap - ERR

printf 'root_account=locked\n'
printf 'rollback_path=%s\n' "$BACKUP_DIR"
