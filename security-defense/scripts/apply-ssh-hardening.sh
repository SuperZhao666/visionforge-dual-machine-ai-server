#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly SSH_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SECURITY_CONFIG="${SSH_DROPIN_DIR}/00-visionforge-security.conf"
readonly CRYPTO_CONFIG="${SSH_DROPIN_DIR}/05-visionforge-crypto.conf"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-ssh-$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SECURITY_CONFIG_SOURCE="${1:-}"
readonly CRYPTO_CONFIG_SOURCE="${2:-${SCRIPT_DIR}/../config/ssh/05-visionforge-crypto.conf}"

require_config_source() {
    local source_path="$1"
    local error_code="$2"
    if [[ -z "$source_path" || ! -f "$source_path" ]]; then
        printf 'error=%s path=%s\n' "$error_code" "$source_path" >&2
        exit 1
    fi
}

require_inputs() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    require_config_source "$SECURITY_CONFIG_SOURCE" missing-config-source
    require_config_source "$CRYPTO_CONFIG_SOURCE" missing-crypto-config-source
    if [[ ! -s /home/ubuntu/.ssh/authorized_keys ]]; then
        printf 'error=ubuntu-authorized-key-missing\n' >&2
        exit 1
    fi
    assert_managed_path_supported "$SECURITY_CONFIG"
    assert_managed_path_supported "$CRYPTO_CONFIG"
}

assert_managed_path_supported() {
    local managed_path="$1"
    if [[ -e "$managed_path" && ! -f "$managed_path" && ! -L "$managed_path" ]]; then
        printf 'error=unsupported-managed-config-type path=%s\n' "$managed_path" >&2
        exit 1
    fi
}

backup_managed_config() {
    local managed_path="$1"
    local backup_name="$2"
    if [[ -e "$managed_path" || -L "$managed_path" ]]; then
        cp -a -- "$managed_path" "${BACKUP_DIR}/${backup_name}"
        printf 'present\n' >"${BACKUP_DIR}/${backup_name}.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/${backup_name}.state"
    fi
}

backup_current_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    backup_managed_config "$SECURITY_CONFIG" security-config
    backup_managed_config "$CRYPTO_CONFIG" crypto-config
}

restore_managed_config() {
    local managed_path="$1"
    local backup_name="$2"
    local restore_status=0
    local state
    if ! state="$(<"${BACKUP_DIR}/${backup_name}.state")"; then
        printf 'error=missing-rollback-state path=%s\n' \
            "${BACKUP_DIR}/${backup_name}.state" >&2
        return 1
    fi
    case "$state" in
        present)
            rm -f -- "$managed_path" || restore_status=1
            if (( restore_status == 0 )); then
                cp -a -- "${BACKUP_DIR}/${backup_name}" "$managed_path" || restore_status=1
            fi
            ;;
        absent)
            rm -f -- "$managed_path" || restore_status=1
            ;;
        *)
            printf 'error=invalid-rollback-state path=%s state=%s\n' \
                "${BACKUP_DIR}/${backup_name}.state" "$state" >&2
            restore_status=1
            ;;
    esac
    return "$restore_status"
}

restore_configuration() {
    local rollback_status=0
    restore_managed_config "$SECURITY_CONFIG" security-config || rollback_status=1
    restore_managed_config "$CRYPTO_CONFIG" crypto-config || rollback_status=1
    if (( rollback_status == 0 )); then
        if ! sshd -t; then
            rollback_status=1
        elif ! systemctl reload ssh; then
            rollback_status=1
        fi
    fi
    return "$rollback_status"
}

rollback_on_error() {
    local apply_status=$?
    local rollback_status
    trap - ERR
    set +e
    restore_configuration
    rollback_status=$?
    set -e
    if (( rollback_status == 0 )); then
        printf 'ssh_hardening=rolled-back rollback_path=%s\n' "$BACKUP_DIR" >&2
    else
        printf 'error=ssh-rollback-incomplete rollback_path=%s\n' "$BACKUP_DIR" >&2
    fi
    exit "$apply_status"
}

effective_sshd_value() {
    local key="$1"
    sshd -T -C user=ubuntu,host=localhost,addr=127.0.0.1 \
        | awk -v key="$key" '$1 == key && !seen {$1=""; sub(/^ /, ""); print; seen=1}'
}

assert_effective_value() {
    local key="$1"
    local expected="$2"
    local actual
    actual="$(effective_sshd_value "$key")"
    if [[ "$actual" != "$expected" ]]; then
        printf 'error=unexpected-sshd-value key=%s expected=%s actual=%s\n' \
            "$key" "$expected" "$actual" >&2
        return 1
    fi
}

assert_no_sha1_pubkey_algorithm() {
    local actual
    local normalized
    actual="$(effective_sshd_value pubkeyacceptedalgorithms)"
    normalized="${actual//[[:space:]]/}"
    if [[ -z "$normalized" ]]; then
        printf 'error=missing-effective-pubkey-accepted-algorithms\n' >&2
        return 1
    fi
    if [[ ",${normalized}," == *",ssh-rsa,"* \
        || ",${normalized}," == *",ssh-rsa-cert-v01@openssh.com,"* ]]; then
        printf 'error=sha1-pubkey-algorithm-enabled actual=%s\n' "$actual" >&2
        return 1
    fi
}

validate_effective_configuration() {
    sshd -t
    assert_effective_value passwordauthentication no
    assert_effective_value kbdinteractiveauthentication no
    assert_effective_value permitrootlogin no
    assert_effective_value pubkeyauthentication yes
    assert_effective_value x11forwarding no
    assert_effective_value allowagentforwarding no
    assert_effective_value allowtcpforwarding local
    assert_effective_value maxauthtries 3
    assert_no_sha1_pubkey_algorithm
}

reload_and_validate_service() {
    systemctl reload ssh
    systemctl is-active --quiet ssh
    assert_no_sha1_pubkey_algorithm
}

main() {
    require_inputs
    backup_current_configuration
    trap rollback_on_error ERR
    install -d -m 755 -o root -g root "$SSH_DROPIN_DIR"
    install -m 644 -o root -g root "$SECURITY_CONFIG_SOURCE" "$SECURITY_CONFIG"
    install -m 644 -o root -g root "$CRYPTO_CONFIG_SOURCE" "$CRYPTO_CONFIG"
    validate_effective_configuration
    reload_and_validate_service
    trap - ERR
    printf 'ssh_hardening=applied\n'
    printf 'managed_config=%s\n' "$SECURITY_CONFIG"
    printf 'managed_crypto_config=%s\n' "$CRYPTO_CONFIG"
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
