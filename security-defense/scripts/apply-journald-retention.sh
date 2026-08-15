#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly JOURNALD_DROPIN_DIR="/etc/systemd/journald.conf.d"
readonly MANAGED_CONFIG="/etc/systemd/journald.conf.d/60-visionforge-retention.conf"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-journald-$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly CONFIG_SOURCE="${1:-}"
readonly -a REQUIRED_SETTINGS=(
    'Storage=persistent'
    'Compress=yes'
    'Seal=yes'
    'SystemMaxUse=512M'
    'SystemKeepFree=3G'
    'SystemMaxFileSize=64M'
    'MaxRetentionSec=14day'
    'SyncIntervalSec=5m'
    'RateLimitIntervalSec=30s'
    'RateLimitBurst=10000'
)

require_inputs() {
    local command_name
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ -z "$CONFIG_SOURCE" || ! -f "$CONFIG_SOURCE" ]]; then
        printf 'error=missing-config-source\n' >&2
        exit 1
    fi
    for command_name in systemctl systemd-analyze journalctl; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            printf 'error=missing-command command=%s\n' "$command_name" >&2
            exit 1
        fi
    done
    if [[ -e "$MANAGED_CONFIG" && ! -f "$MANAGED_CONFIG" && ! -L "$MANAGED_CONFIG" ]]; then
        printf 'error=unsupported-managed-config-type path=%s\n' "$MANAGED_CONFIG" >&2
        exit 1
    fi
}

last_setting_value() {
    local config_path="$1"
    local requested_key="$2"
    awk -v requested_key="$requested_key" '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            in_journal_section = (section == "Journal")
            next
        }
        !in_journal_section { next }
        {
            separator = index($0, "=")
            if (separator == 0) {
                next
            }
            key = substr($0, 1, separator - 1)
            value = substr($0, separator + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (key == requested_key) {
                effective_value = value
                found = 1
            }
        }
        END {
            if (!found) {
                exit 1
            }
            print effective_value
        }
    ' "$config_path"
}

assert_required_settings() {
    local config_path="$1"
    local setting
    local key
    local expected
    local actual
    for setting in "${REQUIRED_SETTINGS[@]}"; do
        key="${setting%%=*}"
        expected="${setting#*=}"
        if ! actual="$(last_setting_value "$config_path" "$key")"; then
            printf 'error=missing-journald-setting key=%s source=%s\n' \
                "$key" "$config_path" >&2
            return 1
        fi
        if [[ "$actual" != "$expected" ]]; then
            printf 'error=unexpected-journald-setting key=%s expected=%s actual=%s\n' \
                "$key" "$expected" "$actual" >&2
            return 1
        fi
    done
}

backup_current_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    if [[ -e "$MANAGED_CONFIG" || -L "$MANAGED_CONFIG" ]]; then
        cp -a -- "$MANAGED_CONFIG" "${BACKUP_DIR}/managed-config"
        printf 'present\n' >"${BACKUP_DIR}/managed-config.state"
    else
        printf 'absent\n' >"${BACKUP_DIR}/managed-config.state"
    fi
    SYSTEMD_COLORS=0 systemd-analyze cat-config systemd/journald.conf \
        >"${BACKUP_DIR}/journald-cat-config.before"
    LC_ALL=C journalctl --disk-usage >"${BACKUP_DIR}/journal-disk-usage.before"
}

restore_configuration() {
    local rollback_status=0
    local state
    if ! state="$(<"${BACKUP_DIR}/managed-config.state")"; then
        printf 'error=missing-rollback-state path=%s\n' \
            "${BACKUP_DIR}/managed-config.state" >&2
        return 1
    fi
    case "$state" in
        present)
            rm -f -- "$MANAGED_CONFIG" || rollback_status=1
            if (( rollback_status == 0 )); then
                cp -a -- "${BACKUP_DIR}/managed-config" "$MANAGED_CONFIG" \
                    || rollback_status=1
            fi
            ;;
        absent)
            rm -f -- "$MANAGED_CONFIG" || rollback_status=1
            ;;
        *)
            printf 'error=invalid-rollback-state path=%s state=%s\n' \
                "${BACKUP_DIR}/managed-config.state" "$state" >&2
            rollback_status=1
            ;;
    esac
    if (( rollback_status == 0 )); then
        if ! SYSTEMD_COLORS=0 systemd-analyze cat-config systemd/journald.conf \
            >"${BACKUP_DIR}/journald-cat-config.rolled-back"; then
            rollback_status=1
        elif ! systemctl restart systemd-journald; then
            rollback_status=1
        elif ! systemctl is-active --quiet systemd-journald; then
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
        printf 'journald_retention=rolled-back rollback_path=%s\n' "$BACKUP_DIR" >&2
    else
        printf 'error=journald-rollback-incomplete rollback_path=%s\n' "$BACKUP_DIR" >&2
    fi
    exit "$apply_status"
}

install_configuration() {
    install -d -m 755 -o root -g root "$JOURNALD_DROPIN_DIR"
    install -m 644 -o root -g root "$CONFIG_SOURCE" "$MANAGED_CONFIG"
}

validate_effective_configuration() {
    local merged_config="${BACKUP_DIR}/journald-cat-config.after"
    SYSTEMD_COLORS=0 systemd-analyze cat-config systemd/journald.conf >"$merged_config"
    if ! grep -Fq -- "$MANAGED_CONFIG" "$merged_config"; then
        printf 'error=journald-dropin-not-loaded path=%s\n' "$MANAGED_CONFIG" >&2
        return 1
    fi
    assert_required_settings "$merged_config"
}

verify_runtime_capacity() {
    local capacity_path="/var/log"
    local available_bytes
    if [[ -d /var/log/journal ]]; then
        capacity_path="/var/log/journal"
    fi
    LC_ALL=C journalctl --disk-usage >"${BACKUP_DIR}/journal-disk-usage.after"
    if [[ ! -s "${BACKUP_DIR}/journal-disk-usage.after" ]]; then
        printf 'error=missing-journal-disk-usage\n' >&2
        return 1
    fi
    LC_ALL=C df -PB1 "$capacity_path" >"${BACKUP_DIR}/journal-filesystem-capacity.after"
    available_bytes="$(awk 'NR == 2 {print $4}' "${BACKUP_DIR}/journal-filesystem-capacity.after")"
    if [[ ! "$available_bytes" =~ ^[0-9]+$ || "$available_bytes" == 0 ]]; then
        printf 'error=journal-filesystem-has-no-free-capacity path=%s available=%s\n' \
            "$capacity_path" "$available_bytes" >&2
        return 1
    fi
}

restart_and_validate_service() {
    systemctl restart systemd-journald
    systemctl is-active --quiet systemd-journald
    verify_runtime_capacity
}

main() {
    local disk_usage
    local service_state
    require_inputs
    assert_required_settings "$CONFIG_SOURCE"
    backup_current_configuration
    trap rollback_on_error ERR
    install_configuration
    validate_effective_configuration
    restart_and_validate_service
    service_state="$(systemctl show systemd-journald --property=ActiveState,SubState)"
    disk_usage="$(<"${BACKUP_DIR}/journal-disk-usage.after")"
    trap - ERR
    printf 'journald_retention=applied\n'
    printf 'managed_config=%s\n' "$MANAGED_CONFIG"
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
    printf '%s\n' "$service_state"
    printf '%s\n' "$disk_usage"
}

main "$@"
