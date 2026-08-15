#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly LOG_DIRECTORY="/var/log/nginx"
readonly QUERY_MARKER="/appPush?"
readonly REDACTION_EXPRESSION='s{(/appPush)\?[^"[:space:]]+}{$1[QUERY_REDACTED]}g'
readonly REPORT_DIRECTORY="/var/backups/visionforge-security"
readonly REPORT_PATH="${REPORT_DIRECTORY}/nginx-sensitive-log-redaction-$(date -u +%Y%m%dT%H%M%SZ).txt"

TEMPORARY_PATH=""

require_environment() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    command -v nginx >/dev/null
    command -v logrotate >/dev/null
    command -v perl >/dev/null
    command -v gzip >/dev/null
    nginx -t
}

rotate_active_logs() {
    logrotate --force /etc/logrotate.d/nginx
    systemctl is-active --quiet nginx
}

redact_plain_log() {
    local source_path="$1"

    TEMPORARY_PATH="$(mktemp --tmpdir="$LOG_DIRECTORY" .vf-redact.XXXXXX)"
    perl -pe "$REDACTION_EXPRESSION" "$source_path" >"$TEMPORARY_PATH"
    chown --reference="$source_path" "$TEMPORARY_PATH"
    chmod --reference="$source_path" "$TEMPORARY_PATH"
    touch --reference="$source_path" "$TEMPORARY_PATH"
    mv -f "$TEMPORARY_PATH" "$source_path"
    TEMPORARY_PATH=""
}

redact_compressed_log() {
    local source_path="$1"

    TEMPORARY_PATH="$(mktemp --tmpdir="$LOG_DIRECTORY" --suffix=.gz .vf-redact.XXXXXX)"
    gzip --decompress --stdout -- "$source_path" |
        perl -pe "$REDACTION_EXPRESSION" |
        gzip --no-name >"$TEMPORARY_PATH"
    chown --reference="$source_path" "$TEMPORARY_PATH"
    chmod --reference="$source_path" "$TEMPORARY_PATH"
    touch --reference="$source_path" "$TEMPORARY_PATH"
    mv -f "$TEMPORARY_PATH" "$source_path"
    TEMPORARY_PATH=""
}

cleanup_temporary_file() {
    if [[ -n "$TEMPORARY_PATH" ]]; then
        rm -f -- "$TEMPORARY_PATH"
    fi
}

redact_historical_logs() {
    local log_path
    local redacted_files=0

    while IFS= read -r -d '' log_path; do
        if ! zgrep -aF "$QUERY_MARKER" "$log_path" >/dev/null 2>&1; then
            continue
        fi
        if [[ "$log_path" == *.gz ]]; then
            redact_compressed_log "$log_path"
        else
            redact_plain_log "$log_path"
        fi
        redacted_files=$((redacted_files + 1))
    done < <(find "$LOG_DIRECTORY" -maxdepth 1 -type f -name 'access.log*' -print0)

    install -d -m 700 -o root -g root "$REPORT_DIRECTORY"
    {
        printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'redacted_files=%s\n' "$redacted_files"
        printf 'pattern=/appPush query string\n'
        printf 'content_backup=none-sensitive-data-not-duplicated\n'
    } >"$REPORT_PATH"
    chmod 600 "$REPORT_PATH"
}

verify_redaction() {
    if zgrep -aF "$QUERY_MARKER" "$LOG_DIRECTORY"/access.log* >/dev/null 2>&1; then
        printf 'error=sensitive-query-remains\n' >&2
        exit 1
    fi
}

main() {
    trap cleanup_temporary_file EXIT
    require_environment
    rotate_active_logs
    redact_historical_logs
    verify_redaction
    printf 'nginx_sensitive_query_logs=redacted\n'
    printf 'report_path=%s\n' "$REPORT_PATH"
}

main "$@"
