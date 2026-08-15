#!/usr/bin/env bash

section() {
    printf '\n## %s\n' "$1"
}

key_value() {
    printf '%s=%s\n' "$1" "$2"
}

has_command() {
    command -v "$1" >/dev/null 2>&1
}

run_optional() {
    local label="$1"
    shift
    printf '\n[%s]\n' "$label"
    if ! "$@"; then
        printf 'status=unavailable-or-failed\n'
    fi
}

run_privileged() {
    local label="$1"
    shift
    printf '\n[%s]\n' "$label"
    if (( EUID == 0 )); then
        "$@" || printf 'status=failed\n'
        return
    fi
    if sudo -n true >/dev/null 2>&1; then
        sudo -n "$@" || printf 'status=failed\n'
        return
    fi
    printf 'status=skipped-no-noninteractive-sudo\n'
}
