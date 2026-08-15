#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly LYNIS_DIRECTORY="${1:-}"
readonly OUTPUT_DIRECTORY="${2:-}"

if (( EUID != 0 )); then
    printf 'error=run-as-root\n' >&2
    exit 1
fi
if [[ -z "$LYNIS_DIRECTORY" || ! -x "$LYNIS_DIRECTORY/lynis" ]]; then
    printf 'error=missing-lynis-directory\n' >&2
    exit 1
fi
if [[ -z "$OUTPUT_DIRECTORY" || ! -d "$OUTPUT_DIRECTORY" ]]; then
    printf 'error=missing-output-directory\n' >&2
    exit 1
fi

cd "$LYNIS_DIRECTORY"
./lynis audit system --no-colors --quick --quiet
grep -F 'hardening_index=' /var/log/lynis-report.dat >/dev/null
grep -F 'report_datetime_end=' /var/log/lynis-report.dat >/dev/null
install -m 600 -o ubuntu -g ubuntu /var/log/lynis-report.dat \
    "$OUTPUT_DIRECTORY/lynis-report-final.dat"
install -m 600 -o ubuntu -g ubuntu /var/log/lynis.log \
    "$OUTPUT_DIRECTORY/lynis-final.log"
printf 'lynis_audit=complete\n'
