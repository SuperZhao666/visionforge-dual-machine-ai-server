#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly REPOSITORY_KEY_URL="https://packagecloud.io/crowdsec/crowdsec/gpgkey"
readonly REPOSITORY_URL="https://packagecloud.io/crowdsec/crowdsec/any"
readonly PRIMARY_FINGERPRINT="6A89E3C2303A901A889971D3376ED5326E93CD0C"
readonly SIGNING_FINGERPRINT="C358C5638A13ACC3A665A9419EB2753BF09DFB77"
readonly CROWDSEC_VERSION="1.7.8"
readonly BOUNCER_PACKAGE="crowdsec-firewall-bouncer-nftables"
readonly BOUNCER_VERSION="0.0.34"
readonly CROWDSEC_SHA256="d93c47d5c25bee9461f5afdef6af513eae4c4b64f3a2e28ea2f7d173a5aa0ba9"
readonly BOUNCER_SHA256="0d8817cd8bb5e1e7970cc1ff4969347653af5d4acd3c2215d1b6f541dbfb1ee4"
readonly APT_TIMEOUT_SECONDS="30"
readonly DOWNLOAD_TIMEOUT_SECONDS="300"
readonly KEYRING_PATH="/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg"
readonly SOURCE_PATH="/etc/apt/sources.list.d/crowdsec_crowdsec.list"
readonly CACHE_DIR="/var/cache/visionforge-security/crowdsec"
readonly BACKUP_DIR="/var/backups/visionforge-security/config-edit-crowdsec-repository-$(date -u +%Y%m%dT%H%M%SZ)"

TEMPORARY_DIRECTORY=""

require_environment() {
    if (( EUID != 0 )); then
        printf 'error=run-as-root\n' >&2
        exit 1
    fi
    if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
        printf 'error=unsupported-architecture\n' >&2
        exit 1
    fi
    if ! iptables -V 2>/dev/null | grep -Fq 'nf_tables'; then
        printf 'error=iptables-backend-is-not-nftables\n' >&2
        exit 1
    fi
    command -v curl >/dev/null
    command -v gpg >/dev/null
}

backup_repository_configuration() {
    install -d -m 700 -o root -g root "$BACKUP_DIR"
    for path in "$KEYRING_PATH" "$SOURCE_PATH"; do
        if [[ -e "$path" ]]; then
            cp -a "$path" "$BACKUP_DIR/"
        fi
    done
}

download_and_verify_key() {
    local temporary_directory="$1"
    local primary_fingerprint
    local signing_fingerprint
    local -a fingerprints=()

    install -d -m 700 "$temporary_directory/gnupg"
    curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
        --connect-timeout 10 --max-time 60 \
        --output "$temporary_directory/crowdsec.asc" "$REPOSITORY_KEY_URL"

    mapfile -t fingerprints < <(
        gpg --homedir "$temporary_directory/gnupg" --batch --show-keys \
            --with-colons "$temporary_directory/crowdsec.asc" |
            awk -F: '$1 == "fpr" { print $10 }'
    )
    primary_fingerprint="${fingerprints[0]:-}"
    signing_fingerprint="${fingerprints[1]:-}"
    [[ "${#fingerprints[@]}" -eq 2 ]]
    [[ "$primary_fingerprint" == "$PRIMARY_FINGERPRINT" ]]
    [[ "$signing_fingerprint" == "$SIGNING_FINGERPRINT" ]]

    gpg --homedir "$temporary_directory/gnupg" --batch --yes --dearmor \
        --output "$temporary_directory/crowdsec.gpg" \
        "$temporary_directory/crowdsec.asc"
}

install_repository_configuration() {
    local temporary_directory="$1"

    install -d -m 755 -o root -g root /etc/apt/keyrings
    install -m 644 -o root -g root "$temporary_directory/crowdsec.gpg" "$KEYRING_PATH"
    printf 'deb [signed-by=%s] %s any main\n' "$KEYRING_PATH" "$REPOSITORY_URL" >"$SOURCE_PATH"
    chmod 644 "$SOURCE_PATH"
    apt-get \
        -o "Acquire::https::Timeout=${APT_TIMEOUT_SECONDS}" \
        -o Acquire::Retries=3 update
}

verify_repository_versions() {
    local crowdsec_candidate
    local bouncer_candidate

    crowdsec_candidate="$(apt-cache policy crowdsec | awk '/Candidate:/ {candidate=$2} END {print candidate}')"
    bouncer_candidate="$(apt-cache policy "$BOUNCER_PACKAGE" | awk '/Candidate:/ {candidate=$2} END {print candidate}')"
    [[ "$crowdsec_candidate" == "$CROWDSEC_VERSION" ]]
    [[ "$bouncer_candidate" == "$BOUNCER_VERSION" ]]
    apt-cache policy crowdsec "$BOUNCER_PACKAGE" |
        grep -F 'packagecloud.io/crowdsec/crowdsec' >/dev/null
}

download_verified_packages() {
    local crowdsec_package
    local bouncer_package

    install -d -m 700 -o root -g root "$CACHE_DIR"
    rm -f "$CACHE_DIR"/*.deb
    (
        cd "$CACHE_DIR"
        timeout "$DOWNLOAD_TIMEOUT_SECONDS" apt-get \
            -o "Acquire::https::Timeout=${APT_TIMEOUT_SECONDS}" \
            -o Acquire::Retries=3 \
            download "crowdsec=${CROWDSEC_VERSION}" "${BOUNCER_PACKAGE}=${BOUNCER_VERSION}"
    )
    crowdsec_package="$(find "$CACHE_DIR" -maxdepth 1 -type f -name 'crowdsec_*.deb' -print -quit)"
    bouncer_package="$(find "$CACHE_DIR" -maxdepth 1 -type f -name "${BOUNCER_PACKAGE}_*.deb" -print -quit)"
    [[ -n "$crowdsec_package" && -n "$bouncer_package" ]]
    printf '%s  %s\n' "$CROWDSEC_SHA256" "$crowdsec_package" | sha256sum --check --status
    printf '%s  %s\n' "$BOUNCER_SHA256" "$bouncer_package" | sha256sum --check --status
    chmod 600 "$crowdsec_package" "$bouncer_package"
}

main() {
    require_environment
    backup_repository_configuration
    TEMPORARY_DIRECTORY="$(mktemp -d)"
    trap 'rm -rf -- "${TEMPORARY_DIRECTORY:-}"' EXIT
    download_and_verify_key "$TEMPORARY_DIRECTORY"
    install_repository_configuration "$TEMPORARY_DIRECTORY"
    verify_repository_versions
    download_verified_packages
    printf 'repository=verified\n'
    printf 'crowdsec_version=%s\n' "$CROWDSEC_VERSION"
    printf 'bouncer_version=%s\n' "$BOUNCER_VERSION"
    printf 'package_cache=%s\n' "$CACHE_DIR"
    printf 'rollback_path=%s\n' "$BACKUP_DIR"
}

main "$@"
