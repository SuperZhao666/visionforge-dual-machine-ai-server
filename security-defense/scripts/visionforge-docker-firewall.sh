#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG_FILE="/etc/default/visionforge-docker-firewall"
readonly ALLOW_COMMENT="vf-allow-container-egress-replies"
readonly DROP_COMMENT="vf-drop-untrusted-forwarding"
readonly XTABLES_LOCK_WAIT_SECONDS=10

load_configuration() {
    if [[ ! -r "$CONFIG_FILE" ]]; then
        printf 'error=missing-firewall-config\n' >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    if [[ ! "${EXT_IF:-}" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
        printf 'error=invalid-external-interface\n' >&2
        exit 1
    fi
    ip link show "$EXT_IF" >/dev/null
}

remove_ipv4_rules() {
    while iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -C DOCKER-USER -i "$EXT_IF" -m conntrack \
        --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT 2>/dev/null; do
        iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -D DOCKER-USER -i "$EXT_IF" -m conntrack \
            --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT
    done
    while iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -C DOCKER-USER -i "$EXT_IF" -m comment \
        --comment "$DROP_COMMENT" -j DROP 2>/dev/null; do
        iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -D DOCKER-USER -i "$EXT_IF" -m comment \
            --comment "$DROP_COMMENT" -j DROP
    done
}

apply_ipv4_rules() {
    iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -S DOCKER-USER >/dev/null
    remove_ipv4_rules
    iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -I DOCKER-USER 1 -i "$EXT_IF" -m comment \
        --comment "$DROP_COMMENT" -j DROP
    iptables -w "$XTABLES_LOCK_WAIT_SECONDS" -I DOCKER-USER 1 -i "$EXT_IF" -m conntrack \
        --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT
}

remove_ipv6_rules() {
    ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -S DOCKER-USER >/dev/null 2>&1 || return 0
    while ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -C DOCKER-USER -i "$EXT_IF" -m conntrack \
        --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT 2>/dev/null; do
        ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -D DOCKER-USER -i "$EXT_IF" -m conntrack \
            --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT
    done
    while ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -C DOCKER-USER -i "$EXT_IF" -m comment \
        --comment "$DROP_COMMENT" -j DROP 2>/dev/null; do
        ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -D DOCKER-USER -i "$EXT_IF" -m comment \
            --comment "$DROP_COMMENT" -j DROP
    done
}

apply_ipv6_rules() {
    ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -S DOCKER-USER >/dev/null 2>&1 || return 0
    remove_ipv6_rules
    ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -I DOCKER-USER 1 -i "$EXT_IF" -m comment \
        --comment "$DROP_COMMENT" -j DROP
    ip6tables -w "$XTABLES_LOCK_WAIT_SECONDS" -I DOCKER-USER 1 -i "$EXT_IF" -m conntrack \
        --ctstate ESTABLISHED,RELATED -m comment --comment "$ALLOW_COMMENT" -j ACCEPT
}

main() {
    local action="${1:-apply}"
    load_configuration
    case "$action" in
        apply)
            apply_ipv4_rules
            apply_ipv6_rules
            ;;
        remove)
            remove_ipv4_rules
            remove_ipv6_rules
            ;;
        *)
            printf 'error=unknown-action\n' >&2
            exit 1
            ;;
    esac
}

main "$@"
