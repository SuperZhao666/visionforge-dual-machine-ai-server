"""Trusted reverse-proxy client-address handling for the loopback sidecar."""
from __future__ import annotations

import ipaddress

from fastapi import Request


_LOOPBACK_PEERS = {"127.0.0.1", "::1"}


def client_ip(request: Request) -> str:
    peer = str(request.client.host if request.client else "")
    if peer not in _LOOPBACK_PEERS:
        return _valid_ip(peer)
    forwarded = str(request.headers.get("x-forwarded-for") or "")
    candidate = forwarded.split(",", 1)[0].strip()
    return _valid_ip(candidate) if candidate else _valid_ip(peer)


def rate_limit_key(request: Request) -> str:
    return client_ip(request) or "unknown"


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""
