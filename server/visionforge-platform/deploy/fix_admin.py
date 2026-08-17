#!/usr/bin/env python3
"""Fail-closed replacement for the retired password-over-SSH admin helper."""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "REMOTE_ADMIN_REPAIR=DISABLED: run deploy/create_admin.py locally on the "
        "server through the cloud console or strict key-authenticated SSH; "
        "password SSH and automatic host-key trust are forbidden.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
