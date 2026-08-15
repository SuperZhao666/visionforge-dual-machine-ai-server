"""Retired GitHub-dependent remote setup entry point."""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "deploy/setup.py is retired. Copy the release to the existing server, "
        "then run deploy/server_setup.sh and deploy/final_setup.sh locally.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
