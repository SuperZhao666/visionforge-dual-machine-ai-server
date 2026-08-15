"""Retired destructive deployment entry point.

This legacy script used to delete the live application directory and recreate
secrets. Keeping that behaviour would also remove the database, signing state,
logs, and self-hosted EXE update artifacts. Production deployment must use the
inventory/backup/staged cutover runbook; local service and Nginx setup uses
``server_setup.sh`` followed by ``final_setup.sh``.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "deploy/full_deploy.py is retired because it was destructive. "
        "Use a backup-first staged deployment, then run deploy/final_setup.sh.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
