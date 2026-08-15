"""Local CLI for issuing and revoking isolated dual-machine cards."""
from __future__ import annotations

import argparse
import json
import secrets
import time
from dataclasses import asdict

from .admin_service import DualMachineAdminService
from .card_service import CardIssuanceService
from .database import initialize_database
from .settings import DualMachineSettings


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    settings = DualMachineSettings.from_environment()
    settings.validate_card_issuance()
    initialize_database(settings)

    if arguments.command == "init-db":
        _print_json({"ok": True, "database": str(settings.database_path)})
        return 0
    if arguments.command == "issue":
        expires_at = (
            int(time.time()) + int(arguments.expires_days) * 86_400
            if arguments.expires_days is not None
            else None
        )
        result = CardIssuanceService(settings).issue_batch(
            request_id=arguments.request_id or secrets.token_hex(16),
            product_key=arguments.product,
            quantity=arguments.quantity,
            channel=arguments.channel,
            note=arguments.note,
            expires_at_epoch=expires_at,
        )
        _print_json({"ok": True, **asdict(result)})
        return 0
    admin = DualMachineAdminService(settings)
    if arguments.command == "revoke-batch":
        _print_json(admin.revoke_batch(
            arguments.batch_id,
            reason=arguments.reason,
            revoke_activated_entitlements=(
                arguments.revoke_activated_entitlements
            ),
        ))
        return 0
    if arguments.command == "list-batches":
        _print_json(admin.list_batches(
            limit=arguments.limit,
            offset=arguments.offset,
            status=arguments.status,
        ))
        return 0
    if arguments.command == "list-codes":
        _print_json(admin.list_codes(
            batch_id=arguments.batch_id,
            limit=arguments.limit,
            offset=arguments.offset,
            status=arguments.status,
        ))
        return 0
    if arguments.command == "revoke-entitlement":
        _print_json(admin.revoke_entitlement(
            arguments.entitlement_id,
            reason=arguments.reason,
        ))
        return 0
    if arguments.command == "entitlement":
        _print_json(admin.entitlement_summary(arguments.entitlement_id))
        return 0
    parser.error("unsupported command")
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VisionForge dual-machine local administration",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-db")

    issue = commands.add_parser("issue")
    issue.add_argument("--product", required=True)
    issue.add_argument("--quantity", type=int, required=True)
    issue.add_argument("--channel", default="manual")
    issue.add_argument("--note", default="")
    issue.add_argument("--request-id", default="")
    issue.add_argument("--expires-days", type=int)

    revoke_batch = commands.add_parser("revoke-batch")
    revoke_batch.add_argument("--batch-id", type=int, required=True)
    revoke_batch.add_argument("--reason", required=True)
    revoke_batch.add_argument(
        "--revoke-activated-entitlements",
        action="store_true",
        help=(
            "also revoke every entitlement activated from this batch; "
            "omit to revoke only unactivated cards"
        ),
    )

    list_batches = commands.add_parser("list-batches")
    list_batches.add_argument("--limit", type=int, default=50)
    list_batches.add_argument("--offset", type=int, default=0)
    list_batches.add_argument(
        "--status",
        choices=("active", "revoked"),
        default="",
    )

    list_codes = commands.add_parser("list-codes")
    list_codes.add_argument("--batch-id", type=int, required=True)
    list_codes.add_argument("--limit", type=int, default=100)
    list_codes.add_argument("--offset", type=int, default=0)
    list_codes.add_argument(
        "--status",
        choices=("issued", "activated", "revoked", "expired"),
        default="",
    )

    revoke_entitlement = commands.add_parser("revoke-entitlement")
    revoke_entitlement.add_argument("--entitlement-id", required=True)
    revoke_entitlement.add_argument("--reason", required=True)

    entitlement = commands.add_parser("entitlement")
    entitlement.add_argument("--entitlement-id", required=True)
    return parser


def _print_json(value: object) -> None:
    print(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        default=list,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
