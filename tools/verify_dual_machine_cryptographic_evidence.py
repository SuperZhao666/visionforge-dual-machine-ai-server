from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.dual_machine_cryptographic_evidence import (  # noqa: E402
    CryptographicEvidenceError,
    VERIFIER_REPORT_SCHEMA,
    verify_evidence_manifest,
)


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def _failure_report(error: Exception) -> dict[str, Any]:
    return {
        "schema": VERIFIER_REPORT_SCHEMA,
        "ok": False,
        "error_code": "cryptographic_evidence_rejected",
        "detail": str(error),
        "verified_cases": [],
    }


def _canonical_json(report: dict[str, Any]) -> str:
    return json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ) + "\n"


def write_report_atomic(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical_json(report)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify archive-local dual-machine mutation, replay, downgrade, "
            "cross-session, and artifact-integrity evidence."
        )
    )
    parser.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="Path to cryptographic_evidence.json.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional atomic JSON report output path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete verifier report as JSON.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(tuple(argv) if argv is not None else tuple(sys.argv[1:]))
    try:
        report = verify_evidence_manifest(args.evidence)
    except (CryptographicEvidenceError, OSError, ValueError) as exc:
        report = _failure_report(exc)
    if args.output is not None:
        write_report_atomic(args.output, report)
    if args.json:
        print(_canonical_json(report), end="")
    elif report["ok"]:
        print(
            "[OK] dual-machine cryptographic evidence verified; "
            f"cases={len(report['verified_cases'])}"
        )
    else:
        print(
            "[ERROR] dual-machine cryptographic evidence rejected: "
            f"{report['detail']}",
            file=sys.stderr,
        )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
