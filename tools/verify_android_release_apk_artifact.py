from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_android_release_apk_contract import (  # noqa: E402
    CheckResult,
    verify_android_release_apk,
)


SCHEMA = "visionforge-android-release-apk-artifact-v1"
ApkVerifier = Callable[[Path, bool], CheckResult]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def result_to_json(result: CheckResult) -> Mapping[str, object]:
    return {
        "name": result.name,
        "ok": result.ok,
        "detail": result.detail,
        "evidence": result.evidence,
    }


def build_report(
    *,
    apk_path: Path,
    require_production_signing: bool,
    result: CheckResult,
) -> Mapping[str, object]:
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": result.ok,
        "apk": str(apk_path),
        "require_production_signing": require_production_signing,
        "check": result_to_json(result),
    }


def write_report(path: Path, report: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def verify_android_release_apk_artifact(
    *,
    apk_path: Path,
    output: Path,
    allow_development_android_signing: bool,
    verifier: ApkVerifier | None = None,
) -> Mapping[str, object]:
    resolved_apk = apk_path.resolve()
    require_production_signing = not allow_development_android_signing
    verifier = verifier or (
        lambda path, require: verify_android_release_apk(
            path,
            require_production_signing=require,
        )
    )
    result = verifier(resolved_apk, require_production_signing)
    report = build_report(
        apk_path=resolved_apk,
        require_production_signing=require_production_signing,
        result=result,
    )
    write_report(output, report)
    return report


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-development-android-signing", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output.resolve()
    try:
        report = verify_android_release_apk_artifact(
            apk_path=args.apk,
            output=output,
            allow_development_android_signing=args.allow_development_android_signing,
        )
    except Exception as exc:  # noqa: BLE001
        report = {
            "schema": SCHEMA,
            "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "ok": False,
            "apk": str(args.apk),
            "require_production_signing": not args.allow_development_android_signing,
            "error": str(exc),
        }
        write_report(output, report)
        print(f"[ERROR] Android APK release preflight failed; report={output}", flush=True)
        print(f"[ERROR] {exc}", flush=True)
        return 1
    if report.get("ok") is True:
        print(f"[OK] Android APK release preflight passed; report={output}", flush=True)
        return 0
    detail = ""
    check = report.get("check")
    if isinstance(check, Mapping):
        detail = str(check.get("detail") or "")
    print(
        "[ERROR] Android APK release preflight failed; "
        f"report={output}",
        flush=True,
    )
    if detail:
        print(f"[ERROR] {detail}", flush=True)
    return 2


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
