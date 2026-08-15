from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "visionforge-android-production-signing-inputs-v1"
ANDROID_DEBUG_CERT_SHA256 = (
    "179faf0492d0b49d66bdefcc66bc51541602525a25b8af8c4e42345a770c7155"
)
STORE_FILE_ENV = "VISIONFORGE_ANDROID_RELEASE_STORE_FILE"
STORE_PASSWORD_ENV = "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD"
KEY_ALIAS_ENV = "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS"
KEY_PASSWORD_ENV = "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD"
ALLOW_DEVELOPMENT_SIGNING_ENV = "VISIONFORGE_ALLOW_DEVELOPMENT_SIGNING"


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class SigningInputs:
    store_file_text: str
    store_password: str
    key_alias: str
    key_password: str
    allow_development_signing: bool


CommandRunner = Callable[[Sequence[str], int], CommandResult]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _env_flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _tail(text: str, limit: int = 6000) -> str:
    return text[-limit:]


def _resolve_store_file(raw_path: str, root: Path) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def load_signing_inputs(
    env: Mapping[str, str] | None = None,
) -> SigningInputs:
    source = os.environ if env is None else env
    return SigningInputs(
        store_file_text=str(source.get(STORE_FILE_ENV, "")).strip(),
        store_password=str(source.get(STORE_PASSWORD_ENV, "")),
        key_alias=str(source.get(KEY_ALIAS_ENV, "")).strip(),
        key_password=str(source.get(KEY_PASSWORD_ENV, "")),
        allow_development_signing=_env_flag(source.get(ALLOW_DEVELOPMENT_SIGNING_ENV)),
    )


def parse_keytool_certificate_output(text: str) -> Mapping[str, Any]:
    owner_match = re.search(r"(?im)^\s*Owner:\s*(?P<owner>.+?)\s*$", text)
    sha_match = re.search(r"(?im)^\s*SHA256:\s*(?P<sha>[0-9A-F:]+)\s*$", text)
    owner = owner_match.group("owner").strip() if owner_match else ""
    sha256 = ""
    if sha_match:
        sha256 = re.sub(r"[^0-9A-Fa-f]", "", sha_match.group("sha")).lower()
    return {
        "certificate_owner": owner,
        "certificate_sha256": sha256,
        "android_debug_certificate": (
            sha256 == ANDROID_DEBUG_CERT_SHA256
            or "CN=Android Debug" in owner
        ),
    }


def run_command(command: Sequence[str], timeout_sec: int) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def inspect_release_certificate(
    *,
    keytool: str,
    store_file: Path,
    store_password: str,
    key_alias: str,
    timeout_sec: int,
    runner: CommandRunner,
) -> tuple[Mapping[str, Any], list[str]]:
    command = [
        keytool,
        "-J-Duser.language=en",
        "-J-Duser.country=US",
        "-list",
        "-v",
        "-keystore",
        str(store_file),
        "-alias",
        key_alias,
        "-storepass:env",
        STORE_PASSWORD_ENV,
    ]
    result = runner(command, timeout_sec)
    evidence: dict[str, Any] = {
        "keytool_returncode": result.returncode,
        "keytool_stdout_tail": _tail(result.stdout),
        "keytool_stderr_tail": _tail(result.stderr),
    }
    errors: list[str] = []
    if result.returncode != 0:
        errors.append("keytool could not inspect the release signing certificate")
        return evidence, errors

    parsed = parse_keytool_certificate_output(result.stdout + "\n" + result.stderr)
    evidence.update(parsed)
    if not parsed["certificate_owner"]:
        errors.append("keytool output did not include a certificate owner")
    if not parsed["certificate_sha256"]:
        errors.append("keytool output did not include a certificate SHA-256 digest")
    if parsed["android_debug_certificate"]:
        errors.append("release signing certificate is the Android Debug certificate")
    return evidence, errors


def verify_android_production_signing_inputs(
    *,
    env: Mapping[str, str] | None = None,
    keytool: str = "keytool",
    timeout_sec: int = 30,
    root: Path = ROOT,
    runner: CommandRunner = run_command,
) -> Mapping[str, Any]:
    inputs = load_signing_inputs(env)
    root = root.resolve()
    errors: list[str] = []
    evidence: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": False,
        "env_names": {
            "store_file": STORE_FILE_ENV,
            "store_password": STORE_PASSWORD_ENV,
            "key_alias": KEY_ALIAS_ENV,
            "key_password": KEY_PASSWORD_ENV,
            "allow_development_signing": ALLOW_DEVELOPMENT_SIGNING_ENV,
        },
        "inputs_present": {
            "store_file": bool(inputs.store_file_text),
            "store_password": bool(inputs.store_password),
            "key_alias": bool(inputs.key_alias),
            "key_password": bool(inputs.key_password),
            "allow_development_signing": inputs.allow_development_signing,
        },
        "signing": {},
        "errors": errors,
    }

    if inputs.allow_development_signing:
        errors.append(
            f"{ALLOW_DEVELOPMENT_SIGNING_ENV} is enabled; production release signing "
            "must run without the development signing switch"
        )
    if not inputs.store_file_text:
        errors.append(f"{STORE_FILE_ENV} is required")
    if not inputs.store_password:
        errors.append(f"{STORE_PASSWORD_ENV} is required")
    if not inputs.key_alias:
        errors.append(f"{KEY_ALIAS_ENV} is required")
    if not inputs.key_password:
        errors.append(f"{KEY_PASSWORD_ENV} is required")

    store_file: Path | None = None
    if inputs.store_file_text:
        store_file = _resolve_store_file(inputs.store_file_text, root)
        signing = evidence["signing"]
        signing["store_file"] = str(store_file)
        signing["store_file_outside_repository"] = not _is_relative_to(store_file, root)
        signing["key_alias"] = inputs.key_alias
        if not store_file.is_file():
            errors.append(f"release signing keystore is missing: {store_file}")
        if _is_relative_to(store_file, root):
            errors.append("release signing keystore must be outside the repository")

    if not errors and store_file is not None:
        certificate_evidence, certificate_errors = inspect_release_certificate(
            keytool=keytool,
            store_file=store_file,
            store_password=inputs.store_password,
            key_alias=inputs.key_alias,
            timeout_sec=timeout_sec,
            runner=runner,
        )
        evidence["signing"].update(certificate_evidence)
        errors.extend(certificate_errors)

    evidence["ok"] = not errors
    return evidence


def write_report(report: Mapping[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keytool", default=os.environ.get("VISIONFORGE_KEYTOOL", "keytool"))
    parser.add_argument("--timeout-sec", type=int, default=30)
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = verify_android_production_signing_inputs(
        keytool=args.keytool,
        timeout_sec=args.timeout_sec,
    )
    if args.output is not None:
        write_report(report, args.output.resolve())
    if report["ok"]:
        print("[OK] Android production signing inputs passed", flush=True)
        return 0
    print("[ERROR] Android production signing inputs failed", flush=True)
    for error in report["errors"]:
        print(f"- {error}", flush=True)
    return 1


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
