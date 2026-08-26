from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_android_production_signing_inputs import (  # noqa: E402
    KEY_ALIAS_ENV,
    KEY_PASSWORD_ENV,
    STORE_FILE_ENV,
    STORE_PASSWORD_ENV,
    parse_keytool_certificate_output,
)


SCHEMA = "visionforge-android-release-keystore-v1"
DEFAULT_ALIAS = "visionforge-release"
DEFAULT_DNAME = "CN=VisionForge Android Release,O=VisionForge,C=CN"
DEFAULT_KEY_SIZE = 4096
DEFAULT_VALIDITY_DAYS = 10000


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[Sequence[str], int, Mapping[str, str]], CommandResult]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _tail(text: str, limit: int = 6000) -> str:
    return text[-limit:]


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def secure_output_dir(
    output_dir: Path,
    *,
    root: Path = ROOT,
    allow_workspace_output: bool = False,
) -> Path:
    resolved_output_dir = output_dir.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if not allow_workspace_output and _is_within(resolved_output_dir, resolved_root):
        raise ValueError(
            "refusing to write Android release keystore inside the repository; "
            "choose a separate secure directory such as C:\\secure",
        )
    if resolved_output_dir.parent == resolved_output_dir:
        raise ValueError("refusing to write Android release keystore to a drive root")
    home = Path.home().resolve(strict=False)
    if resolved_output_dir == home:
        raise ValueError("refusing to write Android release keystore to the home root")
    return resolved_output_dir


def _required_password_env(env: Mapping[str, str]) -> None:
    missing = [
        name
        for name in (STORE_PASSWORD_ENV, KEY_PASSWORD_ENV)
        if not str(env.get(name, "")).strip()
    ]
    if missing:
        raise ValueError(
            "Android release keystore generation requires password environment "
            "variables: " + ", ".join(missing),
        )


def run_command(
    command: Sequence[str],
    timeout_sec: int,
    process_env: Mapping[str, str],
) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        env=dict(process_env),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _harden_secret_permissions(path: Path) -> None:
    os.chmod(path, 0o600)


def _env_template(
    *,
    keystore_path: Path,
    key_alias: str,
) -> str:
    escaped_path = str(keystore_path).replace("`", "``").replace('"', '`"')
    escaped_alias = key_alias.replace("`", "``").replace('"', '`"')
    return "\n".join([
        "# VisionForge Android release signing inputs.",
        "# Password values are intentionally not written by this tool.",
        f'$env:{STORE_FILE_ENV}="{escaped_path}"',
        f'$env:{KEY_ALIAS_ENV}="{escaped_alias}"',
        f'# $env:{STORE_PASSWORD_ENV}="<set in this shell>"',
        f'# $env:{KEY_PASSWORD_ENV}="<set in this shell>"',
        "",
    ])


def _build_command() -> str:
    return "\n".join([
        "python tools\\verify_android_production_signing_inputs.py",
        ".\\gradlew.bat :app:verifyMobileRuntimeSnapshot :app:assembleRelease --offline",
        "",
    ])


def _keytool_generate_command(
    *,
    keytool: str,
    keystore_path: Path,
    key_alias: str,
    dname: str,
    key_size: int,
    validity_days: int,
) -> list[str]:
    return [
        keytool,
        "-J-Duser.language=en",
        "-J-Duser.country=US",
        "-genkeypair",
        "-v",
        "-keystore",
        str(keystore_path),
        "-storetype",
        "JKS",
        "-alias",
        key_alias,
        "-keyalg",
        "RSA",
        "-sigalg",
        "SHA256withRSA",
        "-keysize",
        str(key_size),
        "-validity",
        str(validity_days),
        "-dname",
        dname,
        "-storepass:env",
        STORE_PASSWORD_ENV,
        "-keypass:env",
        KEY_PASSWORD_ENV,
    ]


def _keytool_list_command(
    *,
    keytool: str,
    keystore_path: Path,
    key_alias: str,
) -> list[str]:
    return [
        keytool,
        "-J-Duser.language=en",
        "-J-Duser.country=US",
        "-list",
        "-v",
        "-keystore",
        str(keystore_path),
        "-alias",
        key_alias,
        "-storepass:env",
        STORE_PASSWORD_ENV,
    ]


def create_android_release_keystore(
    *,
    output_dir: Path,
    key_alias: str = DEFAULT_ALIAS,
    dname: str = DEFAULT_DNAME,
    key_size: int = DEFAULT_KEY_SIZE,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
    keytool: str = "keytool",
    timeout_sec: int = 60,
    force: bool = False,
    allow_workspace_output: bool = False,
    root: Path = ROOT,
    env: Mapping[str, str] | None = None,
    runner: CommandRunner = run_command,
) -> dict[str, Any]:
    if not key_alias.strip():
        raise ValueError("Android release key alias is required")
    if key_size < 3072:
        raise ValueError("Android release signing key must be RSA-3072 or stronger")
    if validity_days < 3650:
        raise ValueError("Android release signing validity must be at least 10 years")
    process_env = dict(os.environ if env is None else env)
    _required_password_env(process_env)

    directory = secure_output_dir(
        output_dir,
        root=root,
        allow_workspace_output=allow_workspace_output,
    )
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    keystore_path = directory / "visionforge-android-release.jks"
    report_path = directory / "android-release-keystore.json"
    env_template_path = directory / "android-release-signing-env.ps1"
    build_command_path = directory / "android-release-build-command.txt"
    targets = (keystore_path, report_path, env_template_path, build_command_path)
    existing = [str(path) for path in targets if path.exists()]
    if existing and not force:
        raise FileExistsError(
            "refusing to overwrite existing Android release signing files: "
            + ", ".join(existing),
        )

    generate_command = _keytool_generate_command(
        keytool=keytool,
        keystore_path=keystore_path,
        key_alias=key_alias,
        dname=dname,
        key_size=key_size,
        validity_days=validity_days,
    )
    generated = runner(generate_command, timeout_sec, process_env)
    if generated.returncode != 0:
        raise RuntimeError(
            "keytool failed to generate Android release keystore: "
            + _tail(generated.stdout + "\n" + generated.stderr),
        )
    if not keystore_path.is_file():
        raise RuntimeError(f"keytool did not create keystore: {keystore_path}")
    _harden_secret_permissions(keystore_path)

    listed = runner(
        _keytool_list_command(
            keytool=keytool,
            keystore_path=keystore_path,
            key_alias=key_alias,
        ),
        timeout_sec,
        process_env,
    )
    if listed.returncode != 0:
        raise RuntimeError(
            "keytool failed to inspect Android release keystore: "
            + _tail(listed.stdout + "\n" + listed.stderr),
        )
    certificate = parse_keytool_certificate_output(listed.stdout + "\n" + listed.stderr)
    if certificate["android_debug_certificate"]:
        raise RuntimeError("generated Android release keystore uses Android Debug certificate")

    env_template_path.write_text(
        _env_template(keystore_path=keystore_path, key_alias=key_alias),
        encoding="utf-8",
    )
    build_command_path.write_text(_build_command(), encoding="utf-8")
    report = {
        "schema": SCHEMA,
        "ok": True,
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "output_dir": str(directory),
        "keystore": {
            "path": str(keystore_path),
            "store_type": "JKS",
            "key_alias": key_alias,
            "key_algorithm": "RSA",
            "key_size": key_size,
            "validity_days": validity_days,
            "certificate_owner": certificate["certificate_owner"],
            "certificate_sha256": certificate["certificate_sha256"],
        },
        "env_names": {
            "store_file": STORE_FILE_ENV,
            "store_password": STORE_PASSWORD_ENV,
            "key_alias": KEY_ALIAS_ENV,
            "key_password": KEY_PASSWORD_ENV,
        },
        "env_template": str(env_template_path),
        "next_command_file": str(build_command_path),
        "warning": (
            "The keystore and passwords are release secrets. Do not commit them, "
            "upload them, or paste password values into tickets or chat."
        ),
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _harden_secret_permissions(report_path)
    _harden_secret_permissions(env_template_path)
    _harden_secret_permissions(build_command_path)
    return report


def _text_report(report: Mapping[str, Any]) -> str:
    keystore = report["keystore"]
    return "\n".join([
        "VisionForge Android release keystore:",
        f"- output: {report['output_dir']}",
        f"- keystore: {keystore['path']}",
        f"- alias: {keystore['key_alias']}",
        f"- certificate SHA-256: {keystore['certificate_sha256']}",
        f"- env template: {report['env_template']}",
        f"- next command: {report['next_command_file']}",
    ])


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an Android release signing keystore in a secure directory. "
            "The tool refuses repository output by default."
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--key-alias", default=DEFAULT_ALIAS)
    parser.add_argument("--dname", default=DEFAULT_DNAME)
    parser.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE)
    parser.add_argument("--validity-days", type=int, default=DEFAULT_VALIDITY_DAYS)
    parser.add_argument("--keytool", default=os.environ.get("VISIONFORGE_KEYTOOL", "keytool"))
    parser.add_argument("--timeout-sec", type=int, default=60)
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--allow-workspace-output",
        action="store_true",
        help="Testing only. Allows writing release signing files inside this repository.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(argv or sys.argv[1:])
    try:
        report = create_android_release_keystore(
            output_dir=args.output_dir,
            key_alias=args.key_alias,
            dname=args.dname,
            key_size=args.key_size,
            validity_days=args.validity_days,
            keytool=args.keytool,
            timeout_sec=args.timeout_sec,
            force=args.force,
            allow_workspace_output=args.allow_workspace_output,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"create_android_release_keystore.py: error: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(report, ensure_ascii=False, indent=2)
        if args.json
        else _text_report(report)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
