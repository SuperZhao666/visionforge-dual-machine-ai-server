from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


SCHEMA = "visionforge-dual-machine-release-materials-v1"
PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----"
PUBLIC_KEY_END = "-----END PUBLIC KEY-----"
TLS_PIN_PATTERN = re.compile(r"^sha256/[A-Za-z0-9+/]{43}=$")


@dataclass(frozen=True, slots=True)
class TicketPublicKeyMaterial:
    path: Path
    key_id: str
    sha256_hex: str
    modulus_bits: int
    pem_base64: str


def _configure_utf8_stdio() -> None:
    """Keep Chinese release-material output readable in non-UTF-8 consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def sha256_hex(value: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(value)
    return digest.finalize().hex()


def tls_spki_pin_from_der_spki(der_spki: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_spki)
    return "sha256/" + base64.b64encode(digest.finalize()).decode("ascii")


def validate_tls_pin(value: str) -> str:
    pin = value.strip()
    if not TLS_PIN_PATTERN.fullmatch(pin):
        raise ValueError(f"TLS SPKI pin is not canonical: {value!r}")
    encoded = pin.removeprefix("sha256/")
    decoded = base64.b64decode(encoded, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError(f"TLS SPKI pin is not canonical: {value!r}")
    return pin


def fetch_leaf_tls_spki_pin(
    hostname: str,
    *,
    connect_host: str | None = None,
    port: int = 443,
    timeout_sec: float = 10.0,
) -> str:
    context = ssl.create_default_context()
    target_host = connect_host or hostname
    with socket.create_connection((target_host, port), timeout=timeout_sec) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            certificate_der = tls.getpeercert(binary_form=True)
    if not certificate_der:
        raise RuntimeError(f"server did not return a TLS certificate: {hostname}")
    certificate = x509.load_der_x509_certificate(certificate_der)
    der_spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return tls_spki_pin_from_der_spki(der_spki)


def load_ticket_public_key_material(path: Path) -> TicketPublicKeyMaterial:
    path = path.expanduser().resolve(strict=True)
    contents = path.read_bytes()
    if len(contents) < 256 or len(contents) > 16 * 1024:
        raise ValueError(f"ticket public key PEM size is invalid: {path}")
    try:
        text = contents.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(f"ticket public key PEM is not ASCII: {path}") from exc
    if (
        not text.startswith(PUBLIC_KEY_BEGIN)
        or not text.endswith(PUBLIC_KEY_END)
        or "PRIVATE KEY" in text
        or text.find(PUBLIC_KEY_BEGIN, 1) >= 0
    ):
        raise ValueError(f"ticket key must be exactly one public PEM: {path}")

    body = text[len(PUBLIC_KEY_BEGIN): -len(PUBLIC_KEY_END)]
    try:
        embedded_der = base64.b64decode(re.sub(r"\s", "", body), validate=True)
    except ValueError as exc:
        raise ValueError(f"ticket public key PEM body is invalid: {path}") from exc

    public_key = serialization.load_pem_public_key(contents)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError(f"ticket public key must be RSA: {path}")
    if public_key.key_size < 3072:
        raise ValueError(f"ticket public key must be RSA-3072 or stronger: {path}")

    canonical_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical_der != embedded_der:
        raise ValueError(f"ticket public key PEM is not canonical SPKI: {path}")

    key_sha256 = sha256_hex(canonical_der)
    return TicketPublicKeyMaterial(
        path=path,
        key_id=key_sha256[:16],
        sha256_hex=key_sha256,
        modulus_bits=public_key.key_size,
        pem_base64=base64.b64encode(contents).decode("ascii"),
    )


def load_ticket_public_key_materials(
    paths: Sequence[Path],
) -> tuple[TicketPublicKeyMaterial, ...]:
    if len(paths) > 3:
        raise ValueError("release supports at most 3 pinned ticket public keys")
    materials = tuple(load_ticket_public_key_material(path) for path in paths)
    seen: set[str] = set()
    for material in materials:
        if material.sha256_hex in seen:
            raise ValueError(f"duplicated ticket public key: {material.path}")
        seen.add(material.sha256_hex)
    return materials


def build_release_material_report(
    *,
    tls_host: str,
    tls_port: int,
    tls_connect_host: str | None = None,
    current_tls_pin: str | None = None,
    backup_tls_pins: Sequence[str],
    ticket_public_key_files: Sequence[Path],
    api_origin: str,
    timeout_sec: float = 10.0,
    strict_release: bool = False,
) -> dict[str, Any]:
    current_pin = (
        validate_tls_pin(current_tls_pin)
        if current_tls_pin
        else fetch_leaf_tls_spki_pin(
            tls_host,
            connect_host=tls_connect_host,
            port=tls_port,
            timeout_sec=timeout_sec,
        )
    )
    configured_pins = [current_pin]
    configured_pins.extend(validate_tls_pin(pin) for pin in backup_tls_pins)
    unique_pins = list(dict.fromkeys(configured_pins))

    ticket_keys = load_ticket_public_key_materials(ticket_public_key_files)
    warnings: list[str] = []
    errors: list[str] = []
    if len(unique_pins) != len(configured_pins):
        errors.append("TLS SPKI pins must be distinct")
    if len(unique_pins) < 2:
        message = (
            "release should pin the current TLS SPKI plus at least one offline "
            "backup pin"
        )
        (errors if strict_release else warnings).append(message)
    if len(unique_pins) > 4:
        errors.append("release supports at most 4 TLS SPKI pins")
    if not ticket_keys:
        message = "release requires at least one RSA-3072+ ticket public key"
        (errors if strict_release else warnings).append(message)

    first_key = ticket_keys[0].path if ticket_keys else None
    previous_key_paths = [str(item.path) for item in ticket_keys[1:]]
    return {
        "schema": SCHEMA,
        "ok": not errors,
        "strict_release": strict_release,
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "warnings": warnings,
        "errors": errors,
        "api_origin": api_origin,
        "tls": {
            "host": tls_host,
            "connect_host": tls_connect_host or tls_host,
            "port": tls_port,
            "current_leaf_spki_pin": current_pin,
            "release_pins": unique_pins,
        },
        "ticket_public_keys": [
            {
                "path": str(item.path),
                "key_id": item.key_id,
                "sha256_hex": item.sha256_hex,
                "modulus_bits": item.modulus_bits,
            }
            for item in ticket_keys
        ],
        "android_gradle_inputs": {
            "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS": ",".join(unique_pins),
            "VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE": (
                str(first_key) if first_key else ""
            ),
            "VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES": (
                ";".join(previous_key_paths)
            ),
        },
        "host_release_inputs": {
            "HOST_ROLE": "authenticated_video_publisher",
            "HOST_AUTHORIZATION_GATE": "required",
            "HOST_RELEASE_SECURITY_INPUTS": "public_verification_keyring_required",
            "HOST_IDENTITY_PRIVATE_KEY": "local_cng_tpm_non_exportable",
            "HOST_FORMAL_RELEASE_STATUS": "blocked_until_secure_v2_implemented",
        },
    }


def _powershell_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _powershell_env_line(name: str, value: str) -> str:
    return f"$env:{name}={_powershell_single_quoted(value)}"


def write_android_gradle_env_files(
    *,
    report: dict[str, Any],
    output_json: Path,
) -> dict[str, str]:
    android = report["android_gradle_inputs"]
    env_path = output_json.with_name("dual-machine-android-gradle-env.ps1")
    command_path = output_json.with_name("dual-machine-android-release-build-command.txt")
    lines = [
        "# VisionForge dual-machine Android release Gradle inputs.",
        "# Public-only material: no passwords or private keys are written here.",
        _powershell_env_line(
            "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS",
            android["VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS"],
        ),
        _powershell_env_line(
            "VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE",
            android["VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE"],
        ),
        _powershell_env_line(
            "VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES",
            android["VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES"],
        ),
        "",
    ]
    env_path.write_text("\n".join(lines), encoding="utf-8")
    command_path.write_text(
        "\n".join([
            ". <path-to-android-release-signing-secrets.ps1>",
            f". {_powershell_single_quoted(str(env_path))}",
            "$env:QNN_SDK_ROOT='<path-to-qairt-sdk-root>'",
            (
                "python tools\\build_android_production_release.py "
                "--output-dir releases\\android --gradle-timeout-sec 1200"
            ),
            "",
        ]),
        encoding="utf-8",
    )
    return {
        "android_gradle_env": str(env_path),
        "android_release_build_command": str(command_path),
    }


def _text_report(report: dict[str, Any]) -> str:
    tls = report["tls"]
    android = report["android_gradle_inputs"]
    host = report["host_release_inputs"]
    generated_files = report.get("generated_files")
    lines = [
        "VisionForge dual-machine release materials:",
        f"- status: {'OK' if report['ok'] else 'FAILED'}",
        f"- TLS host: {tls['host']}:{tls['port']}",
        f"- current TLS SPKI pin: {tls['current_leaf_spki_pin']}",
        f"- release TLS pin count: {len(tls['release_pins'])}",
        f"- ticket public key count: {len(report['ticket_public_keys'])}",
        "- Android Gradle inputs:",
        "  VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS="
        + android["VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS"],
        "  VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE="
        + android["VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE"],
        "  VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES="
        + android["VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES"],
        "- Host release inputs:",
        "  HOST_ROLE=" + host["HOST_ROLE"],
        "  HOST_AUTHORIZATION_GATE=" + host["HOST_AUTHORIZATION_GATE"],
        "  HOST_RELEASE_SECURITY_INPUTS="
        + host["HOST_RELEASE_SECURITY_INPUTS"],
        "  HOST_IDENTITY_PRIVATE_KEY=" + host["HOST_IDENTITY_PRIVATE_KEY"],
        "  HOST_FORMAL_RELEASE_STATUS=" + host["HOST_FORMAL_RELEASE_STATUS"],
    ]
    if isinstance(generated_files, dict):
        env_path = str(generated_files.get("android_gradle_env") or "")
        command_path = str(generated_files.get("android_release_build_command") or "")
        if env_path:
            lines.append(f"- Android Gradle env file: {env_path}")
        if command_path:
            lines.append(f"- Android release build command: {command_path}")
    for item in report["warnings"]:
        lines.append(f"- warning: {item}")
    for item in report["errors"]:
        lines.append(f"- error: {item}")
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare public-only dual-machine release material evidence. "
            "This tool never reads ticket private keys."
        ),
    )
    parser.add_argument("--tls-host", default="www.visionforge.cloud")
    parser.add_argument(
        "--tls-connect-host",
        help=(
            "Optional IP/host to connect to when local DNS is constrained. "
            "SNI and certificate validation still use --tls-host."
        ),
    )
    parser.add_argument("--tls-port", type=int, default=443)
    parser.add_argument(
        "--current-tls-pin",
        help=(
            "Optional canonical current TLS SPKI pin. When supplied, the tool "
            "does not open a TLS socket."
        ),
    )
    parser.add_argument(
        "--backup-tls-pin",
        action="append",
        default=[],
        help="Canonical backup SPKI pin, e.g. sha256/<base64-digest>.",
    )
    parser.add_argument(
        "--ticket-public-key-file",
        action="append",
        default=[],
        type=Path,
        help="RSA-3072+ public PEM for RS256 usage-lease verification.",
    )
    parser.add_argument(
        "--api-origin",
        default="https://www.visionforge.cloud",
    )
    parser.add_argument("--timeout-sec", type=float, default=10.0)
    parser.add_argument(
        "--strict-release",
        action="store_true",
        help="Fail unless backup TLS pin and ticket public keys are present.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON, including public CMake key material.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Optional path for a JSON evidence file.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(argv or sys.argv[1:])
    try:
        report = build_release_material_report(
            tls_host=args.tls_host,
            tls_connect_host=args.tls_connect_host,
            tls_port=args.tls_port,
            current_tls_pin=args.current_tls_pin,
            backup_tls_pins=args.backup_tls_pin,
            ticket_public_key_files=args.ticket_public_key_file,
            api_origin=args.api_origin,
            timeout_sec=args.timeout_sec,
            strict_release=args.strict_release,
        )
    except Exception as exc:
        print(f"prepare_dual_machine_release_materials.py: error: {exc}", file=sys.stderr)
        return 1
    if args.output_json:
        generated_files = write_android_gradle_env_files(
            report=report,
            output_json=args.output_json,
        )
        report["generated_files"] = generated_files
        args.output_json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(
        json.dumps(report, ensure_ascii=False, indent=2)
        if args.json
        else _text_report(report)
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
