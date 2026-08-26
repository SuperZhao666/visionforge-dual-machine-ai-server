from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "visionforge-dual-machine-offline-release-secrets-v1"
DEFAULT_TICKET_KEY_BITS = 3072
DEFAULT_BACKUP_TLS_KEY_BITS = 3072


@dataclass(frozen=True, slots=True)
class OfflineReleaseSecretPaths:
    ticket_private_key: Path
    ticket_public_key: Path
    backup_tls_private_key: Path
    backup_tls_public_key: Path
    backup_tls_csr: Path
    report_json: Path
    release_command: Path


def _configure_utf8_stdio() -> None:
    """Keep Chinese release-secret output readable in non-UTF-8 consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def sha256_hex(value: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(value)
    return digest.finalize().hex()


def tls_spki_pin_from_public_key(public_key: rsa.RSAPublicKey) -> str:
    der_spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_spki)
    import base64

    return "sha256/" + base64.b64encode(digest.finalize()).decode("ascii")


def secure_output_dir(
    output_dir: Path,
    *,
    root: Path = ROOT,
    allow_workspace_output: bool = False,
) -> Path:
    resolved_output_dir = output_dir.resolve(strict=False)
    resolved_root = root.resolve(strict=False)
    if not allow_workspace_output and _is_within(
        resolved_output_dir,
        resolved_root,
    ):
        raise ValueError(
            "refusing to write production secrets inside the repository; "
            "choose a separate secure directory such as C:\\secure",
        )
    if resolved_output_dir.parent == resolved_output_dir:
        raise ValueError("refusing to write production secrets to a drive root")
    home = Path.home().resolve(strict=False)
    if resolved_output_dir == home:
        raise ValueError("refusing to write production secrets to the home root")
    return resolved_output_dir


def build_offline_release_secrets(
    *,
    output_dir: Path,
    tls_host: str,
    ticket_key_bits: int = DEFAULT_TICKET_KEY_BITS,
    backup_tls_key_bits: int = DEFAULT_BACKUP_TLS_KEY_BITS,
    force: bool = False,
    allow_workspace_output: bool = False,
) -> dict[str, Any]:
    if ticket_key_bits < 3072:
        raise ValueError("ticket key must be RSA-3072 or stronger")
    if backup_tls_key_bits < 3072:
        raise ValueError("backup TLS key must be RSA-3072 or stronger")
    host = _tls_host(tls_host)
    directory = secure_output_dir(
        output_dir,
        allow_workspace_output=allow_workspace_output,
    )
    paths = _secret_paths(directory)
    _prepare_directory(directory)
    _require_writable_targets(paths, force=force)

    ticket_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=ticket_key_bits,
    )
    backup_tls_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=backup_tls_key_bits,
    )
    ticket_public_key = ticket_private_key.public_key()
    backup_tls_public_key = backup_tls_private_key.public_key()
    ticket_public_der = ticket_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    backup_tls_pin = tls_spki_pin_from_public_key(backup_tls_public_key)
    backup_tls_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]),
            critical=False,
        )
        .sign(backup_tls_private_key, hashes.SHA256())
    )

    _write_private_pem(
        paths.ticket_private_key,
        ticket_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_public_pem(
        paths.ticket_public_key,
        ticket_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    _write_private_pem(
        paths.backup_tls_private_key,
        backup_tls_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _write_public_pem(
        paths.backup_tls_public_key,
        backup_tls_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    _write_public_pem(
        paths.backup_tls_csr,
        backup_tls_csr.public_bytes(serialization.Encoding.PEM),
    )

    release_command = _release_command(
        tls_host=host,
        backup_tls_pin=backup_tls_pin,
        ticket_public_key_path=paths.ticket_public_key,
        output_json_path=directory / "dual-machine-release-materials.json",
    )
    paths.release_command.write_text(release_command, encoding="utf-8")

    report = {
        "schema": SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "output_dir": str(directory),
        "tls_host": host,
        "ticket_public_key": {
            "path": str(paths.ticket_public_key),
            "sha256_hex": sha256_hex(ticket_public_der),
            "modulus_bits": ticket_public_key.key_size,
        },
        "backup_tls": {
            "public_key_path": str(paths.backup_tls_public_key),
            "csr_path": str(paths.backup_tls_csr),
            "spki_pin": backup_tls_pin,
            "modulus_bits": backup_tls_public_key.key_size,
        },
        "private_key_files": {
            "ticket_private_key_path": str(paths.ticket_private_key),
            "backup_tls_private_key_path": str(
                paths.backup_tls_private_key,
            ),
            "warning": (
                "These files are secrets. Do not commit them, upload them, "
                "or paste their contents into tickets or chat."
            ),
        },
        "next_command_file": str(paths.release_command),
    }
    paths.report_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    _harden_secret_permissions(paths.report_json)
    _harden_secret_permissions(paths.release_command)
    return report


def _secret_paths(directory: Path) -> OfflineReleaseSecretPaths:
    return OfflineReleaseSecretPaths(
        ticket_private_key=directory / "dual-machine-ticket-private.pem",
        ticket_public_key=directory / "dual-machine-ticket-public.pem",
        backup_tls_private_key=directory
        / "dual-machine-backup-tls-private.pem",
        backup_tls_public_key=directory
        / "dual-machine-backup-tls-public.pem",
        backup_tls_csr=directory / "dual-machine-backup-tls.csr.pem",
        report_json=directory / "dual-machine-offline-secrets.json",
        release_command=directory / "prepare-release-materials-command.txt",
    )


def _prepare_directory(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)


def _require_writable_targets(
    paths: OfflineReleaseSecretPaths,
    *,
    force: bool,
) -> None:
    existing = [
        str(path)
        for path in (
            paths.ticket_private_key,
            paths.ticket_public_key,
            paths.backup_tls_private_key,
            paths.backup_tls_public_key,
            paths.backup_tls_csr,
            paths.report_json,
            paths.release_command,
        )
        if path.exists()
    ]
    if existing and not force:
        raise FileExistsError(
            "refusing to overwrite existing release secret files: "
            + ", ".join(existing),
        )


def _write_private_pem(path: Path, contents: bytes) -> None:
    path.write_bytes(contents)
    _harden_secret_permissions(path)


def _write_public_pem(path: Path, contents: bytes) -> None:
    path.write_bytes(contents)
    os.chmod(path, 0o644)


def _harden_secret_permissions(path: Path) -> None:
    os.chmod(path, 0o600)


def _release_command(
    *,
    tls_host: str,
    backup_tls_pin: str,
    ticket_public_key_path: Path,
    output_json_path: Path,
) -> str:
    return "\n".join([
        "python tools\\prepare_dual_machine_release_materials.py `",
        f"  --tls-host {tls_host} `",
        f"  --backup-tls-pin {backup_tls_pin} `",
        f"  --ticket-public-key-file {ticket_public_key_path} `",
        "  --strict-release `",
        f"  --output-json {output_json_path}",
        "",
    ])


def _tls_host(value: str) -> str:
    host = value.strip().lower()
    if (
        not host
        or "/" in host
        or ":" in host
        or "\\" in host
        or len(host) > 253
    ):
        raise ValueError(f"invalid TLS host: {value!r}")
    return host


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _text_report(report: dict[str, Any]) -> str:
    private_files = report["private_key_files"]
    return "\n".join([
        "VisionForge dual-machine offline release secrets:",
        f"- output: {report['output_dir']}",
        f"- ticket public key: {report['ticket_public_key']['path']}",
        f"- backup TLS SPKI pin: {report['backup_tls']['spki_pin']}",
        f"- backup TLS CSR: {report['backup_tls']['csr_path']}",
        "- secret files:",
        f"  {private_files['ticket_private_key_path']}",
        f"  {private_files['backup_tls_private_key_path']}",
        f"- next command: {report['next_command_file']}",
    ])


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate dual-machine production candidate secrets in an offline "
            "directory. The tool refuses repository output by default."
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tls-host", default="www.visionforge.cloud")
    parser.add_argument(
        "--ticket-key-bits",
        type=int,
        default=DEFAULT_TICKET_KEY_BITS,
    )
    parser.add_argument(
        "--backup-tls-key-bits",
        type=int,
        default=DEFAULT_BACKUP_TLS_KEY_BITS,
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing files in the selected secure directory.",
    )
    parser.add_argument(
        "--allow-workspace-output",
        action="store_true",
        help="Testing only. Allows writing secrets inside this repository.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(argv or sys.argv[1:])
    try:
        report = build_offline_release_secrets(
            output_dir=args.output_dir,
            tls_host=args.tls_host,
            ticket_key_bits=args.ticket_key_bits,
            backup_tls_key_bits=args.backup_tls_key_bits,
            force=args.force,
            allow_workspace_output=args.allow_workspace_output,
        )
    except Exception as exc:
        print(
            f"create_dual_machine_offline_release_secrets.py: error: {exc}",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(report, ensure_ascii=False, indent=2)
        if args.json
        else _text_report(report)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
