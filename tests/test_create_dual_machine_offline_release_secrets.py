from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.create_dual_machine_offline_release_secrets import (  # noqa: E402
    build_offline_release_secrets,
)
from tools.prepare_dual_machine_release_materials import (  # noqa: E402
    load_ticket_public_key_material,
    validate_tls_pin,
)


def test_offline_secret_generator_creates_release_ready_public_inputs(
    tmp_path: Path,
) -> None:
    report = build_offline_release_secrets(
        output_dir=tmp_path / "secure",
        tls_host="www.visionforge.cloud",
    )

    ticket_public_key_path = Path(report["ticket_public_key"]["path"])
    ticket_private_key_path = Path(
        report["private_key_files"]["ticket_private_key_path"],
    )
    backup_tls_private_key_path = Path(
        report["private_key_files"]["backup_tls_private_key_path"],
    )
    backup_tls_csr_path = Path(report["backup_tls"]["csr_path"])
    command_path = Path(report["next_command_file"])

    assert load_ticket_public_key_material(
        ticket_public_key_path,
    ).modulus_bits == 3072
    assert validate_tls_pin(report["backup_tls"]["spki_pin"]) == (
        report["backup_tls"]["spki_pin"]
    )
    assert ticket_private_key_path.read_bytes().startswith(
        b"-----BEGIN PRIVATE KEY-----",
    )
    assert backup_tls_private_key_path.read_bytes().startswith(
        b"-----BEGIN PRIVATE KEY-----",
    )
    assert backup_tls_csr_path.read_bytes().startswith(
        b"-----BEGIN CERTIFICATE REQUEST-----",
    )

    command = command_path.read_text(encoding="utf-8")
    assert "--backup-tls-pin " + report["backup_tls"]["spki_pin"] in command
    assert "--ticket-public-key-file " + str(ticket_public_key_path) in command
    assert "--strict-release" in command

    serialized = json.dumps(report, ensure_ascii=False)
    assert "BEGIN PRIVATE KEY" not in serialized
    assert ticket_private_key_path.read_text(encoding="ascii") not in serialized
    assert (
        backup_tls_private_key_path.read_text(encoding="ascii")
        not in serialized
    )


def test_offline_secret_generator_refuses_repository_output() -> None:
    with pytest.raises(ValueError, match="repository"):
        build_offline_release_secrets(
            output_dir=ROOT / "owner_secrets" / "dual-machine",
            tls_host="www.visionforge.cloud",
        )


def test_offline_secret_generator_refuses_to_overwrite_without_force(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "secure"
    build_offline_release_secrets(
        output_dir=output_dir,
        tls_host="www.visionforge.cloud",
    )

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        build_offline_release_secrets(
            output_dir=output_dir,
            tls_host="www.visionforge.cloud",
        )
