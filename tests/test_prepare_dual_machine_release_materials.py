from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.prepare_dual_machine_release_materials import (  # noqa: E402
    build_release_material_report,
    load_pair_credential_public_key_material,
    load_pair_credential_public_key_materials,
    load_ticket_public_key_material,
    load_ticket_public_key_materials,
    resolve_current_tls_spki_pin,
    tls_spki_pin_from_der_spki,
    validate_tls_pin,
    write_android_gradle_env_files,
)


def _write_public_key(tmp_path: Path, name: str, bits: int = 3072) -> Path:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )
    path = tmp_path / name
    path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path


def _pin(seed: bytes) -> str:
    return tls_spki_pin_from_der_spki(seed.ljust(64, b"\0"))


def test_validate_tls_pin_accepts_canonical_sha256_pin() -> None:
    pin = _pin(b"current")

    assert validate_tls_pin(pin) == pin


def test_validate_tls_pin_rejects_noncanonical_value() -> None:
    with pytest.raises(ValueError, match="not canonical"):
        validate_tls_pin("sha256/not-a-real-pin")


def test_ticket_public_key_material_requires_rsa_3072_plus(
    tmp_path: Path,
) -> None:
    strong = _write_public_key(tmp_path, "strong.pem", bits=3072)
    weak = _write_public_key(tmp_path, "weak.pem", bits=2048)

    assert load_ticket_public_key_material(strong).modulus_bits == 3072
    with pytest.raises(ValueError, match="RSA-3072"):
        load_ticket_public_key_material(weak)


def test_ticket_public_key_material_resolves_relative_path_for_gradle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    monkeypatch.chdir(tmp_path)

    material = load_ticket_public_key_material(Path("ticket.pem"))

    assert material.path == ticket_key.resolve()
    assert material.path.is_absolute()


def test_ticket_public_key_materials_reject_duplicate_keys(
    tmp_path: Path,
) -> None:
    key_path = _write_public_key(tmp_path, "ticket.pem")

    with pytest.raises(ValueError, match="duplicated"):
        load_ticket_public_key_materials((key_path, key_path))


def test_pair_credential_public_key_material_requires_rsa_3072_plus(
    tmp_path: Path,
) -> None:
    strong = _write_public_key(tmp_path, "pair-strong.pem", bits=3072)
    weak = _write_public_key(tmp_path, "pair-weak.pem", bits=2048)

    assert load_pair_credential_public_key_material(strong).modulus_bits == 3072
    with pytest.raises(ValueError, match="pair credential.*RSA-3072"):
        load_pair_credential_public_key_material(weak)


def test_pair_credential_public_key_materials_reject_duplicate_keys(
    tmp_path: Path,
) -> None:
    key_path = _write_public_key(tmp_path, "pair.pem")

    with pytest.raises(ValueError, match="duplicated pair credential"):
        load_pair_credential_public_key_materials((key_path, key_path))


def test_release_material_report_outputs_build_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    pair_key = _write_public_key(tmp_path, "pair.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )

    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(ticket_key,),
        pair_credential_public_key_files=(pair_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )

    assert report["ok"] is True
    assert report["tls"]["release_pins"] == [current_pin, backup_pin]
    assert report["tls"]["current_leaf_spki_pin_live_verified"] is True
    android = report["android_gradle_inputs"]
    assert android["VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS"] == (
        current_pin + "," + backup_pin
    )
    assert android["VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE"] == (
        str(ticket_key)
    )
    assert android[
        "VISIONFORGE_DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_FILE"
    ] == str(pair_key)
    assert report["pair_credential_public_keys"][0]["modulus_bits"] == 3072
    host = report["host_release_inputs"]
    assert host == {
        "HOST_ROLE": "authenticated_video_publisher",
        "HOST_AUTHORIZATION_GATE": "required",
        "HOST_RELEASE_SECURITY_INPUTS": "public_verification_keyring_required",
        "HOST_IDENTITY_PRIVATE_KEY": "local_cng_tpm_non_exportable",
        "HOST_FORMAL_RELEASE_STATUS": "blocked_until_secure_v2_implemented",
    }


def test_release_material_writer_emits_public_gradle_env_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    pair_key = _write_public_key(tmp_path, "pair.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )
    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(ticket_key,),
        pair_credential_public_key_files=(pair_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )
    output_dir = tmp_path / "release materials"
    output_dir.mkdir()
    output_json = output_dir / "dual-machine-release-materials.json"

    generated = write_android_gradle_env_files(
        report=report,
        output_json=output_json,
    )

    env_text = Path(generated["android_gradle_env"]).read_text(encoding="utf-8")
    command_text = Path(generated["android_release_build_command"]).read_text(
        encoding="utf-8",
    )
    serialized = json.dumps({**report, "generated_files": generated})
    assert "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS" in env_text
    assert "VISIONFORGE_DUAL_MACHINE_TICKET_PUBLIC_KEY_FILE" in env_text
    assert "VISIONFORGE_DUAL_MACHINE_PREVIOUS_TICKET_PUBLIC_KEY_FILES" in env_text
    assert "VISIONFORGE_DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_FILE" in env_text
    assert (
        "VISIONFORGE_DUAL_MACHINE_PREVIOUS_PAIR_CREDENTIAL_PUBLIC_KEY_FILES"
        in env_text
    )
    assert current_pin in env_text
    assert backup_pin in env_text
    assert "build_android_production_release.py" in command_text
    assert "<path-to-android-release-signing-secrets.ps1>" in command_text
    env_path_literal = str(Path(generated["android_gradle_env"])).replace("'", "''")
    assert f". '{env_path_literal}'" in command_text
    assert "PRIVATE KEY" not in serialized
    assert "STORE_PASSWORD" not in serialized


def test_release_material_writer_creates_missing_output_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    pair_key = _write_public_key(tmp_path, "pair.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )
    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(ticket_key,),
        pair_credential_public_key_files=(pair_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )
    output_json = tmp_path / "missing" / "nested" / "materials.json"

    generated = write_android_gradle_env_files(
        report=report,
        output_json=output_json,
    )

    assert Path(generated["android_gradle_env"]).is_file()
    assert Path(generated["android_release_build_command"]).is_file()


def test_strict_release_fails_without_backup_pin_or_ticket_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_pin = _pin(b"leaf")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )

    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        current_tls_pin=current_pin,
        backup_tls_pins=(),
        ticket_public_key_files=(),
        pair_credential_public_key_files=(),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )

    assert report["ok"] is False
    assert report["warnings"] == []
    assert (
        "release should pin the current TLS SPKI plus at least one offline "
        "backup pin"
    ) in report["errors"]
    assert (
        "release requires at least one RSA-3072+ ticket public key"
    ) in report["errors"]
    assert (
        "release requires at least one RSA-3072+ pair-credential public key"
    ) in report["errors"]


def test_release_rejects_key_reuse_between_ticket_and_pair_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reused_key = _write_public_key(tmp_path, "reused.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )

    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(reused_key,),
        pair_credential_public_key_files=(reused_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )

    assert report["ok"] is False
    assert (
        "usage-ticket and pair-credential verification keys must be disjoint"
        in report["errors"]
    )


def test_non_strict_current_tls_pin_override_does_not_open_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    pair_key = _write_public_key(tmp_path, "pair.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")

    def fail_if_called(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("current_tls_pin override should not fetch TLS")

    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        fail_if_called,
    )
    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        current_tls_pin=current_pin,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(ticket_key,),
        pair_credential_public_key_files=(pair_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=False,
    )

    assert report["ok"] is True
    assert report["tls"]["current_leaf_spki_pin"] == current_pin
    assert report["tls"]["current_leaf_spki_pin_live_verified"] is False


def test_strict_current_tls_pin_override_must_match_live_peer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    configured_pin = _pin(b"mistyped-leaf")
    live_pin = _pin(b"live-leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: live_pin,
    )

    with pytest.raises(ValueError, match="does not match the live leaf"):
        build_release_material_report(
            tls_host="www.visionforge.cloud",
            tls_port=443,
            current_tls_pin=configured_pin,
            backup_tls_pins=(backup_pin,),
            ticket_public_key_files=(ticket_key,),
            api_origin="https://www.visionforge.cloud",
            strict_release=True,
        )


def test_strict_current_tls_pin_override_records_live_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_pin = _pin(b"live-leaf")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )

    resolved, live_verified = resolve_current_tls_spki_pin(
        "www.visionforge.cloud",
        configured_pin=current_pin,
        verify_configured_against_live=True,
    )

    assert resolved == current_pin
    assert live_verified is True


def test_release_material_json_contains_no_private_key_material(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ticket_key = _write_public_key(tmp_path, "ticket.pem")
    pair_key = _write_public_key(tmp_path, "pair.pem")
    current_pin = _pin(b"leaf")
    backup_pin = _pin(b"offline-backup")
    monkeypatch.setattr(
        "tools.prepare_dual_machine_release_materials.fetch_leaf_tls_spki_pin",
        lambda *args, **kwargs: current_pin,
    )

    report = build_release_material_report(
        tls_host="www.visionforge.cloud",
        tls_port=443,
        backup_tls_pins=(backup_pin,),
        ticket_public_key_files=(ticket_key,),
        pair_credential_public_key_files=(pair_key,),
        api_origin="https://www.visionforge.cloud",
        strict_release=True,
    )
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)

    assert "PRIVATE KEY" not in serialized
    assert "load_pem_private_key" not in serialized
    assert report["ticket_public_keys"][0]["modulus_bits"] == 3072
    assert report["pair_credential_public_keys"][0]["modulus_bits"] == 3072
    assert "pem_base64" not in report["ticket_public_keys"][0]
    assert "pem_base64" not in report["pair_credential_public_keys"][0]
    assert "VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64" not in serialized
    assert report["host_release_inputs"]["HOST_AUTHORIZATION_GATE"] == "required"
    assert report["host_release_inputs"]["HOST_FORMAL_RELEASE_STATUS"] == (
        "blocked_until_secure_v2_implemented"
    )
