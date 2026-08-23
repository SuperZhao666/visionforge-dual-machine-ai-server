from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from tools import verify_dual_machine_cryptographic_evidence as cli
from tools import dual_machine_cryptographic_evidence as verifier


REQUIRED_CASES = (
    "tag_bit_flip",
    "aad_bit_flip",
    "ciphertext_bit_flip",
    "truncation",
    "oversize",
    "duplicate_counter",
    "out_of_order",
    "wrong_epoch",
    "wrong_direction",
    "wrong_type",
    "wrong_connection",
    "cross_session",
    "plaintext_downgrade",
    "artifact_sha256",
)


def _write_manifest(
    root: Path,
    payload: dict[object, object],
    name: str = "cryptographic_evidence.json",
) -> Path:
    path = root / name
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    return path


def _valid_manifest(
    root: Path,
    *,
    case_order: tuple[str, ...] | None = None,
) -> tuple[Path, dict[str, object]]:
    cases = case_order or REQUIRED_CASES
    artifacts: list[dict[str, object]] = []
    matrix: list[dict[str, object]] = []
    for case_id in cases:
        relative = f"artifacts/{case_id}.evidence"
        content = f"case={case_id}\nobserved=target_rejected\n".encode("utf-8")
        artifact_path = root / Path(*relative.split("/"))
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_bytes(content)
        artifacts.append(
            {
                "path": relative,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
        matrix.append(
            {
                "case_id": case_id,
                "result": "rejected",
                "artifact": relative,
            }
        )
    payload: dict[str, object] = {
        "schema": verifier.MANIFEST_SCHEMA,
        "artifacts": artifacts,
        "attack_matrix": matrix,
    }
    return _write_manifest(root, payload), payload


def _assert_rejected(manifest: Path) -> None:
    with pytest.raises(verifier.CryptographicEvidenceError):
        verifier.verify_evidence_manifest(manifest)


def test_required_case_names_match_verifier_contract() -> None:
    assert tuple(verifier.REQUIRED_ATTACK_CASES) == REQUIRED_CASES


def test_minimal_manifest_succeeds_and_report_order_is_stable(tmp_path: Path) -> None:
    manifest, _ = _valid_manifest(tmp_path, case_order=tuple(reversed(REQUIRED_CASES)))

    first = verifier.verify_evidence_manifest(manifest)
    second = verifier.verify_evidence_manifest(manifest)

    assert first == second
    assert first == {
        "schema": verifier.VERIFIER_REPORT_SCHEMA,
        "ok": True,
        "verified_artifacts": sorted(
            f"artifacts/{case_id}.evidence" for case_id in REQUIRED_CASES
        ),
        "verified_cases": sorted(REQUIRED_CASES),
    }


@pytest.mark.parametrize("missing_case", REQUIRED_CASES)
def test_each_required_case_must_be_present(tmp_path: Path, missing_case: str) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["attack_matrix"] = [
        case for case in payload["attack_matrix"] if case["case_id"] != missing_case
    ]
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize("duplicate_case", REQUIRED_CASES)
def test_each_required_case_must_be_unique(tmp_path: Path, duplicate_case: str) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    original = next(
        case for case in payload["attack_matrix"] if case["case_id"] == duplicate_case
    )
    payload["attack_matrix"].append(copy.deepcopy(original))
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize("accepted_case", REQUIRED_CASES)
def test_each_required_case_must_report_rejected(tmp_path: Path, accepted_case: str) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    next(
        case for case in payload["attack_matrix"] if case["case_id"] == accepted_case
    )["result"] = "accepted"
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


def test_unknown_case_is_rejected(tmp_path: Path) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["attack_matrix"][0]["case_id"] = "unknown_case"
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "wrong-schema"),
        ("schema", True),
        ("artifacts", {}),
        ("attack_matrix", {}),
        ("unexpected", "field"),
    ],
)
def test_top_level_schema_and_types_are_strict(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    if field == "unexpected":
        payload[field] = value
    else:
        payload[field] = value
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize(
    "bad_size",
    [True, False, 1.0, -1, verifier.MAX_ARTIFACT_BYTES + 1],
)
def test_artifact_size_is_a_bounded_non_boolean_integer(
    tmp_path: Path,
    bad_size: object,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["size"] = bad_size
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize(
    "bad_hash",
    [
        "A" * 64,
        "a" * 63,
        "a" * 65,
        "g" * 64,
        True,
        1,
    ],
)
def test_artifact_hash_is_lowercase_sha256_hex(
    tmp_path: Path,
    bad_hash: object,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["sha256"] = bad_hash
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


@pytest.mark.parametrize(
    "bad_path",
    [
        "../outside.evidence",
        "artifacts/../../outside.evidence",
        "/absolute.evidence",
        "C:/absolute.evidence",
        "C:\\absolute.evidence",
        "artifacts\\escape.evidence",
        "./artifacts/evidence",
        "artifacts//evidence",
        "",
    ],
)
def test_artifact_path_must_be_archive_local_posix_relative(
    tmp_path: Path,
    bad_path: str,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["path"] = bad_path
    payload["attack_matrix"][0]["artifact"] = bad_path
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


def test_case_shape_is_exact_and_artifact_reference_is_required(tmp_path: Path) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["attack_matrix"][0] = {
        "case_id": REQUIRED_CASES[0],
        "result": "rejected",
        "extra": "not allowed",
    }
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


def test_duplicate_artifact_paths_and_unreferenced_artifacts_are_rejected(
    tmp_path: Path,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"].append(copy.deepcopy(payload["artifacts"][0]))
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)

    manifest, payload = _valid_manifest(tmp_path)
    extra = b"unreferenced\n"
    extra_path = tmp_path / "artifacts" / "unreferenced.evidence"
    extra_path.write_bytes(extra)
    payload["artifacts"].append(
        {
            "path": "artifacts/unreferenced.evidence",
            "size": len(extra),
            "sha256": hashlib.sha256(extra).hexdigest(),
        }
    )
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)


def test_manifest_rejects_nan_and_duplicate_json_keys(tmp_path: Path) -> None:
    manifest = tmp_path / "cryptographic_evidence.json"
    manifest.write_text('{"schema": NaN}', encoding="utf-8")
    _assert_rejected(manifest)

    manifest.write_text(
        '{"schema": "' + verifier.MANIFEST_SCHEMA + '", '
        '"schema": "' + verifier.MANIFEST_SCHEMA + '", '
        '"artifacts": [], "attack_matrix": []}',
        encoding="utf-8",
    )
    _assert_rejected(manifest)


def test_manifest_and_entry_counts_are_bounded(tmp_path: Path) -> None:
    manifest = tmp_path / "cryptographic_evidence.json"
    too_many_artifacts = [
        {"path": f"artifacts/{index}.evidence", "size": 0, "sha256": "0" * 64}
        for index in range(verifier.MAX_ARTIFACT_ENTRIES + 1)
    ]
    payload = {
        "schema": verifier.MANIFEST_SCHEMA,
        "artifacts": too_many_artifacts,
        "attack_matrix": [],
    }
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)

    manifest.write_bytes(b"{" + b" " * verifier.MAX_MANIFEST_BYTES + b"}")
    _assert_rejected(manifest)


def test_missing_directory_and_directory_artifact_are_rejected(tmp_path: Path) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["path"] = "artifacts/missing.evidence"
    payload["attack_matrix"][0]["artifact"] = "artifacts/missing.evidence"
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)

    manifest, payload = _valid_manifest(tmp_path)
    directory = tmp_path / "artifacts" / "directory.evidence"
    directory.mkdir()
    payload["artifacts"][0]["path"] = "artifacts/directory.evidence"
    payload["attack_matrix"][0]["artifact"] = "artifacts/directory.evidence"
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-cryptographic-evidence.bin"
    outside.write_bytes(b"outside evidence must not be followed")
    link = tmp_path / "artifacts" / "escaped.evidence"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0] = {
        "path": "artifacts/escaped.evidence",
        "size": outside.stat().st_size,
        "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
    }
    payload["attack_matrix"][0]["artifact"] = "artifacts/escaped.evidence"
    _write_manifest(tmp_path, payload)

    _assert_rejected(manifest)


def _replace_open_path(root: Path, relative: str, replacement: bytes) -> None:
    target = root / Path(*relative.split("/"))
    moved = target.with_name(target.name + ".original")
    try:
        os.replace(target, moved)
        target.write_bytes(replacement)
    except OSError as exc:
        if moved.exists() and not target.exists():
            os.replace(moved, target)
        pytest.skip(f"path replacement unavailable: {exc}")


def test_manifest_handle_remains_bound_when_manifest_path_is_replaced(
    tmp_path: Path,
) -> None:
    manifest, _ = _valid_manifest(tmp_path)
    original = manifest.read_bytes()
    replacement = b"manifest path replacement must not be read"

    with verifier._SecureArchive(tmp_path) as archive:
        with archive.open_file(manifest.name) as handle:
            _replace_open_path(tmp_path, manifest.name, replacement)
            handle.seek(0)
            assert handle.read() == original


def test_artifact_handle_remains_bound_when_artifact_path_is_replaced(
    tmp_path: Path,
) -> None:
    _valid_manifest(tmp_path)
    relative = f"artifacts/{REQUIRED_CASES[0]}.evidence"
    target = tmp_path / Path(*relative.split("/"))
    original = target.read_bytes()

    with verifier._SecureArchive(tmp_path) as archive:
        with archive.open_file(relative) as handle:
            _replace_open_path(tmp_path, relative, b"artifact path replacement")
            handle.seek(0)
            assert handle.read() == original


def test_manifest_symlink_is_rejected_or_skipped_explicitly(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-manifest-evidence.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "manifest-link.json"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink/junction creation unavailable: {exc}")

    _assert_rejected(link)


def test_size_mutation_and_hash_mutation_are_rejected(tmp_path: Path) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    artifact = tmp_path / "artifacts" / f"{REQUIRED_CASES[0]}.evidence"

    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)

    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["size"] += 1
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)

    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["sha256"] = "f" * 64
    _write_manifest(tmp_path, payload)
    _assert_rejected(manifest)


def test_total_declared_artifact_bytes_is_checked_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    payload["artifacts"][0]["size"] = verifier.MAX_TOTAL_ARTIFACT_BYTES
    payload["artifacts"][1]["size"] = 1
    _write_manifest(tmp_path, payload)

    def fail_if_hashing(*_args: object, **_kwargs: object) -> None:
        pytest.fail("artifact hashing must not start before total-size validation")

    monkeypatch.setattr(verifier, "_hash_artifact", fail_if_hashing)
    with pytest.raises(verifier.CryptographicEvidenceError) as caught:
        verifier.verify_evidence_manifest(manifest)
    assert caught.value.code == "artifact_total_size_bound"


def test_total_declared_artifact_bytes_boundary_is_inclusive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, payload = _valid_manifest(tmp_path)
    total = sum(artifact["size"] for artifact in payload["artifacts"])
    monkeypatch.setattr(verifier, "MAX_TOTAL_ARTIFACT_BYTES", total)
    assert verifier.verify_evidence_manifest(manifest)["ok"] is True

    monkeypatch.setattr(verifier, "MAX_TOTAL_ARTIFACT_BYTES", total - 1)
    with pytest.raises(verifier.CryptographicEvidenceError) as caught:
        verifier.verify_evidence_manifest(manifest)
    assert caught.value.code == "artifact_total_size_bound"


def test_cli_json_and_text_stdout_stderr_contract(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest, _ = _valid_manifest(tmp_path)

    assert cli.main(("--evidence", str(manifest), "--json")) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["ok"] is True
    assert "NaN" not in captured.out

    assert cli.main(("--evidence", str(manifest))) == 0
    captured = capsys.readouterr()
    assert captured.out.startswith("[OK] dual-machine cryptographic evidence verified;")
    assert captured.err == ""


def test_cli_failure_is_fail_closed_and_does_not_echo_secret_or_file_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "SECRET-MUST-NOT-APPEAR-123"
    manifest = tmp_path / "cryptographic_evidence.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": verifier.MANIFEST_SCHEMA,
                "artifacts": [
                    {
                        "path": "artifacts/missing.evidence",
                        "size": 1,
                        "sha256": "0" * 64,
                    }
                ],
                "attack_matrix": [
                    {
                        "case_id": REQUIRED_CASES[0],
                        "result": "rejected",
                        "artifact": "artifacts/missing.evidence",
                    }
                ],
                "secret": secret,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    assert cli.main(("--evidence", str(manifest), "--json")) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["ok"] is False
    assert secret not in captured.out
    assert "missing.evidence" not in captured.out

    assert cli.main(("--evidence", str(manifest))) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(
        "[ERROR] dual-machine cryptographic evidence rejected:"
    )
    assert secret not in captured.err
    assert "missing.evidence" not in captured.err


def test_output_is_deterministic_and_atomic_for_success_and_failure(
    tmp_path: Path,
) -> None:
    manifest, _ = _valid_manifest(tmp_path)
    output = tmp_path / "reports" / "evidence-report.json"

    assert cli.main(("--evidence", str(manifest), "--output", str(output))) == 0
    first = output.read_text(encoding="utf-8")
    assert json.loads(first)["ok"] is True
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))

    assert cli.main(("--evidence", str(manifest), "--output", str(output))) == 0
    assert output.read_text(encoding="utf-8") == first
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not-json", encoding="utf-8")
    assert cli.main(("--evidence", str(invalid), "--output", str(output))) == 1
    failure = json.loads(output.read_text(encoding="utf-8"))
    assert failure["ok"] is False
    assert failure["verified_cases"] == []
    assert not list(output.parent.glob(f".{output.name}.*.tmp"))


def test_atomic_writer_removes_temporary_file_when_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.json"
    original_replace = Path.replace

    def fail_replace(self: Path, target: Path) -> Path:
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replacement failure"):
        cli.write_report_atomic(output, {"ok": False})
    monkeypatch.setattr(Path, "replace", original_replace)

    assert not output.exists()
    assert not list(tmp_path.glob(f".{output.name}.*.tmp"))
