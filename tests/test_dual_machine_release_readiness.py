from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_dual_machine_release_readiness as readiness_module  # noqa: E402
from tools.verify_dual_machine_release_readiness import (  # noqa: E402
    ACTIVATION_CHALLENGE_ROUTE,
    CheckResult,
    READINESS_SCHEMA,
    REQUIRED_REVERSE_RESISTANCE_CHECKS,
    REVERSE_RESISTANCE_REGISTRY_CHECK,
    _check_reverse_resistance_registry,
    _json_report,
    build_api_url,
    check_reverse_resistance_contracts,
    check_source_contracts,
    validate_security_headers,
)


def _hardened_headers(**overrides: str) -> dict[str, str]:
    headers = {
        "Cache-Control": "no-store, no-store",
        "Strict-Transport-Security": (
            "max-age=31536000; includeSubDomains, "
            "max-age=31536000; includeSubDomains"
        ),
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Resource-Policy": "same-site",
        "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
        "X-Trace-Id": "abc123",
    }
    headers.update(overrides)
    return headers


def _write_formal_security_fixture(
    root: Path,
    *,
    enabled: bool,
) -> dict[str, Path]:
    runtime_root = root / "dual_machine_runtime"
    android_app = root / "android_inference_benchmark" / "app"
    runtime_root.mkdir(parents=True, exist_ok=True)
    android_app.mkdir(parents=True, exist_ok=True)
    paths = {
        "cmake": runtime_root / "CMakeLists.txt",
        "host_capability": runtime_root / "formal_security_capability.cmake",
        "host_loader": runtime_root / "formal_security_loader.cmake",
        "gradle": android_app / "build.gradle",
        "android_capability": (
            android_app / "formal-security-capability.properties"
        ),
        "android_loader": android_app / "formal-security-loader.gradle",
    }
    paths["cmake"].write_text(
        "cmake_minimum_required(VERSION 3.22)\n"
        "project(VisionForgeFormalSecurityProbe LANGUAGES NONE)\n"
        "option(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY \"formal\" OFF)\n"
        'include("${CMAKE_CURRENT_SOURCE_DIR}/formal_security_loader.cmake")\n',
        encoding="utf-8",
    )
    paths["gradle"].write_text(
        "tasks.register('packageRelease')\n"
        "tasks.register('bundleRelease')\n"
        "apply from: 'formal-security-loader.gradle'\n",
        encoding="utf-8",
    )
    paths["host_loader"].write_bytes(
        readiness_module.EXPECTED_HOST_FORMAL_SECURITY_LOADER
    )
    paths["android_loader"].write_bytes(
        readiness_module.EXPECTED_ANDROID_FORMAL_SECURITY_LOADER
    )
    paths["host_capability"].write_text(
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED "
        + ("ON" if enabled else "OFF")
        + ")\n",
        encoding="ascii",
    )
    paths["android_capability"].write_text(
        "formalSecureDataPlaneImplemented="
        + ("true" if enabled else "false")
        + "\n",
        encoding="ascii",
    )
    return paths


def test_header_validation_accepts_duplicate_app_and_edge_headers() -> None:
    assert validate_security_headers(_hardened_headers()) == []


def test_header_validation_rejects_wide_referrer_policy() -> None:
    errors = validate_security_headers(
        _hardened_headers(
            **{"Referrer-Policy": "strict-origin-when-cross-origin"},
        ),
    )

    assert any("no-referrer" in error for error in errors)


def test_build_api_url_accepts_domain_or_api_prefix() -> None:
    expected = (
        "https://www.visionforge.cloud"
        "/api/dual-machine/v1/license-activations/challenges"
    )

    assert build_api_url(
        "https://www.visionforge.cloud",
        ACTIVATION_CHALLENGE_ROUTE,
    ) == expected
    assert build_api_url(
        "https://www.visionforge.cloud/api/dual-machine/v1",
        ACTIVATION_CHALLENGE_ROUTE,
    ) == expected


def test_source_contracts_cover_billing_android_and_release_tooling() -> None:
    results = check_source_contracts(ROOT)
    names = {result.name for result in results}

    assert all(result.ok for result in results)
    assert {
        "billing-starts-only-after-formal-use",
        "sidecar-http-formal-use-full-chain-test",
        "sidecar-status-query-replay-protection",
        "sidecar-card-admin-not-public-api",
        "sidecar-card-admin-local-cli",
        "sidecar-card-secrets-never-persisted-test",
        "sidecar-http-status-replay-test",
        "sidecar-status-replay-test",
        "sidecar-pair-generation-schema-foundation",
        "sidecar-pair-generation-repository-foundation",
        "sidecar-pair-generation-concurrency-migration-tests",
        "sidecar-pair-generation-route-no-direct-repository-access",
        "android-inference-start-auto-billing-ui",
        "android-inference-start-static-test",
        "android-card-key-direct-user-copy",
        "android-card-key-mode-no-login-ui-test",
        "android-status-query-fresh-nonce-test",
        "android-inference-start-fresh-network-identity-test",
        "android-release-security-material-fail-closed",
        "android-https-sidecar-transport-hardening",
        "android-https-sidecar-transport-static-test",
        "android-release-build-security-input-gate",
        "android-release-installer-production-signer-gate",
        "android-production-signing-input-preflight",
        "android-production-signing-input-preflight-tests",
        "android-release-keystore-generator",
        "android-release-keystore-generator-tests",
        "android-production-release-apk-builder",
        "android-production-release-apk-builder-tests",
        "android-installer-emits-formal-device-evidence",
        "android-model-target-ui-hides-unsupported-classes",
        "android-overwatch-enemy-target-contract-test",
        "android-overwatch-native-enemy-class-control-test",
        "formal-release-bundle-verifier-fail-closed",
        "formal-device-evidence-generator",
        "formal-release-acceptance-orchestrator",
        "formal-release-acceptance-orchestrator-tests",
        "android-release-apk-artifact-preflight",
        "android-release-apk-artifact-preflight-tests",
        "android-device-connectivity-preflight",
        "android-device-connectivity-preflight-tests",
        "android-qnn-htp-multi-architecture-doc",
        "authenticated-peer-handshake-v1-draft-contract",
        "authenticated-peer-handshake-v1-cpp-foundation",
        "authenticated-peer-handshake-v1-cpp-regressions",
        "authenticated-peer-handshake-v1-cmake-isolation",
        "authenticated-peer-handshake-v1-android-fresh-owner",
        "authenticated-peer-handshake-v1-android-confirmation-gate",
        "authenticated-peer-handshake-v1-android-provider-boundaries",
        "authenticated-peer-handshake-v1-android-regressions",
        "authenticated-peer-handshake-v1-android-gradle-gate",
        "authenticated-peer-handshake-v1-api29-plus-probe",
        "android-bound-peer-session-api29-plus-public-bind-probe",
        "host-restricted-peer-transcript-signer-foundation",
        "host-restricted-peer-transcript-signer-regressions",
        "host-restricted-peer-transcript-signer-cmake-isolation",
        "android-bound-peer-session-foundation",
        "android-bound-peer-session-confirmed-owner",
        "android-bound-peer-session-typed-identity-signer",
        "android-bound-peer-session-regression-gate",
        "formal-security-host-capability-switch",
        "formal-security-android-capability-switch",
        "formal-security-host-loader-contract",
        "formal-security-android-loader-contract",
        "pair-generation-proposal-v1-design-contract",
        "pair-generation-proposal-v1-python-foundation",
        "pair-generation-proposal-v1-python-regressions",
        "pair-generation-proposal-v1-cpp-foundation",
        "pair-generation-proposal-v1-cpp-regressions",
        "pair-generation-proposal-v1-cmake-isolation",
        "pair-generation-proposal-v1-android-foundation",
        "pair-generation-proposal-v1-android-regressions",
        "pair-generation-proposal-v1-android-gradle-gate",
        "pair-generation-credential-v1-design-contract",
        "pair-generation-credential-v1-crypto-foundation",
        "pair-generation-credential-v1-regressions",
        "dual-machine-reverse-resistance-threat-model",
        "dual-machine-reverse-resistance-release-gate-tests",
        "publishable-release-bundle-packager",
        "formal-release-manifest-signature-core",
        "publishable-release-bundle-packager-tests",
        "publishable-release-bundle-archive-verifier",
        "publishable-release-bundle-archive-verifier-tests",
        "release-material-generator-public-only",
        "release-material-generator-strict-tests",
        "offline-release-secret-generator",
        "offline-release-secret-generator-tests",
        "ow2-mobile-accuracy-evaluator",
        "ow2-mobile-accuracy-evaluator-tests",
        "ow2-mobile-accuracy-release-doc",
    }.issubset(names)


def test_formal_reverse_resistance_blocks_known_legacy_data_plane() -> None:
    results = check_reverse_resistance_contracts(ROOT)
    by_name = {result.name: result for result in results}

    assert set(by_name) == {
        *REQUIRED_REVERSE_RESISTANCE_CHECKS,
        REVERSE_RESISTANCE_REGISTRY_CHECK,
    }
    assert by_name[REVERSE_RESISTANCE_REGISTRY_CHECK].ok is True
    assert any(
        not by_name[name].ok for name in REQUIRED_REVERSE_RESISTANCE_CHECKS
    )
    assert by_name["reverse-resistance-host-data-plane-gate"].ok is False
    host_gate_evidence = by_name[
        "reverse-resistance-host-data-plane-gate"
    ].evidence
    assert (
        host_gate_evidence["constant_permit_count"] >= 1
        or host_gate_evidence["missing_authenticated_gate_tokens"]
    )
    video_envelope = by_name["reverse-resistance-video-aead-envelope"]
    assert video_envelope.ok is False
    assert video_envelope.evidence["missing_secure_header_tokens"]
    assert video_envelope.evidence["legacy_plaintext_markers"] == {}
    authenticated_idr = by_name["reverse-resistance-authenticated-idr"]
    assert authenticated_idr.ok is True
    assert authenticated_idr.evidence["legacy_idr_markers"] == {}


def test_host_identity_is_reported_when_fully_wired() -> None:
    results = check_reverse_resistance_contracts(ROOT)
    by_name = {result.name: result for result in results}

    identity = by_name[
        "reverse-resistance-host-independent-hardware-identity"
    ]

    assert identity.ok is True
    assert identity.evidence["foundation_present"] is True
    assert identity.evidence["linked_into_host"] is True
    assert identity.evidence["missing_host_runtime_identity_tokens"] == []
    assert identity.evidence["missing_machine_key_acl_markers"] == []
    assert identity.evidence["missing_machine_key_acl_test_tokens"] == []


def test_pair_generation_foundation_and_authorized_routes_are_reported(
) -> None:
    results = check_reverse_resistance_contracts(ROOT)
    handshake = {
        result.name: result for result in results
    }["reverse-resistance-handshake-channel-binding"]

    assert handshake.ok is False
    assert handshake.evidence["pair_generation_foundation_present"] is True
    assert (
        handshake.evidence["pair_generation_proposal_foundation_present"]
        is True
    )
    assert (
        handshake.evidence[
            "pair_generation_credential_crypto_foundation_present"
        ]
        is True
    )
    assert (
        handshake.evidence["pair_generation_public_route_registered"] is True
    )
    route_references = handshake.evidence[
        "pair_generation_public_route_references"
    ]
    assert route_references
    assert any(
        route.endswith("/pair-generations/challenges")
        for routes in route_references.values()
        for route in routes
    )
    assert any(
        route.endswith("/pair-generations/credentials")
        for routes in route_references.values()
        for route in routes
    )
    assert (
        handshake.evidence["signed_generation_credential_implemented"] is False
    )
    assert handshake.evidence["authoritative_service_wired"] is True
    assert handshake.evidence["authoritative_service_missing_paths"] == []
    assert handshake.evidence["authoritative_service_missing_tokens"] == {}
    assert (
        handshake.evidence["transactional_issuance_service_present"] is True
    )
    assert handshake.evidence["immutable_issuance_journal_wired"] is True
    assert handshake.evidence["client_generation_verifiers_wired"] is False
    assert handshake.evidence["formal_capability_markers_enabled"] is False
    assert handshake.evidence["signed_generation_credential_missing_tokens"]
    assert handshake.evidence["production_runtime_wired"] is False


@pytest.mark.parametrize(
    "missing_prerequisite",
    (
        "foundation_present",
        "foundation_tests_wired",
        "pair_generation_foundation_present",
        "pair_generation_proposal_foundation_present",
        "pair_generation_credential_crypto_foundation_present",
        "authoritative_service_wired",
        "immutable_issuance_journal_wired",
        "client_generation_verifiers_wired",
        "formal_capability_markers_enabled",
        "signed_generation_credential_implemented",
        "pair_generation_public_route_registered",
    ),
)
def test_handshake_fails_when_any_generation_prerequisite_is_missing(
    monkeypatch,
    tmp_path: Path,
    missing_prerequisite: str,
) -> None:
    host_path = (
        tmp_path
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "authenticated_pairing_handshake.cpp"
    )
    android_path = (
        tmp_path
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "AuthenticatedPairingHandshake.java"
    )
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text(
        "ECDH transcript channel_binding connection_id key_epoch",
        encoding="utf-8",
    )
    android_path.parent.mkdir(parents=True, exist_ok=True)
    android_path.write_text(
        "ECDH transcript channelBinding connectionId keyEpoch",
        encoding="utf-8",
    )

    evidence = {
        "foundation_present": True,
        "foundation_tests_wired": True,
        "pair_generation_foundation_present": True,
        "pair_generation_proposal_foundation_present": True,
        "pair_generation_credential_crypto_foundation_present": True,
        "authoritative_service_wired": True,
        "immutable_issuance_journal_wired": True,
        "client_generation_verifiers_wired": True,
        "formal_capability_markers_enabled": True,
        "signed_generation_credential_implemented": True,
        "pair_generation_public_route_registered": True,
    }
    monkeypatch.setattr(
        readiness_module,
        "_peer_handshake_foundation_evidence",
        lambda _root: evidence,
    )
    assert readiness_module._check_handshake_channel_binding(tmp_path).ok

    evidence[missing_prerequisite] = False
    assert not readiness_module._check_handshake_channel_binding(tmp_path).ok


@pytest.mark.parametrize(
    ("relative_path", "comment_only"),
    (
        ("service.py", "# authoritative_service_wired"),
        ("verifier.cpp", "// client_generation_verifiers_wired"),
        ("Verifier.java", "/* signed_generation_credential_implemented */"),
        ("build.gradle", "// formalSecureDataPlaneImplemented = true"),
        ("CMakeLists.txt", "# set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)"),
    ),
)
def test_executable_contracts_ignore_comment_only_decoys(
    tmp_path: Path,
    relative_path: str,
    comment_only: str,
) -> None:
    path = tmp_path / relative_path
    path.write_text(comment_only, encoding="utf-8")
    required = comment_only.lstrip("#/ *").rstrip(" */")

    missing_paths, missing_tokens = readiness_module._code_contract_gaps(
        {"decoy": (path, (required,))}
    )

    assert missing_paths == []
    assert missing_tokens == {"decoy": [required]}


def test_pair_generation_route_requires_a_real_router_decorator(
    tmp_path: Path,
) -> None:
    routes_path = tmp_path / "routes.py"
    routes_path.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "# @router.post('/pair-generations/credentials')\n"
        "DECOY = '/pair-generations/credentials'\n"
        "if False:\n"
        "    @router.post('/pair-generations/credentials')\n"
        "    def inactive_route():\n"
        "        return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == ()

    routes_path.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "class Nested:\n"
        "    @router.post('/pair-generations/credentials')\n"
        "    def nested_route(self):\n"
        "        return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == (
        "/api/dual-machine/v1/pair-generations/credentials",
    )

    routes_path.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "@router.post('/pair-generations/credentials')\n"
        "def issue_credential():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == (
        "/api/dual-machine/v1/pair-generations/credentials",
    )

    routes_path.write_text(
        "class APIRouter:\n"
        "    pass\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "@router.post('/pair-generations/credentials')\n"
        "def fake_router_route():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == ()

    routes_path.write_text(
        "from fastapi import APIRouter as Fake\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "@router.post('/pair-generations/credentials')\n"
        "def alias_decoy_route():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == ()

    routes_path.write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "router = FakeRouter()\n"
        "@router.post('/pair-generations/credentials')\n"
        "def rebound_router_route():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == ()

    routes_path.write_text(
        "from fastapi import APIRouter\n"
        "class APIRouter:\n"
        "    pass\n"
        "router = APIRouter(prefix='/api/dual-machine/v1')\n"
        "@router.post('/pair-generations/credentials')\n"
        "def rebound_class_route():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert readiness_module._python_route_literals(routes_path) == ()


def test_formal_capability_switch_requires_exact_files_and_loader_contracts(
    tmp_path: Path,
) -> None:
    paths = _write_formal_security_fixture(tmp_path, enabled=False)
    cmake_path = paths["cmake"]
    gradle_path = paths["gradle"]
    host_capability = paths["host_capability"]
    android_capability = paths["android_capability"]

    evidence = readiness_module._formal_security_marker_evidence(tmp_path)

    assert evidence["host_formal_security_marker_value"] == "OFF"
    assert evidence["android_formal_security_marker_value"] is False
    assert evidence["host_formal_security_loader_valid"] is True
    assert evidence["android_formal_security_loader_valid"] is True
    assert evidence["formal_capability_markers_enabled"] is False

    host_capability.write_text(
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)\n# extra\n",
        encoding="ascii",
    )
    android_capability.write_text(
        "formalSecureDataPlaneImplemented=true\nextra=true\n",
        encoding="ascii",
    )
    ambiguous = readiness_module._formal_security_marker_evidence(tmp_path)
    assert ambiguous["host_formal_security_marker_value"] is None
    assert ambiguous["android_formal_security_marker_value"] is None
    assert ambiguous["formal_capability_markers_enabled"] is False

    host_capability.write_text(
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)\n",
        encoding="ascii",
    )
    android_capability.write_text(
        "formalSecureDataPlaneImplemented=true\n",
        encoding="ascii",
    )
    cmake_path.write_text(
        cmake_path.read_text(encoding="utf-8")
        + "unset(VFDUAL_FORMAL_SECURITY_IMPLEMENTED)\n",
        encoding="utf-8",
    )
    gradle_path.write_text(
        gradle_path.read_text(encoding="utf-8")
        + "formalSecureDataPlaneImplemented = false\n",
        encoding="utf-8",
    )
    mutated_loader = readiness_module._formal_security_marker_evidence(tmp_path)
    assert mutated_loader["host_formal_security_marker_value"] == "ON"
    assert mutated_loader["android_formal_security_marker_value"] is True
    assert mutated_loader["host_formal_security_loader_valid"] is False
    assert mutated_loader["android_formal_security_loader_valid"] is False
    assert mutated_loader["formal_capability_markers_enabled"] is False


def test_formal_capability_rejects_nonexecuted_main_file_string_decoys(
    tmp_path: Path,
) -> None:
    paths = _write_formal_security_fixture(tmp_path, enabled=True)
    paths["cmake"].write_text(
        "cmake_minimum_required(VERSION 3.22)\n"
        "project(VisionForgeFormalSecurityDecoy LANGUAGES NONE)\n"
        "message([[include(\"${CMAKE_CURRENT_SOURCE_DIR}/"
        "formal_security_loader.cmake\")]])\n",
        encoding="utf-8",
    )
    paths["gradle"].write_text(
        "def loaderDecoy = \"apply from: "
        "'formal-security-loader.gradle'\"\n",
        encoding="utf-8",
    )

    evidence = readiness_module._formal_security_marker_evidence(tmp_path)

    assert evidence["host_formal_security_loader_source_valid"] is True
    assert evidence["android_formal_security_loader_source_valid"] is True
    assert evidence["host_formal_security_loader_valid"] is False
    assert evidence["android_formal_security_loader_valid"] is False
    assert evidence["formal_capability_markers_enabled"] is False


def test_schema_lineage_requires_one_exact_top_level_string_assignment(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "database.py"
    database_path.write_text(
        "# SCHEMA_VERSION = "
        "\"20260804_dual_machine_reactivation_mode_v9\"\n"
        "SCHEMA_VERSION = \"unapproved\"\n",
        encoding="utf-8",
    )
    assert readiness_module._python_top_level_string_assignment(
        database_path,
        "SCHEMA_VERSION",
    ) == "unapproved"

    database_path.write_text(
        "SCHEMA_VERSION = "
        "\"20260804_dual_machine_reactivation_mode_v9\"\n"
        "if True:\n"
        "    SCHEMA_VERSION = \"rebound\"\n",
        encoding="utf-8",
    )
    assert (
        readiness_module._python_top_level_string_assignment(
            database_path,
            "SCHEMA_VERSION",
        )
        is None
    )

    database_path.write_text(
        "SCHEMA_VERSION = "
        "\"20260804_dual_machine_reactivation_mode_v9\"\n",
        encoding="utf-8",
    )
    schema_version = readiness_module._python_top_level_string_assignment(
        database_path,
        "SCHEMA_VERSION",
    )
    assert schema_version in readiness_module.APPROVED_PAIR_GENERATION_SCHEMA_LINEAGE


@pytest.mark.parametrize(
    "rebind_source",
    (
        "import os as SCHEMA_VERSION\n",
        "from os import path as SCHEMA_VERSION\n",
        "def SCHEMA_VERSION():\n    return None\n",
        "class SCHEMA_VERSION:\n    pass\n",
        "match 'rebound':\n    case SCHEMA_VERSION:\n        pass\n",
        "try:\n    1 / 0\nexcept Exception as SCHEMA_VERSION:\n    pass\n",
    ),
)
def test_schema_lineage_rejects_module_level_rebinding_forms(
    tmp_path: Path,
    rebind_source: str,
) -> None:
    database_path = tmp_path / "database.py"
    database_path.write_text(
        "SCHEMA_VERSION = "
        "\"20260804_dual_machine_reactivation_mode_v9\"\n"
        + rebind_source,
        encoding="utf-8",
    )

    assert (
        readiness_module._python_top_level_string_assignment(
            database_path,
            "SCHEMA_VERSION",
        )
        is None
    )
    runtime_value = readiness_module._python_runtime_exact_string_constant(
        database_path,
        "SCHEMA_VERSION",
    )
    assert runtime_value not in readiness_module.APPROVED_PAIR_GENERATION_SCHEMA_LINEAGE


def test_formal_marker_completion_state_is_reachable_without_contract_conflict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write_formal_security_fixture(tmp_path, enabled=True)
    successful_probe = {
        "ok": True,
        "detail": "test_probe_executed",
        "returncode": 0,
    }
    monkeypatch.setattr(
        readiness_module,
        "_probe_host_formal_security_loader",
        lambda _root: successful_probe,
    )
    monkeypatch.setattr(
        readiness_module,
        "_probe_android_formal_security_loader",
        lambda _root: successful_probe,
    )

    result = readiness_module._check_no_plaintext_fallback(tmp_path)

    assert result.ok is True
    fixed_blockers = {
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)",
        "formalSecureDataPlaneImplemented = false",
    }
    assert all(
        fixed_blockers.isdisjoint(contract.required)
        for contract in readiness_module._source_contracts(ROOT)
    )


def test_enabled_formal_loaders_execute_real_build_system_probes(
    tmp_path: Path,
) -> None:
    _write_formal_security_fixture(tmp_path, enabled=True)
    gradle_project = tmp_path / "android_inference_benchmark"
    (gradle_project / "settings.gradle").write_text(
        "rootProject.name = 'VisionForgeFormalSecurityProbe'\n"
        "include ':app'\n",
        encoding="utf-8",
    )
    (gradle_project / "build.gradle").write_text("", encoding="utf-8")

    host_probe = readiness_module._probe_host_formal_security_loader(tmp_path)
    android_probe = readiness_module._probe_android_formal_security_loader(tmp_path)

    if host_probe["detail"] == "cmake_missing":
        pytest.skip("CMake is unavailable for the real formal-loader probe")
    if android_probe["detail"] == "gradle_wrapper_missing":
        pytest.skip("Gradle wrapper is unavailable for the real formal-loader probe")
    assert host_probe["ok"] is True, host_probe
    assert android_probe["ok"] is True, android_probe


def test_handshake_requires_independent_host_and_android_runtime_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    host_path = (
        tmp_path
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "authenticated_pairing_handshake.cpp"
    )
    android_path = (
        tmp_path
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "AuthenticatedPairingHandshake.java"
    )
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text(
        "ECDH transcript channel_binding connection_id key_epoch "
        "channelBinding connectionId keyEpoch",
        encoding="utf-8",
    )
    android_path.parent.mkdir(parents=True, exist_ok=True)
    android_path.write_text(
        "// ECDH transcript channelBinding connectionId keyEpoch",
        encoding="utf-8",
    )
    complete_evidence = {
        "foundation_present": True,
        "foundation_tests_wired": True,
        "pair_generation_foundation_present": True,
        "pair_generation_proposal_foundation_present": True,
        "pair_generation_credential_crypto_foundation_present": True,
        "authoritative_service_wired": True,
        "immutable_issuance_journal_wired": True,
        "client_generation_verifiers_wired": True,
        "formal_capability_markers_enabled": True,
        "signed_generation_credential_implemented": True,
        "pair_generation_public_route_registered": True,
    }
    monkeypatch.setattr(
        readiness_module,
        "_peer_handshake_foundation_evidence",
        lambda _root: complete_evidence,
    )

    result = readiness_module._check_handshake_channel_binding(tmp_path)

    assert result.ok is False
    assert result.evidence["host_missing_handshake_tokens"] == []
    assert result.evidence["android_missing_handshake_tokens"]


def test_reverse_resistance_registry_fails_when_required_check_is_missing() -> None:
    missing_name = sorted(REQUIRED_REVERSE_RESISTANCE_CHECKS)[0]
    results = [
        CheckResult(name, False, "pending", {})
        for name in REQUIRED_REVERSE_RESISTANCE_CHECKS
        if name != missing_name
    ]

    registry = _check_reverse_resistance_registry(results)

    assert registry.ok is False
    assert registry.evidence["missing"] == [missing_name]


def test_host_development_contract_does_not_require_insecure_formal_behavior() -> None:
    cmake = (ROOT / "dual_machine_runtime" / "CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    lifecycle_test = (
        ROOT
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "tests"
        / "host_ui_lifecycle_contract_tests.cpp"
    ).read_text(encoding="utf-8")
    formal_loader = (
        ROOT
        / "dual_machine_runtime"
        / "formal_security_loader.cmake"
    ).read_text(encoding="utf-8")

    assert "option(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY" in cmake
    assert (
        ROOT
        / "dual_machine_runtime"
        / "formal_security_capability.cmake"
    ).read_text(encoding="ascii") == (
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n"
    )
    assert "formal_security_loader.cmake" in cmake
    assert "Formal secure data plane is not implemented" in formal_loader
    assert 'runtime_run.find("return true;")' not in lifecycle_test
    assert (
        'runtime_source.find("install_authenticated_formal_runtime") =='
        not in lifecycle_test
    )


def test_development_diagnostic_never_reports_formal_release_success() -> None:
    results = [
        CheckResult("base", True, "ok", {}),
        CheckResult(
            "reverse-resistance-test",
            False,
            "not implemented",
            {},
        ),
    ]

    report = json.loads(_json_report(results, mode="development"))

    assert report["schema"] == READINESS_SCHEMA
    assert report["requested_mode"] == "development"
    assert report["mode"] == "diagnostic"
    assert report["diagnostic_completed"] is True
    assert report["base_checks_ok"] is True
    assert report["reverse_resistance_ok"] is False
    assert report["strict_ok"] is False
    assert report["formal_eligible"] is False
    assert report["formal_ok"] is False
    assert report["formal_release_ok"] is False
    assert report["bypasses"] == []
    assert report["ok"] is False


def test_strict_report_cannot_claim_formal_eligibility() -> None:
    results = [
        CheckResult("base", True, "ok", {}),
        CheckResult(REVERSE_RESISTANCE_REGISTRY_CHECK, True, "ok", {}),
    ]

    report = json.loads(_json_report(results, mode="strict"))

    assert report["checks_ok"] is True
    assert report["strict_ok"] is True
    assert report["ok"] is True
    assert report["formal_ok"] is False
    assert report["formal_release_ok"] is False


def test_authenticated_data_plane_regressions_are_wired_without_formal_claim() -> None:
    cmake = (ROOT / "dual_machine_runtime" / "CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    gradle = (
        ROOT / "android_inference_benchmark" / "app" / "build.gradle"
    ).read_text(encoding="utf-8")
    android_internals = (
        ROOT
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "dataplane"
        / "AuthenticatedDataPlaneV2Internals.java"
    ).read_text(encoding="utf-8")

    assert "shared/src/authenticated_data_plane_v2.cpp" in cmake
    assert "vfdual_authenticated_data_plane_v2_tests" in cmake
    assert "vfdual_host_cng_device_identity_tests" in cmake
    assert "compileAuthenticatedDataPlaneV2SelfTest" in gradle
    assert "verifyAuthenticatedDataPlaneV2" in gradle
    assert "preReleaseBuild" in gradle
    assert "PacketEncryptor" not in android_internals
    assert "EncryptionAttemptHook" in android_internals
    assert (
        ROOT
        / "dual_machine_runtime"
        / "formal_security_capability.cmake"
    ).read_text(encoding="ascii") == (
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n"
    )
    assert (
        ROOT
        / "android_inference_benchmark"
        / "app"
        / "formal-security-capability.properties"
    ).read_text(encoding="ascii") == (
        "formalSecureDataPlaneImplemented=false\n"
    )


def test_authenticated_peer_handshake_regressions_are_wired_without_formal_claim(
) -> None:
    runtime_root = ROOT / "dual_machine_runtime"
    android_app = ROOT / "android_inference_benchmark" / "app"
    cmake = (runtime_root / "CMakeLists.txt").read_text(encoding="utf-8")
    gradle = (android_app / "build.gradle").read_text(encoding="utf-8")
    cpp_tests = (
        runtime_root / "tests" / "authenticated_peer_handshake_v1_tests.cpp"
    ).read_text(encoding="utf-8")
    instrumentation_dir = (
        android_app
        / "src/androidTest/java/com/visionforge/inferencebenchmark"
    )
    runner = (
        instrumentation_dir / "PairingIdentityTestInstrumentation.java"
    ).read_text(encoding="utf-8")
    probe = (
        instrumentation_dir / "AuthenticatedPeerHandshakeV1InstrumentationProbe.java"
    ).read_text(encoding="utf-8")
    bound_probe = (
        instrumentation_dir
        / "AndroidBoundPeerHandshakeSessionInstrumentationProbe.java"
    ).read_text(encoding="utf-8")

    assert cmake.count("shared/src/authenticated_peer_handshake_v1.cpp") == 2
    assert "add_library(vfdual_authenticated_peer_handshake_v1 STATIC" in cmake
    assert "add_executable(vfdual_authenticated_peer_handshake_v1_tests" in cmake
    assert cmake.count(
        "VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS=1"
    ) == 1
    assert "!std::is_move_constructible_v<" in cpp_tests
    host_signer_header = (
        runtime_root
        / "host/windows/security/include/vfdual"
        / "host_peer_handshake_transcript_signer_v1.hpp"
    ).read_text(encoding="utf-8")
    assert "HostSignedPeerHandshakeContextV1" in host_signer_header
    assert "build_and_sign_bound_transcript" in host_signer_header
    assert not any(
        token in host_signer_header
        for token in ("sign_bytes", "sign_digest", "sign_sha256_digest")
    )
    host_link_body = cmake.split(
        "target_link_libraries(VisionForgeHost PRIVATE", 1
    )[1].split(")", 1)[0]
    assert "vfdual_host_peer_handshake_transcript_signer_v1" not in host_link_body
    assert "compileAuthenticatedPeerHandshakeV1SelfTest" in gradle
    assert gradle.count("tasks.named('verifyAuthenticatedPeerHandshakeV1')") >= 3
    assert gradle.count(
        "tasks.named('verifyAndroidBoundPeerHandshakeSession')"
    ) >= 3
    assert "JavaVersion.VERSION_1_8" in gradle
    assert "options.release.set(8)" in gradle
    assert "testInstrumentationRunner(" in gradle
    assert "AuthenticatedPeerHandshakeV1InstrumentationProbe.verify()" in runner
    assert "AndroidBoundPeerHandshakeSessionInstrumentationProbe.verify()" in runner
    assert "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK" in runner
    assert "generateFreshEphemeralKeyAgreement" in probe
    assert "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q" in probe
    assert "AndroidPairingIdentityStore" in bound_probe
    assert "bindExpectedPair" in bound_probe
    assert "confirmHostFinished" in bound_probe
    assert "requireMatchingSecrets" in bound_probe
    assert "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q" in bound_probe

    main_dir = (
        android_app
        / "src/main/java/com/visionforge/inferencebenchmark/handshake"
    )
    main_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(main_dir.glob("*.java"))
    )
    forbidden_seams = (
        "forTestPrivateScalar",
        "sec1ForTestScalar",
        "finishedKeyForTest",
        "channelBindingExporterForTest",
    )
    assert not any(token in main_text for token in forbidden_seams)

    results = check_reverse_resistance_contracts(ROOT)
    handshake = {
        result.name: result for result in results
    }["reverse-resistance-handshake-channel-binding"]
    assert handshake.ok is False
    assert handshake.evidence["foundation_present"] is True
    assert handshake.evidence["foundation_tests_wired"] is True
    assert handshake.evidence["wiring_errors"] == []
    assert "api29_plus_bound_peer_probe" in handshake.evidence["gate_paths"]
    assert handshake.evidence["gate_missing_paths"] == []
    assert handshake.evidence["gate_missing_tokens"] == {}
    assert handshake.evidence["production_runtime_wired"] is False
    assert (
        runtime_root / "formal_security_capability.cmake"
    ).read_text(encoding="ascii") == (
        "set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n"
    )
    assert (
        android_app / "formal-security-capability.properties"
    ).read_text(encoding="ascii") == (
        "formalSecureDataPlaneImplemented=false\n"
    )
