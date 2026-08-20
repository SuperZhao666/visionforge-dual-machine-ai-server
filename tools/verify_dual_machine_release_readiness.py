from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tokenize
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DUAL_MACHINE_API_PREFIX = "/api/dual-machine/v1"
ACTIVATION_CHALLENGE_ROUTE = "/license-activations/challenges"
READINESS_SCHEMA = "visionforge-dual-machine-release-readiness-v3"
READINESS_MODES = ("diagnostic", "strict", "formal", "development")
DEVELOPMENT_MODE_ALIAS = "development"
APPROVED_PAIR_GENERATION_SCHEMA_LINEAGE = frozenset(
    {
        "20260804_dual_machine_pair_generation_foundation_v8",
        "20260804_dual_machine_reactivation_mode_v9",
        "20260804_dual_machine_generation_credential_journal_v10",
        "20260804_dual_machine_verified_pair_bootstrap_v11",
        "20260804_dual_machine_pair_security_schema_attestation_v12",
    }
)
HOST_FORMAL_SECURITY_CAPABILITIES: Mapping[bytes, str] = {
    b"set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF)\n": "OFF",
    b"set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ON)\n": "ON",
}
ANDROID_FORMAL_SECURITY_CAPABILITIES: Mapping[bytes, bool] = {
    b"formalSecureDataPlaneImplemented=false\n": False,
    b"formalSecureDataPlaneImplemented=true\n": True,
}
EXPECTED_HOST_FORMAL_SECURITY_LOADER = (
    b'include("${CMAKE_CURRENT_LIST_DIR}/formal_security_capability.cmake")\n'
    b"if(NOT DEFINED VFDUAL_FORMAL_SECURITY_IMPLEMENTED OR\n"
    b'        NOT "${VFDUAL_FORMAL_SECURITY_IMPLEMENTED}" MATCHES '
    b'"^(ON|OFF)$")\n'
    b'    message(FATAL_ERROR "Formal security capability must be exactly '
    b'ON or OFF")\n'
    b"endif()\n"
    b"if(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY AND\n"
    b"        NOT VFDUAL_FORMAL_SECURITY_IMPLEMENTED)\n"
    b"    message(FATAL_ERROR\n"
    b'        "Formal secure data plane is not implemented; refusing to build '
    b'a release candidate")\n'
    b"endif()\n"
    b"set(VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT\n"
    b'    "visionforge-formal-security-loader-v1"\n'
    b'    CACHE INTERNAL "Executed formal security loader contract" FORCE)\n'
)
EXPECTED_ANDROID_FORMAL_SECURITY_LOADER = (
    b"def formalSecurityCapabilityFile = "
    b"file('formal-security-capability.properties')\n"
    b"if (!formalSecurityCapabilityFile.isFile()) {\n"
    b"    throw new GradleException(\n"
    b'            "Formal security capability file is missing: '
    b'${formalSecurityCapabilityFile}")\n'
    b"}\n"
    b"def formalSecurityCapabilityProperties = new Properties()\n"
    b"formalSecurityCapabilityFile.withInputStream {\n"
    b"    formalSecurityCapabilityProperties.load(it)\n"
    b"}\n"
    b"def formalSecurityCapabilityValue = formalSecurityCapabilityProperties\n"
    b"        .getProperty('formalSecureDataPlaneImplemented')\n"
    b"if (!(formalSecurityCapabilityValue in ['true', 'false'])) {\n"
    b"    throw new GradleException(\n"
    b"            'formalSecureDataPlaneImplemented must be exactly true or false')\n"
    b"}\n"
    b"ext.formalSecureDataPlaneImplemented = Boolean.parseBoolean(\n"
    b"        formalSecurityCapabilityValue)\n"
    b"def formalSecureDataPlaneOnly = providers\n"
    b"        .gradleProperty('visionforgeFormalSecureDataPlaneOnly')\n"
    b"        .getOrElse('false')\n"
    b"        .toBoolean()\n"
    b"tasks.register('verifyFormalSecureDataPlaneImplemented') {\n"
    b"    group = 'verification'\n"
    b"    description = 'Blocks formal APK output until Secure v2 is fully implemented.'\n"
    b"    doLast {\n"
    b"        if (!formalSecureDataPlaneOnly) {\n"
    b"            throw new GradleException(\n"
    b"                    'Formal release must set -PvisionforgeFormalSecureDataPlaneOnly=true')\n"
    b"        }\n"
    b"        if (!formalSecureDataPlaneImplemented) {\n"
    b"            throw new GradleException(\n"
    b"                    'Formal secure data plane is not implemented; refusing release APK')\n"
    b"        }\n"
    b"        println(\n"
    b"                'VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT=v1:'\n"
    b"                        + formalSecureDataPlaneImplemented)\n"
    b"    }\n"
    b"}\n"
    b"def formalReleaseArtifactTaskNames = ['packageRelease', 'bundleRelease']\n"
    b"tasks.configureEach { task ->\n"
    b"    if (task.name in formalReleaseArtifactTaskNames) {\n"
    b"        task.dependsOn(tasks.named('verifyFormalSecureDataPlaneImplemented'))\n"
    b"    }\n"
    b"}\n"
    b"tasks.register('probeFormalSecurityReleaseGraphContract') {\n"
    b"    group = 'verification'\n"
    b"    description = 'Proves the formal gate is in the Android release task graph.'\n"
    b"    doLast {\n"
    b"        def formalTask = tasks.named(\n"
    b"                'verifyFormalSecureDataPlaneImplemented').get()\n"
    b"        formalReleaseArtifactTaskNames.each { String taskName ->\n"
    b"            def releaseTask = tasks.named(taskName).get()\n"
    b"            def dependencies = releaseTask.taskDependencies\n"
    b"                    .getDependencies(releaseTask)\n"
    b"            if (!dependencies.contains(formalTask)) {\n"
    b"                throw new GradleException(\n"
    b'                        "Formal security verification is absent from ${taskName}")\n'
    b"            }\n"
    b"        }\n"
    b"        println(\n"
    b"                'VFDUAL_FORMAL_SECURITY_RELEASE_GRAPH=v1:'\n"
    b"                        + 'packageRelease,bundleRelease'\n"
    b"                        + '->verifyFormalSecureDataPlaneImplemented')\n"
    b"    }\n"
    b"}\n"
)


EXPECTED_SECURITY_HEADER_TOKENS: Mapping[str, tuple[str, ...]] = {
    "cache-control": ("no-store",),
    "strict-transport-security": (
        "max-age=31536000",
        "includesubdomains",
    ),
    "x-content-type-options": ("nosniff",),
    "x-frame-options": ("deny",),
    "referrer-policy": ("no-referrer",),
    "cross-origin-resource-policy": ("same-site",),
    "permissions-policy": (
        "camera=()",
        "geolocation=()",
        "microphone=()",
    ),
}


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    evidence: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SourceContract:
    name: str
    path: Path
    required: tuple[str, ...]
    forbidden: tuple[str, ...] = ()


def _configure_utf8_stdio() -> None:
    """Keep Chinese release-gate output readable in non-UTF-8 consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _pass(
    name: str,
    detail: str,
    evidence: Mapping[str, Any] | None = None,
) -> CheckResult:
    return CheckResult(name=name, ok=True, detail=detail, evidence=evidence or {})


def _fail(
    name: str,
    detail: str,
    evidence: Mapping[str, Any] | None = None,
) -> CheckResult:
    return CheckResult(name=name, ok=False, detail=detail, evidence=evidence or {})


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _python_top_level_string_assignment(path: Path, name: str) -> str | None:
    """Return one exact module assignment and reject executable reassignments."""
    if not path.is_file():
        return None
    try:
        tree = ast.parse(_read_text(path), filename=str(path))
    except (SyntaxError, ValueError):
        return None

    assignment: ast.Assign | ast.AnnAssign | None = None
    target: ast.Name | None = None
    value: ast.expr | None = None
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == name
            ):
                if assignment is not None:
                    return None
                assignment = statement
                target = statement.targets[0]
                value = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == name
        ):
            if assignment is not None:
                return None
            assignment = statement
            target = statement.target
            value = statement.value

    if (
        assignment is None
        or target is None
        or not isinstance(value, ast.Constant)
        or type(value.value) is not str
    ):
        return None

    bindings: list[ast.AST] = []

    class ModuleAssignmentVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node.name == name:
                bindings.append(node)
            for expression in (
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
            ):
                if expression is not None:
                    self.visit(expression)
            if node.returns is not None:
                self.visit(node.returns)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if node.name == name:
                bindings.append(node)
            for expression in (*node.decorator_list, *node.bases):
                self.visit(expression)
            for keyword in node.keywords:
                self.visit(keyword.value)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return None

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".", 1)[0]
                if bound_name == name:
                    bindings.append(alias)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            for alias in node.names:
                bound_name = alias.asname or alias.name
                if bound_name == name:
                    bindings.append(alias)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name == name:
                bindings.append(node)
            self.generic_visit(node)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name == name:
                bindings.append(node)
            if node.pattern is not None:
                self.visit(node.pattern)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name == name:
                bindings.append(node)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest == name:
                bindings.append(node)
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            if node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                bindings.append(node)

    ModuleAssignmentVisitor().visit(tree)
    if len(bindings) != 1 or bindings[0] is not target:
        return None
    return value.value


def _python_runtime_exact_string_constant(path: Path, name: str) -> str | None:
    """Import a Python module in isolation and read one exact built-in string."""
    if not path.is_file() or not name.isidentifier():
        return None
    probe = r'''
import importlib
import importlib.util
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]).resolve()
name = sys.argv[2]
package_init = path.parent / "__init__.py"
if package_init.is_file():
    sys.path.insert(0, str(path.parent.parent))
    module = importlib.import_module(f"{path.parent.name}.{path.stem}")
else:
    spec = importlib.util.spec_from_file_location("vf_runtime_constant", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("constant module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
value = getattr(module, name, None)
payload = value if type(value) is str else None
print("VFDUAL_RUNTIME_CONSTANT=" + json.dumps(payload, separators=(",", ":")))
'''
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", probe, str(path), name],
            cwd=str(
                path.parent.parent
                if (path.parent / "__init__.py").is_file()
                else path.parent
            ),
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    prefix = "VFDUAL_RUNTIME_CONSTANT="
    lines = [line for line in result.stdout.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        return None
    try:
        value = json.loads(lines[0][len(prefix):])
    except (json.JSONDecodeError, TypeError):
        return None
    return value if type(value) is str else None


def _base_source_contracts(root: Path) -> tuple[SourceContract, ...]:
    server_root = root / "server" / "visionforge-platform"
    sidecar_root = server_root / "dual_machine_service"
    deploy_root = server_root / "deploy"
    android_root = root / "android_inference_benchmark" / "app" / "src"
    host_root = root / "dual_machine_runtime" / "host" / "windows"
    shared_root = root / "dual_machine_runtime" / "shared" / "include"

    return (
        SourceContract(
            name="sidecar-systemd-isolation",
            path=deploy_root / "vf-dual-machine.service",
            required=(
                "User=vf-dual-machine",
                "EnvironmentFile=/etc/visionforge-dual-machine/service.env",
                "python -m dual_machine_service.run",
                "StateDirectory=visionforge-dual-machine",
                "NoNewPrivileges=true",
                "UMask=0077",
            ),
            forbidden=("app.main", "--port 8000"),
        ),
        SourceContract(
            name="sidecar-nginx-route-and-headers",
            path=deploy_root / "nginx" / "dual_machine_api_location.conf.example",
            required=(
                "location ^~ /api/dual-machine/v1/",
                "proxy_pass http://127.0.0.1:8010;",
                "proxy_set_header X-Forwarded-For $remote_addr;",
                "client_max_body_size 16k;",
                'add_header Strict-Transport-Security "max-age=31536000; '
                'includeSubDomains" always;',
                'add_header X-Content-Type-Options "nosniff" always;',
                'add_header X-Frame-Options "DENY" always;',
                'add_header Referrer-Policy "no-referrer" always;',
                'add_header Cross-Origin-Resource-Policy "same-site" always;',
                'add_header Permissions-Policy "camera=(), geolocation=(), '
                'microphone=()" always;',
                'add_header Cache-Control "no-store" always;',
                'add_header Content-Security-Policy "default-src \'none\'; '
                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'\" "
                "always;",
                "add_header X-Request-ID $request_id always;",
            ),
            forbidden=("$proxy_add_x_forwarded_for", "127.0.0.1:8000"),
        ),
        SourceContract(
            name="sidecar-runtime-security-headers",
            path=sidecar_root / "main.py",
            required=(
                'response.headers["Cache-Control"] = "no-store"',
                'response.headers["X-Trace-Id"]',
                'response.headers["Strict-Transport-Security"]',
                'response.headers["X-Content-Type-Options"] = "nosniff"',
                'response.headers["X-Frame-Options"] = "DENY"',
                'response.headers["Referrer-Policy"] = "no-referrer"',
                'response.headers["Cross-Origin-Resource-Policy"] = '
                '"same-site"',
                'response.headers["Permissions-Policy"]',
            ),
        ),
        SourceContract(
            name="sidecar-api-isolation",
            path=sidecar_root / "routes.py",
            required=(
                'APIRouter(prefix="/api/dual-machine/v1")',
                "config_filename=os.devnull",
                "@router.post(\"/license-activations/challenges\")",
                "@router.post(\"/usage-sessions/start-challenges\")",
                "@router.post(\"/usage-sessions/start\")",
                "@router.post(\"/entitlements/{entitlement_id}/status\")",
            ),
            forbidden=("username", "password", "app.main"),
        ),
        SourceContract(
            name="sidecar-card-admin-not-public-api",
            path=sidecar_root / "routes.py",
            required=(
                "@router.post(\"/license-activations/challenges\")",
                "@router.post(\"/license-activations/confirm\")",
                "@router.post(\"/entitlements/{entitlement_id}/status\")",
            ),
            forbidden=(
                "CardIssuanceService",
                "DualMachineAdminService",
                "issue_batch",
                "revoke_batch",
                "revoke_entitlement",
                "/admin",
                "/license-batches",
            ),
        ),
        SourceContract(
            name="sidecar-card-admin-local-cli",
            path=sidecar_root / "admin_cli.py",
            required=(
                "VisionForge dual-machine local administration",
                'commands.add_parser("issue")',
                'commands.add_parser("revoke-batch")',
                'commands.add_parser("revoke-entitlement")',
                "DualMachineAdminService(settings)",
            ),
            forbidden=("APIRouter", "FastAPI", "@router"),
        ),
        SourceContract(
            name="sidecar-card-secrets-never-persisted-test",
            path=sidecar_root / "tests" / "test_card_activation.py",
            required=(
                "test_card_code_plaintext_is_never_persisted_to_database_or_audit",
                "def _sidecar_text_cells(",
                "forbidden_values = (*issuance.codes, "
                'challenge["challenge_token"])',
                "assert leaked_cells == []",
            ),
        ),
        SourceContract(
            name="sidecar-status-query-replay-protection",
            path=sidecar_root / "usage_service.py",
            required=(
                "def entitlement_status(",
                'scope="entitlement_status"',
                'self._nonce_digest(\n                    normalized["request_nonce"]',
                "usage_request_replayed",
                "connection.commit()",
            ),
        ),
        SourceContract(
            name="billing-starts-only-after-formal-use",
            path=sidecar_root / "tests" / "test_api_isolation.py",
            required=(
                "test_http_billing_starts_only_after_explicit_formal_start",
                "_assert_no_usage_billing(settings)",
                'start_challenge["billing_started"] is False',
                'started["billing_started"] is True',
                "SELECT COUNT(*) FROM dm_usage_sessions",
                "SELECT COUNT(*) FROM dm_usage_ledger",
            ),
        ),
        SourceContract(
            name="sidecar-http-formal-use-full-chain-test",
            path=sidecar_root / "tests" / "test_api_isolation.py",
            required=(
                "usage_heartbeat_payload",
                "usage_stop_payload",
                "heartbeat_response.status_code == 200",
                'renewed["total_consumed_seconds"] == (',
                "stop_response.status_code == 200",
                'stopped["charged_seconds"] == 0',
                '("ended", "user_stopped")',
            ),
        ),
        SourceContract(
            name="sidecar-http-status-replay-test",
            path=sidecar_root / "tests" / "test_api_isolation.py",
            required=(
                "replayed_status_response.status_code == 409",
                '"usage_request_replayed"',
                "_assert_no_usage_billing(settings)",
            ),
        ),
        SourceContract(
            name="sidecar-status-replay-test",
            path=sidecar_root / "tests" / "test_entitlement_status.py",
            required=(
                "test_status_nonce_replay_is_rejected_without_billing",
                "usage_request_replayed",
                "_assert_no_billing_and_no_session(activated_pair)",
            ),
        ),
        SourceContract(
            name="sidecar-pair-generation-schema-foundation",
            path=sidecar_root / "database.py",
            required=(
                'SCHEMA_VERSION = "20260804_dual_machine_pair_security_schema_attestation_v12"',
                "PAIR_GENERATION_CREDENTIAL_JOURNAL_SCHEMA_VERSION = (",
                "CREATE TABLE IF NOT EXISTS dm_pair_security_state (",
                "CREATE TABLE IF NOT EXISTS dm_pair_generation_challenges (",
                "CREATE TABLE IF NOT EXISTS dm_pair_generation_allocations (",
                'connection.execute("BEGIN IMMEDIATE")',
                "_migrate_pair_security_schema(connection)",
                "_migrate_pair_generation_allocation_schema",
                "_reinstall_pair_security_triggers",
                "PAIR_SECURITY_TRIGGER_NAMES = (",
                "PAIR_SECURITY_INDEX_NAMES",
                "_reinstall_pair_security_indexes",
                "CREATE UNIQUE INDEX idx_dm_pair_one_issued_challenge ",
                "ON dm_pair_generation_challenges(pair_id) ",
                "WHERE status = 'issued'",
                "dm_pair_allocations_reject_update",
                "dm_pair_allocations_reject_delete",
                "dm_pair_allocations_validate_insert",
                "dm_pair_allocations_validate_insert",
                "dm_pair_state_reject_delete",
                "dm_pair_state_reject_identity_update",
                "dm_pair_state_reject_rollback",
                "dm_pair_state_validate_transition",
                "dm_pair_challenge_reject_delete",
                "dm_pair_challenge_reject_content_update",
                "dm_pair_challenge_reject_terminal_update",
                'legacy_table = "dm_pair_generation_allocations_with_credential_v7"',
                'removed_columns = {"credential_token", "credential_sha256"}',
                "pair generation allocation migration requires operator recovery",
                "DROP TRIGGER IF EXISTS",
                "BEGIN IMMEDIATE",
            ),
            forbidden=(
                "CREATE TRIGGER IF NOT EXISTS dm_pair_",
                "CREATE INDEX idx_dm_pair_one_issued_challenge ",
            ),
        ),
        SourceContract(
            name="sidecar-pair-generation-repository-foundation",
            path=sidecar_root / "pair_security_repository.py",
            required=(
                "def register_pending_pair(",
                "binding_revision = _next_binding_revision(",
                "def issue_generation_challenge(",
                "def allocate_generation(",
                "_require_exact_allocation_retry",
                "_require_live_binding(connection, identity)",
                "_require_issued_challenge(",
                "_advance_generation_high_water(",
                "_consume_challenge(",
                "_insert_allocation(",
                "connection.execute(\"BEGIN IMMEDIATE\")",
            ),
            forbidden=(
                "def activate_pair(",
            ),
        ),
        SourceContract(
            name="sidecar-pair-generation-concurrency-migration-tests",
            path=sidecar_root / "tests" / "test_pair_generation.py",
            required=(
                "test_pending_revision_is_server_allocated_and_retry_revalidates_binding",
                "test_concurrent_exact_allocation_retry_returns_one_stored_tuple",
                "test_same_challenge_different_allocation_requests_have_one_winner",
                "test_same_allocation_request_different_payload_has_one_exact_winner",
                "test_initialization_replaces_a_weak_known_security_trigger",
                "test_initialization_replaces_weak_allocation_authority_trigger",
                "test_database_rejects_allocation_that_does_not_match_consumed_challenge",
                "test_initialization_replaces_wrong_one_issued_challenge_index",
                "test_initialization_rejects_preexisting_duplicate_issued_challenges",
                "test_true_legacy_schema_without_pair_tables_upgrades_fail_closed",
                "test_orphaned_allocation_migration_table_requires_operator_recovery",
                "test_half_upgraded_credential_schema_is_removed_and_reentry_is_exact",
            ),
        ),
        SourceContract(
            name="sidecar-pair-generation-route-no-direct-repository-access",
            path=sidecar_root / "routes.py",
            required=(
                'APIRouter(prefix="/api/dual-machine/v1")',
            ),
            forbidden=(
                "PairSecurityRepository",
                "pair_security_repository",
                "issue_generation_challenge",
                "allocate_generation",
            ),
        ),
        SourceContract(
            name="android-inference-start-auto-billing-ui",
            path=(
                android_root
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "MainActivity.java"
            ),
            required=(
                "public void onStartInference()",
                "authorizationUiState.canStartFormalUse()",
                "pipelineStarting = true;",
                "binder.startFormalUsage();",
                "status_inference_starting",
                "public void onStopInference()",
                "binder.stopFormalUsage();",
                "operator_inference_stop",
            ),
            forbidden=(
                "public void onStartFormalUsage()",
                "public void onStopFormalUsage()",
                "requestFormalUsageStartAfterConfirmation()",
                "authorization_formal_start_confirm_title",
                "authorization_formal_start_confirm_detail",
            ),
        ),
        SourceContract(
            name="android-inference-start-user-copy",
            path=(
                android_root
                / "main"
                / "res"
                / "values"
                / "dual_machine_authorization_strings.xml"
            ),
            required=(
                "卡密与剩余时间",
                "主机配置包",
                "开始推理",
                "成功启动后",
                "剩余时间不会减少",
            ),
            forbidden=(
                "正式使用",
                "Secure v2",
                "数据面",
                "票据",
                "刷新余额与授权状态",
                "累计正式使用",
            ),
        ),
        SourceContract(
            name="android-inference-start-static-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "MobileRuntimeServiceCommandContractSelfTest.java"
            ),
            required=(
                "public void onStartInference()",
                "status_inference_starting",
                "!activity.contains(\"public void onStartFormalUsage()\")",
                "!authorizationStrings.contains(\"正式使用\")",
                "postFrameCallbackDelayed(",
                "removeFrameCallback(frameCallback)",
            ),
        ),
        SourceContract(
            name="android-card-key-mode-no-login-ui-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineAuthorizationCardModeContractSelfTest.java"
            ),
            required=(
                "Keeps the Android authorization UI in traditional card-key mode.",
                "Card-key activation and remaining-time presentation boundary",
                'count(authorizationScreen, "new EditText(context)") == 2',
                "DualMachineCardCode.normalizeAndValidate(raw);",
                "actions.onActivateCard(normalized);",
                "!authorizationScreen.contains(\"section_formal_usage\")",
                "void onStartInference();",
                "!actions.contains(\"onLogin\")",
                "authorization_username",
                "authorization_password",
            ),
        ),
        SourceContract(
            name="android-status-query-fresh-nonce-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineCardAuthorizationCoordinatorSelfTest.java"
            ),
            required=(
                "String firstStatusNonce = fixture.sidecar.lastStatusNonce;",
                "String secondStatusNonce = fixture.sidecar.lastStatusNonce;",
                "check(!firstStatusNonce.equals(secondStatusNonce));",
                "check(fixture.sidecar.statusRequests == 2);",
                "lastStatusNonce = request.requestNonce;",
            ),
        ),
        SourceContract(
            name="android-inference-start-fresh-network-identity-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineFormalUsageCoordinatorSelfTest.java"
            ),
            required=(
                "checkDistinctRequestIdentity(",
                "startChallengeRequestId",
                "startUsageRequestId",
                "heartbeatRequestId",
                "stopRequestId",
                "check(!fixture.sidecar.heartbeatRequestNonce.equals(",
                "check(!fixture.sidecar.stopRequestNonce.equals(",
            ),
        ),
        SourceContract(
            name="android-release-security-material-fail-closed",
            path=(
                android_root
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineReleaseSecurityConfig.java"
            ),
            required=(
                "parsePins(",
                "dual_machine_tls_pin_rotation_set_invalid",
                "parseTicketKeys(",
                "dual_machine_ticket_key_duplicated",
                "RSAPublicKey",
                "rsaPublicKey.getModulus().bitLength() < 3072",
                "dual_machine_ticket_public_key_too_weak",
                "DualMachineTlsPinPolicy",
                "DualMachineUsageLeaseKeyring",
            ),
            forbidden=("PRIVATE KEY-----\" +",),
        ),
        SourceContract(
            name="android-https-sidecar-transport-hardening",
            path=(
                android_root
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineHttpsJsonTransport.java"
            ),
            required=(
                "connection.connect();",
                "verifyPins(connection);",
                "connection.getOutputStream()",
                "connection.setInstanceFollowRedirects(false);",
                "connection.setFixedLengthStreamingMode(contentLength);",
                '"authentication route is not HTTPS"',
                '"sidecar destination escaped base origin"',
                "MAXIMUM_REQUEST_BYTES = 64 * 1024",
                "MAXIMUM_RESPONSE_BYTES = 128 * 1024",
                'baseUrl must be an HTTPS origin',
                'value.startsWith("/api/dual-machine/v1/")',
            ),
            forbidden=("setFollowRedirects(true)", "http://"),
        ),
        SourceContract(
            name="android-https-sidecar-transport-static-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineHttpsJsonTransportSelfTest.java"
            ),
            required=(
                "happyPathOrderHeadersAndBody(",
                "pinMismatchWritesNoSensitiveByte(",
                "redirectDisabledAndNotFollowed(",
                "apiPathAndBaseUrlEscapeRejected(",
                "responseLimitEnforced(",
                'bodyAt > pinAt',
                '!connection.events.contains("getOutputStream")',
                "factory.openCount == 1",
            ),
        ),
        SourceContract(
            name="android-release-build-security-input-gate",
            path=root / "android_inference_benchmark" / "app" / "build.gradle",
            required=(
                "verifyDualMachineReleaseSecurityInputs",
                "verifyProductionReleaseVersion",
                "productionVersionCode = 4",
                "productionVersionName = '1.0.1'",
                "previouslyReleasedVersionCode = 3",
                "Production versionName must be stable SemVer without a prerelease label",
                "task.name in ['packageRelease', 'bundleRelease']",
                "Release requires 2-4 distinct SHA-256 SPKI pins",
                "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS",
                "Release requires 1-3 pinned RS256 public ticket keys.",
                "publicKey.modulus.bitLength() < 3072",
                "MessageDigest.isEqual(publicKey.encoded, der)",
                "production_usage_ticket_v1_public.pem",
                "deployedDualMachineTicketPublicKeyFile",
                "does not match the deployed production Sidecar key",
                "task.name == 'packageRelease'",
                "verifyReleaseSigningIdentity",
                "requireProductionReleaseSigningCertificate",
                "androidDebugCertSha256",
                "Release signing keystore must stay outside the repository workspace.",
                "Release signing certificate is the Android Debug certificate.",
                "verifyDualMachineHttpsJsonTransport",
                "verifyDualMachineSidecarHttpClient",
                "verifyMobileReleaseContracts",
                "readQnnSdkIdentity",
                "sdk.yaml",
                "readQnnModelSdkIdentity",
                "QNN SDK/model toolchain identity mismatch",
                "verifyQnnSdkModelToolchainIdentityPolicy",
                "apply from: 'formal-security-loader.gradle'",
            ),
            forbidden=(
                "VISIONFORGE_DUAL_MACHINE_TICKET_PRIVATE_KEY",
                "PRIVATE KEY-----\" +",
            ),
        ),
        SourceContract(
            name="release-material-generator-public-only",
            path=root / "tools" / "prepare_dual_machine_release_materials.py",
            required=(
                "This tool never reads ticket private keys.",
                "fetch_leaf_tls_spki_pin",
                "--tls-connect-host",
                "--current-tls-pin",
                "ticket public key must be RSA-3072 or stronger",
                "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS",
                "write_android_gradle_env_files",
                "dual-machine-android-gradle-env.ps1",
                "dual-machine-android-release-build-command.txt",
                "Public-only material",
                "generated_files",
                "<path-to-android-release-signing-secrets.ps1>",
            ),
            forbidden=(
                "load_pem_private_key",
                "PRIVATE KEY-----\" +",
                "VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64",
            ),
        ),
        SourceContract(
            name="release-material-generator-strict-tests",
            path=root / "tests" / "test_prepare_dual_machine_release_materials.py",
            required=(
                "test_strict_release_fails_without_backup_pin_or_ticket_key",
                "test_current_tls_pin_override_does_not_open_network",
                "test_release_material_json_contains_no_private_key_material",
                "test_release_material_writer_emits_public_gradle_env_files",
                "write_android_gradle_env_files",
                'assert "PRIVATE KEY" not in serialized',
                'assert "STORE_PASSWORD" not in serialized',
                'assert "pem_base64" not in report["ticket_public_keys"][0]',
                '"<path-to-android-release-signing-secrets.ps1>"',
                "current_tls_pin=current_pin",
            ),
        ),
        SourceContract(
            name="offline-release-secret-generator",
            path=root
            / "tools"
            / "create_dual_machine_offline_release_secrets.py",
            required=(
                "Generate dual-machine production candidate secrets",
                "refusing to write production secrets inside the repository",
                "rsa.generate_private_key(",
                "key_size=ticket_key_bits",
                "key_size=backup_tls_key_bits",
                "dual-machine-ticket-private.pem",
                "dual-machine-ticket-public.pem",
                "dual-machine-backup-tls.csr.pem",
                "prepare_dual_machine_release_materials.py",
                "These files are secrets. Do not commit them",
            ),
            forbidden=("print(ticket_private", "print(backup_tls_private"),
        ),
        SourceContract(
            name="offline-release-secret-generator-tests",
            path=root
            / "tests"
            / "test_create_dual_machine_offline_release_secrets.py",
            required=(
                "test_offline_secret_generator_creates_release_ready_public_inputs",
                "test_offline_secret_generator_refuses_repository_output",
                "test_offline_secret_generator_refuses_to_overwrite_without_force",
                'assert "BEGIN PRIVATE KEY" not in serialized',
                "load_ticket_public_key_material",
                "validate_tls_pin",
            ),
        ),
        SourceContract(
            name="ow2-mobile-accuracy-evaluator",
            path=root / "tools" / "evaluate_yolo_detection_accuracy.py",
            required=(
                "TRACE_CSV_HEADER = (\"frame_id\", \"class_id\", "
                "\"confidence\", \"x1\", \"y1\", \"x2\", \"y2\")",
                "def evaluate_detection_accuracy(",
                "def _average_precision(",
                "MAP_THRESHOLDS",
                "mAP50-95",
                "--require-complete",
                "--min-map50",
                "OW2_MOBILE_ACCURACY_EVALUATION_OK",
            ),
        ),
        SourceContract(
            name="ow2-mobile-accuracy-evaluator-tests",
            path=root / "tests" / "test_evaluate_yolo_detection_accuracy.py",
            required=(
                "test_yolo_detection_accuracy_scores_multiclass_trace_csv",
                "test_yolo_detection_accuracy_high_confidence_false_positive_reduces_ap",
                "test_yolo_detection_accuracy_requires_complete_prediction_coverage",
                "test_yolo_detection_accuracy_writes_reader_friendly_markdown",
                'assert summary["map50"] == 1.0',
                'assert summary["missing_prediction_samples"] == ["2"]',
            ),
        ),
        SourceContract(
            name="ow2-mobile-accuracy-release-doc",
            path=root / "docs" / "OW2_MOBILE_ACCURACY_EVALUATION.md",
            required=(
                "# OW2 手机模型精度评测门禁",
                "tools\\evaluate_yolo_detection_accuracy.py",
                "frame_id,class_id,confidence,x1,y1,x2,y2",
                "--require-complete",
                "mAP@0.50",
                "mAP50-95",
                "不允许进入正式生产模型列表",
            ),
        ),
        SourceContract(
            name="host-release-build-security-input-gate",
            path=host_root / "build_host_application.bat",
            required=(
                "VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64 is required",
                "-DVFDUAL_ENFORCE_HOST_RELEASE_SECURITY_INPUTS=ON",
                "--target verify_host_release_security_inputs",
                "VFHost.exe",
            ),
            forbidden=(
                "VFDUAL_DUAL_MACHINE_TICKET_PRIVATE_KEY",
                "PRIVATE KEY",
            ),
        ),
        SourceContract(
            name="host-secure-control-does-not-encrypt-video",
            path=host_root / "src" / "host_secure_v2_control_service.cpp",
            required=("video_encrypted=false",),
        ),
        SourceContract(
            name="host-control-plane-boundary-doc",
            path=(
                host_root
                / "include"
                / "vfdual"
                / "host_secure_v2_control_service.hpp"
            ),
            required=(
                "It never encrypts, encodes or sends video.",
                "before each video publish attempt.",
            ),
        ),
        SourceContract(
            name="host-session-boundary-doc",
            path=host_root / "include" / "vfdual" / "host_secure_v2_session.hpp",
            required=(
                "does not encode, encrypt or transmit video",
                "seals only small lease/control frames",
            ),
        ),
        SourceContract(
            name="secure-v2-wire-leaves-video-traffic-unchanged",
            path=shared_root / "vfdual" / "secure_v2_wire.hpp",
            required=(
                "does not compress, encrypt, fragment or otherwise change "
                "video traffic.",
            ),
        ),
        SourceContract(
            name="host-ui-discloses-video-boundary",
            path=host_root / "src" / "streamer_desktop_app.cpp",
            required=(
                "Host 只推屏幕视频，不加密视频、不执行控制。",
                "Secure v2 只负责许可门控",
            ),
        ),
    )


def check_source_contracts(root: Path = ROOT) -> list[CheckResult]:
    results: list[CheckResult] = []
    for contract in _source_contracts(root):
        if not contract.path.exists():
            results.append(_fail(
                contract.name,
                "source file is missing",
                {"path": str(contract.path)},
            ))
            continue

        text = _read_text(contract.path)
        missing = [item for item in contract.required if item not in text]
        forbidden = [item for item in contract.forbidden if item in text]
        if missing or forbidden:
            results.append(_fail(
                contract.name,
                "source contract failed",
                {
                    "path": str(contract.path),
                    "missing": missing,
                    "forbidden_present": forbidden,
                },
            ))
            continue

        results.append(_pass(
            contract.name,
            "source contract passed",
            {"path": str(contract.path)},
        ))
    return results


def _source_contracts(root: Path = ROOT) -> tuple[SourceContract, ...]:
    android_root = (
        root / "android_inference_benchmark" / "app" / "src"
    )
    sidecar_root = (
        root / "server" / "visionforge-platform" / "dual_machine_service"
    )
    replaced = {
        "android-inference-start-auto-billing-ui",
        "android-inference-start-static-test",
        "android-release-build-security-input-gate",
        "android-inference-start-user-copy",
        "host-release-build-security-input-gate",
        "host-secure-control-does-not-encrypt-video",
        "host-control-plane-boundary-doc",
        "host-session-boundary-doc",
        "secure-v2-wire-leaves-video-traffic-unchanged",
        "host-ui-discloses-video-boundary",
        "release-material-generator-public-only",
        "android-card-key-mode-no-login-ui-test",
    }
    inherited = [
        contract
        for contract in _base_source_contracts(root)
        if contract.name not in replaced
    ]
    inherited.extend((
        SourceContract(
            name="android-inference-start-auto-billing-ui",
            path=(
                android_root
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "MainActivity.java"
            ),
            required=(
                "MobileRuntimeService.ensureRunning(this);",
                "control_gate=automatic_fail_closed",
            ),
            forbidden=(
                "public void onStartInference()",
                "public void onStopInference()",
                "binder.startFormalUsage();",
                "binder.stopFormalUsage();",
                "requestFormalUsageStartAfterConfirmation()",
                "authorization_formal_start_confirm_title",
                "authorization_formal_start_confirm_detail",
            ),
        ),
        SourceContract(
            name="android-inference-start-static-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "MobileRuntimeServiceCommandContractSelfTest.java"
            ),
            required=(
                '!activity.contains("public void onStartInference()")',
                '!activity.contains("public void onStopInference()")',
                '!activity.contains("binder.startFormalUsage()")',
                "attemptAutomaticFormalUsageStart(runtime, generationReceipt);",
                'requestFormalUsageStop(\\"inference_progress_stalled\\")',
                "postFrameCallbackDelayed(",
                "removeFrameCallback(frameCallback)",
            ),
        ),
        SourceContract(
            name="android-release-build-security-input-gate",
            path=root / "android_inference_benchmark" / "app" / "build.gradle",
            required=(
                "verifyDualMachineReleaseSecurityInputs",
                "verifyProductionReleaseVersion",
                "dualMachineAndroidRelease.version_code",
                "dualMachineReleaseVersionFile",
                "../dual_machine_runtime/release_version.txt",
                "productionVersionName = dualMachineReleaseVersionFile.text.trim()",
                "dualMachineAndroidRelease.previous_version_code",
                "Production versionName must be stable SemVer without a prerelease label",
                "task.name in ['packageRelease', 'bundleRelease']",
                "Release requires 2-4 distinct SHA-256 SPKI pins",
                "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS",
                "Release requires 1-3 pinned RS256 public ticket keys.",
                "publicKey.modulus.bitLength() < 3072",
                "MessageDigest.isEqual(publicKey.encoded, der)",
                "production_usage_ticket_v1_public.pem",
                "deployedDualMachineTicketPublicKeyFile",
                "does not match the deployed production Sidecar key",
                "task.name == 'packageRelease'",
                "verifyReleaseSigningIdentity",
                "requireProductionReleaseSigningCertificate",
                "androidDebugCertSha256",
                "Release signing keystore must stay outside the repository workspace.",
                "Release signing certificate is the Android Debug certificate.",
                "readQnnSdkIdentity",
                "sdk.yaml",
                "readQnnModelSdkIdentity",
                "QNN SDK/model toolchain identity mismatch",
                "verifyQnnSdkModelToolchainIdentityPolicy",
            ),
        ),
        SourceContract(
            name="android-card-key-mode-no-login-ui-test",
            path=(
                android_root
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "DualMachineAuthorizationCardModeContractSelfTest.java"
            ),
            required=(
                "Keeps the Android authorization UI in traditional card-key mode.",
                "Card-key activation and remaining-time presentation boundary",
                'count(authorizationScreen, "new EditText(context)") == 1',
                "DualMachineCardCode.normalizeAndValidate(raw);",
                "actions.onActivateCard(normalized);",
                "!authorizationScreen.contains(\"pairingPackage\")",
                "!actions.contains(\"onImportPairingPackage\")",
                "!automationIds.contains(\"PAIRING_PACKAGE\")",
                "!authorizationScreen.contains(\"section_formal_usage\")",
                "!actions.contains(\"onStartInference\")",
                "!actions.contains(\"onStopInference\")",
                "!actions.contains(\"onLogin\")",
                "authorization_username",
                "authorization_password",
                "authorization.balanceKnown",
                "R.string.authorization_balance_pending",
                "if (authorization.permanent)",
            ),
        ),
        SourceContract(
            name="release-material-generator-public-only",
            path=root / "tools" / "prepare_dual_machine_release_materials.py",
            required=(
                "This tool never reads ticket private keys.",
                "fetch_leaf_tls_spki_pin",
                "--tls-connect-host",
                "--current-tls-pin",
                "ticket public key must be RSA-3072 or stronger",
                "VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS",
                "host_release_inputs",
                '"HOST_AUTHORIZATION_GATE": "required"',
                '"HOST_RELEASE_SECURITY_INPUTS": "public_verification_keyring_required"',
                '"HOST_IDENTITY_PRIVATE_KEY": "local_cng_tpm_non_exportable"',
                '"HOST_FORMAL_RELEASE_STATUS": "blocked_until_secure_v2_implemented"',
                "write_android_gradle_env_files",
                "dual-machine-android-gradle-env.ps1",
                "dual-machine-android-release-build-command.txt",
                "Public-only material",
                "generated_files",
                "<path-to-android-release-signing-secrets.ps1>",
            ),
            forbidden=(
                "load_pem_private_key",
                "PRIVATE KEY-----\" +",
                "VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64",
                "VFDUAL_ENFORCE_HOST_RELEASE_SECURITY_INPUTS",
            ),
        ),
        SourceContract(
            name="android-card-key-direct-user-copy",
            path=(
                android_root
                / "main"
                / "res"
                / "values"
                / "dual_machine_authorization_strings.xml"
            ),
            required=(
                "卡密剩余时间",
                "待同步",
                "永久",
                "已自动布防",
                "Host 只负责推送屏幕画面",
            ),
            forbidden=(
                "卡密与剩余时间",
                "主机配置包",
                "配对包",
                "Secure v2",
                "票据",
                "数据面",
                "正式使用",
            ),
        ),
        SourceContract(
            name="android-release-installer-production-signer-gate",
            path=root / "android_inference_benchmark" / "tools" / "install_mobile_release.ps1",
            required=(
                "function Resolve-ApkSignerPath",
                "function Assert-MobileApkSigningIdentity",
                "function Assert-AndroidProductionSigningInputs",
                "tools/verify_android_production_signing_inputs.py",
                "Assert-AndroidProductionSigningInputs $workspaceRoot",
                "APK Signature Scheme v2",
                "APK Signature Scheme v3",
                "Production APK must not use APK Signature Scheme v1",
                "Production APK must contain exactly one current signer",
                "[string]::IsNullOrWhiteSpace($env:QNN_SDK_ROOT)",
                "$defaultQnnRoot",
                "Resolve-Path -LiteralPath $qnnRoot",
                "CN=Android Debug",
                "APK is signed with the Android Debug certificate and cannot be used",
                "Assert-MobileApkSigningIdentity $apk $workspaceRoot ([bool]$AllowDevelopmentSigning)",
            ),
        ),
        SourceContract(
            name="android-production-signing-input-preflight",
            path=root / "tools" / "verify_android_production_signing_inputs.py",
            required=(
                "visionforge-android-production-signing-inputs-v1",
                "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
                "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
                "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
                "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
                "VISIONFORGE_ALLOW_DEVELOPMENT_SIGNING",
                "ANDROID_DEBUG_CERT_SHA256",
                "-storepass:env",
                "release signing keystore must be outside the repository",
                "release signing certificate is the Android Debug certificate",
            ),
        ),
        SourceContract(
            name="android-release-keystore-generator",
            path=root / "tools" / "create_android_release_keystore.py",
            required=(
                "visionforge-android-release-keystore-v1",
                "refusing to write Android release keystore inside the repository",
                "STORE_PASSWORD_ENV",
                "KEY_PASSWORD_ENV",
                "visionforge-android-release.jks",
                "-storepass:env",
                "-keypass:env",
                "verify_android_production_signing_inputs.py",
                "Password values are intentionally not written by this tool.",
                "Do not commit them",
            ),
            forbidden=(
                "STORE_PASSWORD_ENV] +",
                "KEY_PASSWORD_ENV] +",
            ),
        ),
        SourceContract(
            name="android-release-keystore-generator-tests",
            path=root / "tests" / "test_create_android_release_keystore.py",
            required=(
                "test_android_release_keystore_generator_creates_safe_release_inputs",
                "test_android_release_keystore_generator_refuses_repository_output",
                "test_android_release_keystore_generator_requires_password_env",
                "test_android_release_keystore_generator_refuses_overwrite",
                "test_android_release_keystore_generator_rejects_debug_certificate",
                'assert "store-secret" not in all_generated_text',
                'assert "key-secret" not in all_generated_text',
            ),
        ),
        SourceContract(
            name="android-production-release-apk-builder",
            path=root / "tools" / "build_android_production_release.py",
            required=(
                "visionforge-android-production-release-build-v1",
                "verify_android_production_signing_inputs",
                "verify_android_release_apk",
                "require_production_signing=True",
                ":app:verifyMobileRuntimeSnapshot",
                ":app:assembleRelease",
                "-PvisionforgeFormalSecureDataPlaneOnly=true",
                "--offline",
                "VFMobile_",
                ".sha256",
                "android_production_release_build.json",
                "signing_errors",
                "next_actions",
                "_build_next_actions",
                "_signing_required_env",
                "create_android_release_keystore.py",
            ),
            forbidden=(
                "visionforgeAllowDevelopmentSigning",
                "allow-development-android-signing",
            ),
        ),
        SourceContract(
            name="android-production-release-apk-builder-tests",
            path=root / "tests" / "test_build_android_production_release.py",
            required=(
                "test_android_release_build_stops_when_signing_preflight_fails",
                "test_android_release_build_copies_verified_apk_and_writes_sha256",
                "test_android_release_build_stops_when_apk_static_verification_fails",
                'assert "-PvisionforgeAllowDevelopmentSigning=true" not in command',
                'assert "-PvisionforgeFormalSecureDataPlaneOnly=true" in command',
                'assert report["signing_errors"] ==',
                'assert report["next_actions"][0]["required_env"] ==',
                'assert "create_android_release_keystore.py" in report["next_actions"][0]["command"]',
                'assert report["next_actions"] == []',
                'assert report["stage"] == "android_apk_static_verification"',
            ),
        ),
        SourceContract(
            name="android-production-signing-input-preflight-tests",
            path=root / "tests" / "test_verify_android_production_signing_inputs.py",
            required=(
                "test_production_signing_inputs_fail_when_material_is_missing",
                "test_production_signing_inputs_reject_development_signing_switch",
                "test_production_signing_inputs_reject_repository_keystore",
                "test_production_signing_inputs_reject_android_debug_certificate",
                "test_production_signing_inputs_accept_non_debug_certificate",
            ),
        ),
        SourceContract(
            name="android-installer-emits-formal-device-evidence",
            path=root / "android_inference_benchmark" / "tools" / "install_mobile_release.ps1",
            required=(
                "function Write-FormalDeviceEvidence",
                'Write-Host "VISIONFORGE_MOBILE_UI_OK',
                "tools/create_formal_device_evidence.py",
                "formal_device_evidence.json",
                "--require-complete",
                "BluetoothRouteEvidencePath",
                "BluetoothRouteMobileLogPath",
                "MakcuRouteEvidencePath",
                "MakcuRouteMobileLogPath",
                "FinalSafeIdleEvidencePath",
                "FinalSafeIdleMobileLogPath",
                "FinalSafeIdleUiXmlPath",
                "--bluetooth-route-evidence",
                "--makcu-route-evidence",
                "--final-safe-idle-evidence",
                "mobile-logcat.txt",
                "formal_device_evidence=$formalDeviceEvidence",
            ),
            forbidden=('Write-Output "VISIONFORGE_MOBILE_UI_OK',),
        ),
        SourceContract(
            name="android-model-target-ui-hides-unsupported-classes",
            path=android_root
            / "main"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "ui"
            / "ControlScreen.java",
            required=(
                "state.activeModel.supports(entry.getKey())",
                "setVisibility(supported ? View.VISIBLE : View.GONE)",
                "supported && entry.getKey() == state.aimTarget",
            ),
        ),
        SourceContract(
            name="android-overwatch-enemy-target-contract-test",
            path=android_root
            / "test"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "MobileRuntimeServiceCommandContractSelfTest.java",
            required=(
                "sharedModelContractPath",
                "dual_machine_runtime",
                "model_contract.hpp",
                "!inference.model().supports(target)",
                "if (!model.supports(selected)) return;",
                "return profile.supports(restored) ? restored : profile.defaultAimTarget;",
                "model.supports(selectedAimTarget)",
                "overwatch2-416-yolov5",
                "counter-strike-2-vombit-416-v8s",
                ".body_class_id = 0U",
                ".head_class_id = kNoModelClass",
                "enemy_body",
                "non_enemy_body",
                "ct_body",
                "ct_head",
                "t_body",
                "t_head",
            ),
        ),
        SourceContract(
            name="android-overwatch-native-enemy-class-control-test",
            path=android_root / "main" / "cpp" / "MobileControlCoreTests.cpp",
            required=(
                "overwatch_enemy_body_config",
                "config.head_class_id = vfdual::kNoModelClass",
                "config.selected_class_id = 0U",
                "config.selected_class_uses_geometric_head = true",
                "test_overwatch_non_enemy_body_class_is_ignored",
                "ControlSuppressionReason::no_valid_target",
                "rejected_unsupported_class == 1U",
                "rejected_unsupported_class == 2U",
                "selected.target_x - 210.0F",
            ),
        ),
        SourceContract(
            name="formal-release-bundle-verifier-fail-closed",
            path=root / "tools" / "verify_formal_release_bundle.py",
            required=(
                "visionforge-formal-release-bundle-v1",
                "EXPECTED_ANDROID_MODELS",
                "EXPECTED_QNN_HTP_RUNTIME",
                "FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS",
                "AuthenticatedPeerHandshakeV1SelfTest",
                "PairGenerationProposalV1SelfTest",
                "AndroidBoundPeerHandshakeSessionSelfTest",
                "AuthenticatedPeerHandshakeV1InstrumentationProbe",
                "AndroidBoundPeerHandshakeSessionInstrumentationProbe",
                "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK",
                "RejectingPrivateKey",
                "APK DEX contains authenticated-handshake test-only crypto seams",
                "APK is signed with Android Debug certificate",
                "device evidence JSON is required for formal release",
                "device evidence device_serial is missing",
                "device evidence installed_package_version is missing",
                "device evidence installed_package_version does not match Android APK",
                "expected_package_version",
                "ui_evidence_package_scope",
                "overwatch_enemy_target_contract",
                "counter_strike_2_faction_target_contract",
                "game_model_display_names_visible",
                "EXPECTED_GAME_DISPLAY_NAMES",
                "game_display_name_errors",
                "game_display_names",
                "无畏契约",
                "守望先锋",
                "三角洲行动",
                "反恐精英2",
                "EXPECTED_MODEL_TARGET_CONTRACTS",
                "model_target_contract_errors",
                "model_target_contracts",
                "lock_class_id",
                "lock_class_name",
                "enemy_body",
                "non_enemy_body",
                "geometric_body_box",
                "cross_faction_pairing_allowed",
                "control_move_lock_smoke",
                "bluetooth_hid_physical_e2e",
                "makcu_usb_physical_e2e",
                "dual_output_routes_same_apk",
                "physical_output_route_errors",
                "final_safe_idle_restored",
                "final_safe_idle_errors",
                "verify_source_contracts(ROOT)",
            ),
        ),
        SourceContract(
            name="formal-release-bundle-verifier-tests",
            path=root / "tests" / "test_verify_formal_release_bundle.py",
            required=(
                "test_device_evidence_requires_physical_full_chain_flags",
                "test_device_evidence_requires_device_serial_and_installed_version",
                "test_device_evidence_rejects_installed_package_version_mismatch",
                "expected_package_version=\"1.0.0-rc1\"",
                "test_device_evidence_requires_chinese_game_display_names",
                "game_display_names.overwatch2-416-yolov5",
                "test_device_evidence_requires_overwatch_enemy_class_contract",
                "model_target_contracts.overwatch2-416-yolov5.lock_class_name",
                "test_device_evidence_requires_cs2_faction_class_contract",
                "cross_faction_pairing_allowed",
                "test_inspect_apk_zip_rejects_handshake_test_crypto_seam",
            ),
        ),
        SourceContract(
            name="formal-device-evidence-generator",
            path=root / "tools" / "create_formal_device_evidence.py",
            required=(
                "DEVICE_EVIDENCE_SCHEMA",
                "REQUIRED_DEVICE_EVIDENCE_FLAGS",
                "_missing_complete_evidence_fields",
                "device_serial",
                "installed_package_version",
                "ui_evidence_package_scope",
                "_ui_evidence_package_scope",
                "EXPECTED_ANDROID_PACKAGE",
                "qnn_htp_graph_execute",
                "game_model_display_names_visible",
                "EXPECTED_GAME_DISPLAY_NAMES",
                "_has_content_desc_with_text",
                "_game_model_display_names_visible",
                "game_display_names",
                "overwatch_enemy_target_contract",
                "counter_strike_2_faction_target_contract",
                "EXPECTED_MODEL_TARGET_CONTRACTS",
                "_model_target_contracts",
                "model_target_contracts",
                "ethernet_link",
                "host_mobile_stream_connected",
                "control_move_lock_smoke",
                "physical_output_routes",
                "final_safe_idle",
                "final_safe_idle_errors",
                "legacy_generic_move_signal_is_release_proof",
                "VISIONFORGE_FORMAL_DEVICE_EVIDENCE",
            ),
        ),
        SourceContract(
            name="formal-device-evidence-generator-tests",
            path=root / "tests" / "test_create_formal_device_evidence.py",
            required=(
                "test_build_device_evidence_sets_all_checks_from_real_artifacts_and_logs",
                "test_main_reports_incomplete_when_ui_nodes_belong_to_other_package",
                "com.fake.overlay",
                '"ui_evidence_package_scope"] is False',
                "game_model_display_names_visible",
                "EXPECTED_GAME_DISPLAY_NAMES",
                '"lock_class_id"] == 0',
                '"cross_faction_pairing_allowed"] is False',
                '"lock_class_name"] == "enemy_body"',
                '"ignored_class_names"] == ["non_enemy_body"]',
                "test_main_require_complete_fails_when_device_metadata_is_missing",
            ),
        ),
        SourceContract(
            name="physical-output-route-evidence",
            path=root / "tools" / "physical_output_route_evidence.py",
            required=(
                "visionforge-physical-output-route-evidence-v1",
                "bluetooth_hid_send_report_accepted",
                "native_bluetooth_hid_api_acceptances_advanced",
                "makcu_native_device_acknowledgements_advanced",
                "makcu_java_device_acknowledgements_advanced",
                "km.MAKCU\\r\\n>>> ",
                "windows_cursor_moved",
                "route_activity_correlated_with_cursor",
                "valid_segment_count",
                "ROUTE_SELECTION_CONTEXT_MILLIS",
                "route_selection_timestamp_unix_ms",
                "source_mobile_logs",
                "route_evidence_errors",
            ),
        ),
        SourceContract(
            name="physical-output-route-evidence-tests",
            path=root / "tests" / "test_physical_output_route_evidence.py",
            required=(
                "test_static_windows_cursor_cannot_prove_physical_output",
                "test_cursor_reset_across_invalid_warmup_gap_is_not_counted_as_movement",
                "test_latest_recent_route_selection_may_precede_measurement_window",
                "test_later_different_route_selection_invalidates_measurement_route",
                "test_bluetooth_api_acceptance_must_advance_during_capture",
                "test_makcu_ack_counters_must_advance_during_capture",
                "test_prefilled_true_checks_are_recomputed_from_raw_records",
                "test_cursor_csv_parser_accepts_powershell_utc_format",
            ),
        ),
        SourceContract(
            name="final-safe-idle-evidence",
            path=root / "tools" / "final_safe_idle_evidence.py",
            required=(
                "visionforge-final-safe-idle-evidence-v1",
                "dual_physical_acceptance_bound",
                "safe_idle_after_physical_acceptance",
                "makcu_route_restored",
                "side_button_2_restored",
                "formal_usage_closed_locally",
                "formal_usage_stop_server_confirmed",
                "inference_pipeline_stopped",
                "control_output_fail_closed",
                "no_later_runtime_reactivation",
                "ui_output_gate_disabled",
                "final_safe_idle_evidence_errors",
                "VISIONFORGE_FINAL_SAFE_IDLE_EVIDENCE",
            ),
        ),
        SourceContract(
            name="final-safe-idle-evidence-tests",
            path=root / "tests" / "test_final_safe_idle_evidence.py",
            required=(
                "test_final_safe_idle_evidence_recomputes_complete_terminal_state",
                "test_final_safe_idle_rejects_later_state_override",
                "test_final_safe_idle_rejects_unconfirmed_server_stop",
                "test_final_safe_idle_rejects_prefilled_green_checks",
            ),
        ),
        SourceContract(
            name="dual-machine-physical-acceptance-doc",
            path=root / "docs" / "DUAL_MACHINE_PHYSICAL_ACCEPTANCE.md",
            required=(
                "同一个 APK SHA256",
                "最终默认路线必须恢复为 `makcu_usb`",
                "最终触发键必须恢复为 `mouse5`",
                "server_confirmed=true",
                "native_move_completion_pending=0",
                "采集最终 XML",
                "不得再安装、启动、导航或操作 App、Host、手机",
                "final_safe_idle_evidence.py",
                "create_formal_device_evidence.py",
                "visionforge-dual-machine-device-evidence-v3",
            ),
        ),
        SourceContract(
            name="windows-cursor-evidence-capture",
            path=root / "tools" / "capture_windows_cursor_samples.py",
            required=(
                "GetCursorPos",
                "AndroidApkSha256",
                "DeviceSerial",
                "VISIONFORGE_WINDOWS_CURSOR_SAMPLES",
                "duration-seconds",
                "warmup-seconds",
                "warmup_setup",
                "interval-millis",
            ),
            forbidden=(
                "SetCursorPos",
                "mouse_event",
                "SendInput",
            ),
        ),
        SourceContract(
            name="formal-release-acceptance-orchestrator",
            path=root / "tools" / "run_formal_release_acceptance.py",
            required=(
                "visionforge-formal-release-acceptance-v1",
                "verify_android_production_signing_inputs.py",
                "build_android_signing_preflight_command",
                "android_signing_preflight",
                "android_signing_report_text = str(android_signing_report)",
                "return 7",
                "verify_android_release_apk_artifact.py",
                "build_android_apk_preflight_command",
                "android_apk_preflight",
                "android_release_apk_preflight.json",
                "return 6",
                "verify_android_device_connectivity.py",
                "build_android_device_preflight_command",
                "android_device_preflight",
                "android_device_connectivity.json",
                "return 5",
                "install_mobile_release.ps1",
                "-Launch",
                "-VerifyUi",
                "-BluetoothRouteEvidencePath",
                "-BluetoothRouteMobileLogPath",
                "-MakcuRouteEvidencePath",
                "-MakcuRouteMobileLogPath",
                "-FinalSafeIdleEvidencePath",
                "-FinalSafeIdleMobileLogPath",
                "-FinalSafeIdleUiXmlPath",
                "--bluetooth-route-evidence",
                "--makcu-route-evidence",
                "--final-safe-idle-evidence",
                "--final-safe-idle-mobile-log",
                "--final-safe-idle-ui-xml",
                "formal_device_evidence=",
                "stage_formal_device_evidence",
                "device_evidence_sources",
                "_stage_evidence_files",
                "formal device evidence sources.ui_evidence_dir is missing",
                "formal device evidence sources.{label} is missing",
                "formal_device_evidence.json",
                "Formal device evidence staging failed",
                "verify_formal_release_bundle.py",
                "build_publishable_packager_command",
                "package_formal_release_bundle.py",
                "publishable_packager",
                "publishable_bundle_dir",
                "summarize_publishable_bundle",
                "parse_publishable_packager_report_path",
                "summarize_publishable_packager_rejection",
                "publishable_bundle",
                "publishable_packager_report",
                "publishable_packager_rejection",
                "formal_release_manifest.json",
                "formal_release_bundle.zip",
                "formal_release_bundle.zip.sha256",
                "publishable_release_bundle_verify.json",
                "archive_sha256",
                "archive_sha256_sidecar_digest",
                "archive_verifier_ok",
                "Publishable release bundle artifact validation failed",
                "publishable archive sha256 sidecar does not name archive",
                "returncode=5",
                "publishable_release",
                "build_android_production_release.py",
                "parse_android_release_artifact_path",
                "resolve_android_release_artifact",
                "Android release build report is missing",
                "Android release build report is not complete",
                "Android release artifact path does not match the build report",
                "Android release APK sha256 sidecar is missing",
                "android_release_builder",
                "android_release_report",
                "android_release_report_text",
                "android_release_dir",
                "android_production_signing_inputs.json",
                "release_blockers",
                "next_actions",
                "print_release_blocker_summary",
                "[ERROR] release blockers:",
                "[ERROR] next actions:",
                "_command_diagnostic_details",
                "_command_primary_detail",
                "_compact_primary_detail_line",
                "_next_action_for_blocker",
                "_android_device_report_next_action",
                "_release_next_actions",
                "ANDROID_RELEASE_SIGNING_ENV_VARS",
                "create_android_release_keystore.py",
                "production-signed release APK",
                "adb mdns services",
                "adb devices",
                '"commands"',
                '"hint"',
                'value.split(" report=", 1)[0].rstrip(" ;")',
                "prefix_budget",
                '"detail": _command_primary_detail(result)',
                '"details": _command_diagnostic_details(result)',
                '"details": details',
                "build_acceptance_run_parameters",
                "run_parameters",
                "android_apk_input",
                "timeouts_sec",
                "android_apk_preflight",
                "android_device_preflight",
                "build_apk=False",
                "return 4",
                "--device-evidence",
                "formal_release_bundle_verify.json",
            ),
            forbidden=(
                "--allow-development-android-signing",
                "-AllowDevelopmentSigning",
            ),
        ),
        SourceContract(
            name="formal-release-acceptance-orchestrator-tests",
            path=root / "tests" / "test_run_formal_release_acceptance.py",
            required=(
                "test_build_install_command_forwards_both_physical_route_evidence_sets",
                "-FinalSafeIdleEvidencePath",
                "-FinalSafeIdleMobileLogPath",
                "-FinalSafeIdleUiXmlPath",
                "test_formal_acceptance_stops_when_android_apk_preflight_fails",
                "test_command_primary_detail_preserves_specific_error_after_long_header",
                "test_command_primary_detail_removes_report_path_noise_from_single_line",
                "reason=no_authorized_device",
                "APK is signed with Android Debug certificate",
                "verify_android_release_apk_artifact.py",
                "Android production signing inputs failed",
                'assert report["android_signing_preflight"]["returncode"] == 1',
                'assert report["android_signing_preflight"]["detail"] ==',
                'assert report["android_signing_preflight"]["details"] ==',
                'assert report["android_signing_report"].endswith',
                'signing_blocker["detail"]',
                'signing_blocker["details"]',
                "VISIONFORGE_ANDROID_RELEASE_STORE_FILE is required",
                'assert report["android_apk_preflight"]["returncode"] == 2',
                'assert report["android_apk_preflight"]["detail"] ==',
                "assert len(calls) == 3",
                'assert report["android_device_preflight"]["details"] ==',
                'assert [action["stage"] for action in report["next_actions"]] ==',
                'assert report["next_actions"][0]["required_env"] ==',
                'assert "create_android_release_keystore.py" in report["next_actions"][0]["command"]',
                'assert "production-signed release APK" in report["next_actions"][1]["action"]',
                'assert "--build-apk" in report["next_actions"][1]["command"]',
                'assert "adb devices -l" == report["next_actions"][2]["command"]',
                'assert report["next_actions"][2]["commands"] ==',
                'assert report["next_actions"][2]["hint"] ==',
                "_write_device_connectivity_failure_report",
                'assert report["android_device_report"].endswith("android_device_connectivity.json")',
                'assert report["release_blockers"] == []',
                'assert report["next_actions"] == []',
                'assert report["run_parameters"] == {',
                '"android_apk_input": str(apk)',
                'assert report["run_parameters"]["build_apk"] is True',
                'blocker["stage"] for blocker in report["release_blockers"]',
                'assert report["release_blockers"][0]["report"].endswith',
                'assert "[ERROR] release blockers:" in output',
                'assert "- android_apk_preflight returncode=2" in output',
                "test_formal_acceptance_build_stops_on_android_signing_preflight_failure",
                "verify_android_production_signing_inputs.py",
                'assert report["android_signing_preflight"]["returncode"] == 1',
                'assert report["android_device_preflight"]["returncode"] == 2',
                '"android_signing_preflight",',
                "test_formal_acceptance_stops_when_android_device_preflight_fails",
                "test_formal_acceptance_stops_when_device_evidence_file_is_missing",
                "_write_installer_device_evidence",
                "installer-device-ui",
                'Path(staged_sources["ui_evidence_dir"]).is_relative_to',
                "verify_android_device_connectivity.py",
                'assert report["android_device_preflight"]["returncode"] == 2',
                'assert report["installer"]["returncode"] == 5',
                "test_formal_acceptance_build_installs_archived_production_apk",
                "test_formal_acceptance_fails_when_publishable_packager_fails",
                'assert report["publishable_packager"]["returncode"] == 1',
                'assert report["publishable_packager_report"].endswith',
                'assert report["publishable_packager_rejection"]["ok"] is False',
                'assert report["publishable_packager_rejection"]["acceptance_next_actions_empty"]',
                'assert report["publishable_packager_rejection"]["acceptance_packaging_ready"] is False',
                'assert report["publishable_packager_rejection"]["release_blocker_stages"] == [',
                'assert report["publishable_packager_rejection"]["next_action_stages"] == [',
                "publishable release bundle rejected",
                "package_formal_release_bundle.py",
                'assert report["publishable_bundle_dir"] == str(output_dir / "publishable_release")',
                "_write_publishable_bundle",
                "test_formal_acceptance_fails_when_publishable_artifacts_are_missing",
                'assert report["publishable_bundle"]["ok"] is True',
                'assert report["publishable_bundle"]["archive_verifier_ok"] is True',
                'assert report["publishable_packager"]["returncode"] == 5',
                "publishable archive is missing",
                "test_publishable_bundle_summary_rejects_wrong_sidecar_archive_name",
                "stale_release_bundle.zip",
                "publishable archive sha256 sidecar does not name archive",
                "test_formal_acceptance_build_rejects_unreported_apk_artifact",
                "android_production_release_build.json",
                'assert "-Build" not in command',
                'assert report["android_release_builder"]["returncode"] == 5',
                'assert report["android_release_report"] == ""',
            ),
        ),
        SourceContract(
            name="android-release-apk-artifact-preflight",
            path=root / "tools" / "verify_android_release_apk_artifact.py",
            required=(
                "visionforge-android-release-apk-artifact-v1",
                "verify_android_release_apk",
                "require_production_signing",
                "allow_development_android_signing",
                "--allow-development-android-signing",
                "Android APK release preflight failed",
                "Android APK release preflight passed",
            ),
        ),
        SourceContract(
            name="android-release-apk-artifact-preflight-tests",
            path=root / "tests" / "test_verify_android_release_apk_artifact.py",
            required=(
                "test_android_release_apk_artifact_writes_success_report",
                "test_android_release_apk_artifact_rejects_debug_certificate",
                "test_android_release_apk_artifact_allows_lab_development_signing",
                "test_android_release_apk_artifact_main_writes_error_report",
                "APK is signed with Android Debug certificate",
            ),
        ),
        SourceContract(
            name="android-device-connectivity-preflight",
            path=root / "tools" / "verify_android_device_connectivity.py",
            required=(
                "visionforge-android-device-connectivity-v1",
                "\"devices\", \"-l\"",
                "\"mdns\", \"services\"",
                "no_authorized_device",
                "unauthorized_device",
                "offline_device",
                "multiple_authorized_devices",
                "duplicate_adb_transports",
                "requested_device_not_online",
                "selected_single_device",
                "android_device_preflight_error",
                "devices",
                "duplicate_transport_groups",
                "adb_mdns_services",
                "adb_mdns_stdout",
                "device_connectivity_next_actions",
                "No ADB mDNS services were discovered",
                "next_actions",
            ),
        ),
        SourceContract(
            name="android-device-connectivity-preflight-tests",
            path=root / "tests" / "test_verify_android_device_connectivity.py",
            required=(
                "test_android_device_connectivity_accepts_single_authorized_device",
                "test_android_device_connectivity_rejects_no_device",
                "test_android_device_connectivity_records_mdns_services_in_failure_report",
                "adb mdns services",
                "test_android_device_connectivity_rejects_unauthorized_device",
                "test_android_device_connectivity_accepts_requested_serial",
                "test_android_device_connectivity_rejects_duplicate_mdns_transports",
                "test_android_device_connectivity_writes_report",
            ),
        ),
        SourceContract(
            name="formal-release-manifest-signature-core",
            path=root / "tools" / "formal_release_manifest_security.py",
            required=(
                "visionforge-publishable-release-manifest-envelope-v1",
                "visionforge-publishable-release-bundle-v2",
                "Ed25519",
                "canonical_json_bytes",
                "allow_nan=False",
                "sort_keys=True",
                "separators=(\",\", \":\")",
                "duplicate JSON key",
                "public_key_id",
                "payload_b64",
                "signature_b64",
                "manifest key_id does not match the trusted public key",
                "manifest signature verification failed",
                "manifest payload is not canonical JSON",
            ),
        ),
        SourceContract(
            name="publishable-release-bundle-packager",
            path=root / "tools" / "package_formal_release_bundle.py",
            required=(
                "PAYLOAD_SCHEMA",
                "formal_release_manifest_security",
                "sign_manifest_payload",
                "load_private_key",
                "public_key_pem",
                "_load_offline_manifest_signing_key",
                "explicit offline Ed25519 manifest signing key is required",
                "offline manifest signing key must stay outside the repository",
                "offline manifest signing key must stay outside the output directory",
                "_portable_artifact",
                "_portable_evidence_sources",
                '"bundle_sequence"',
                "trusted_public_key_pem",
                "minimum_bundle_sequence",
                "minimum_revocation_epoch",
                "DEVICE_EVIDENCE_SOURCES_DIR",
                "PUBLISHABLE_ARCHIVE_VERIFY_NAME",
                "verify_publishable_archive",
                "_verify_publishable_archive",
                "formal acceptance report is not successful",
                "formal acceptance report is missing",
                "release_blockers",
                "next_actions",
                "print_acceptance_blocker_summary",
                "print_acceptance_next_action_summary",
                'blocker.get("detail")',
                '"acceptance_report"',
                '"acceptance_ok"',
                '"acceptance_release_blockers_empty"',
                '"acceptance_next_actions_empty"',
                '"acceptance_packaging_ready"',
                '"release_blockers"',
                '"next_actions"',
                "formal acceptance report release_blockers must be empty",
                "formal acceptance report next_actions must be empty",
                "run_parameters",
                "_validate_acceptance_run_parameters",
                "_validate_installer_command",
                "formal acceptance installer command",
                "formal acceptance installer command must not rebuild APK",
                "-ApkPath",
                "-WindowsExePath",
                "-HostExePath",
                "-ExpectControlLocked",
                "run_parameters.timeouts_sec",
                "non-build android_apk_input",
                "command result",
                "did not pass",
                "installer",
                "bundle_verifier",
                "android_release_builder",
                "android_apk_preflight",
                "android_device_preflight",
                "android_apk_report",
                "android_device_report",
                "android_apk_report did not require production signing",
                "android_apk_report sha256 does not match current Android APK",
                "android_device_report selected_serial is missing",
                "android_device_report requested_serial does not match run_parameters",
                "android_device_report selected_serial does not match requested serial",
                "android_device_report adb_path does not match run_parameters",
                "_resolve_runtime_path",
                "android_release_report stage is not complete",
                "android_release_report signing_report_path is missing",
                "android_release_report signing_report_path does not match acceptance report",
                "android_release_report source_apk is missing",
                "android_release_report source_apk does not match run_parameters",
                "android_signing_report used development signing",
                "must be inside the formal acceptance directory",
                "device_evidence",
                "bundle_report",
                "REQUIRED_DEVICE_EVIDENCE_FLAGS",
                "formal device evidence device_serial is missing",
                "formal device evidence device_serial does not match Android device report",
                "formal device evidence installed_package_name is missing",
                "formal device evidence installed_package_name does not match Android APK report",
                "formal device evidence installed_package_version is missing",
                "formal device evidence installed_package_version does not match Android APK report",
                "formal device evidence sources are missing",
                "formal device evidence sources.ui_evidence_dir is missing",
                "formal device evidence sources.{label} must be a list",
                "_validate_device_evidence_log_sources",
                "_copy_device_evidence_source_tree",
                "_copy_device_evidence_with_publishable_sources",
                "_publishable_evidence_source_path",
                "formal device evidence source tree",
                "evidence_sources",
                "archive_path",
                '"files": file_entries',
                "_required_dir",
                "formal device evidence sources.{source_field} is missing",
                "formal device evidence sources.{source_field} does not match accepted artifact",
                "expected_source_fields",
                "_validate_device_evidence_sources",
                "_validate_final_safe_idle",
                "final_safe_idle_errors",
                "decode_ui_xml",
                "acceptance_dir=acceptance_dir",
                "_android_device_report_selected_serial",
                "_android_apk_report_package_name",
                "_android_apk_report_version_name",
                "formal device evidence check",
                "formal device evidence does not list all production game models",
                "game_display_name_errors",
                "model_target_contract_errors",
                "does not match current artifact",
                "formal_bundle_report_errors",
                "formal bundle verifier report is missing artifact hashes",
                "formal bundle verifier report is missing",
                "formal bundle verifier report device_evidence path does not match acceptance report",
                "path does not match acceptance report",
                "source_contracts",
                "sha256 does not match formal bundle report",
                "formal_release_manifest.json",
                "formal_acceptance_report",
                "formal_bundle_report",
                "formal_device_evidence",
                "device_evidence_sources",
                "formal_release_bundle.zip",
                "formal_release_bundle.zip.sha256",
                "publishable_release_bundle_verify.json",
                ".rejected_",
                "_unique_rejection_report_path",
                "partial_output.unlink()",
                "zipfile.ZipFile",
                "refusing to overwrite existing publishable release output",
                "refusing to mix publishable release output with unrelated existing files",
                "publishable release artifacts have duplicate output names",
                "publishable release artifacts collide with reserved output names",
            ),
        ),
        SourceContract(
            name="publishable-release-bundle-packager-tests",
            path=root / "tests" / "test_package_formal_release_bundle.py",
            required=(
                "test_package_formal_release_bundle_copies_only_verified_artifacts",
                "test_package_formal_release_bundle_requires_explicit_offline_signer",
                "verify_manifest_envelope",
                'assert b"PRIVATE KEY" not in archived_text',
                'assert "acceptance_report" not in signed_payload',
                'archive_verifier = Path(manifest["archive_verifier"]["path"])',
                "test_package_formal_release_bundle_rejects_failed_acceptance",
                "test_package_formal_release_bundle_rejects_acceptance_with_release_blockers",
                "test_package_formal_release_bundle_rejects_acceptance_with_next_actions",
                "release_blockers must be empty",
                "next_actions must be empty",
                "test_package_formal_release_bundle_cli_prints_acceptance_release_blockers",
                'assert "[ERROR] release blockers:" in output',
                'assert "[ERROR] next actions:" in output',
                'assert "command=adb devices -l" in output',
                'assert "commands=adb mdns services, adb devices -l" in output',
                'assert "hint=No ADB mDNS services were discovered." in output',
                '"detail": "[ERROR] Android ADB device is not ready; reason=no_authorized_device"',
                '"details": [',
                "stale fallback detail",
                'rejection["acceptance_report"] == str(acceptance.resolve())',
                'rejection["acceptance_ok"] is True',
                'rejection["acceptance_release_blockers_empty"] is False',
                'rejection["acceptance_next_actions_empty"] is False',
                'rejection["acceptance_packaging_ready"] is False',
                'rejection["release_blockers"][0]["detail"]',
                'rejection["next_actions"][0]["command"] == "adb devices -l"',
                'rejection["next_actions"][0]["commands"] ==',
                "test_package_formal_release_bundle_rejects_missing_run_parameters",
                "test_package_formal_release_bundle_rejects_non_build_apk_input_mismatch",
                "test_package_formal_release_bundle_rejects_device_serial_mismatch",
                "test_package_formal_release_bundle_rejects_device_evidence_serial_mismatch",
                "test_package_formal_release_bundle_rejects_installed_package_version_mismatch",
                "test_package_formal_release_bundle_rejects_installed_package_name_mismatch",
                "test_package_formal_release_bundle_rejects_missing_device_evidence_sources",
                "test_package_formal_release_bundle_rejects_device_evidence_source_mismatch",
                "test_package_formal_release_bundle_rejects_external_ui_evidence_source",
                "test_package_formal_release_bundle_rejects_unstaged_ui_evidence_source",
                "test_package_formal_release_bundle_rejects_external_mobile_log_source",
                'read_text(encoding="utf-8")',
                'copied_sources["android_apk"] == "VFMobile_1.0.0.apk"',
                'copied_sources["ui_evidence_dir"] == "device_evidence_sources/device-ui"',
                'evidence_sources["archive_path"] == "device_evidence_sources"',
                "evidence_file_hashes",
                'item["archive_path"] == copied.name',
                'archived_evidence = json.loads(release_archive.read("formal_device_evidence.json"))',
                "device_evidence_sources/device-ui/control.xml",
                "device_evidence_sources/mobile_logs/01-mobile-logcat.txt",
                '("android_apk", "windows_exe", "host_exe")',
                "test_package_formal_release_bundle_accepts_matching_explicit_adb_path",
                "test_package_formal_release_bundle_rejects_adb_path_mismatch",
                "test_package_formal_release_bundle_rejects_installer_apk_mismatch",
                "test_package_formal_release_bundle_rejects_installer_rebuild_flag",
                "test_package_formal_release_bundle_rejects_installer_control_flag_mismatch",
                "missing run_parameters",
                "non-build android_apk_input",
                "requested_serial",
                "adb_path",
                "test_package_formal_release_bundle_rejects_bundle_hash_mismatch",
                "test_package_formal_release_bundle_rejects_missing_device_evidence_flag",
                "test_package_formal_release_bundle_rejects_wrong_game_display_name",
                'game_display_names"]["delta-force-416-v8s"]',
                "test_package_formal_release_bundle_rejects_wrong_overwatch_target_contract",
                "test_package_formal_release_bundle_rejects_device_evidence_hash_mismatch",
                "test_package_formal_release_bundle_rejects_failed_bundle_report",
                "test_package_formal_release_bundle_rejects_bundle_report_without_device_check",
                "test_package_formal_release_bundle_rejects_bundle_report_artifact_path_mismatch",
                "test_package_formal_release_bundle_rejects_bundle_report_device_path_mismatch",
                "test_package_formal_release_bundle_rejects_failed_command_result",
                "test_package_formal_release_bundle_rejects_failed_signing_preflight",
                "test_package_formal_release_bundle_rejects_failed_apk_preflight",
                "test_package_formal_release_bundle_rejects_failed_device_preflight",
                "test_package_formal_release_bundle_rejects_unsuccessful_apk_preflight_report",
                "test_package_formal_release_bundle_rejects_apk_preflight_hash_mismatch",
                "test_package_formal_release_bundle_rejects_android_release_source_apk_mismatch",
                "test_package_formal_release_bundle_rejects_android_release_signing_report_mismatch",
                "test_package_formal_release_bundle_rejects_device_report_without_selected_device",
                "test_package_formal_release_bundle_rejects_preflight_report_outside_acceptance_dir",
                "test_package_formal_release_bundle_rejects_device_evidence_outside_acceptance_dir",
                "test_package_formal_release_bundle_rejects_bundle_report_outside_acceptance_dir",
                "test_package_formal_release_bundle_refuses_manifest_overwrite",
                "test_package_formal_release_bundle_cli_failure_does_not_overwrite_manifest",
                "test_package_formal_release_bundle_removes_success_manifest_when_archive_fails",
                "test_package_formal_release_bundle_removes_outputs_when_archive_verifier_fails",
                "publishable archive verification failed",
                "archive failed",
                "publishable.rejected_",
                "test_package_formal_release_bundle_refuses_archive_overwrite",
                "test_package_formal_release_bundle_refuses_unrelated_existing_output",
                "test_package_formal_release_bundle_force_rejects_unrelated_existing_output",
                "test_package_formal_release_bundle_rejects_duplicate_output_names",
                "installer did not pass",
                "qnn_htp_graph_execute",
                "tampered-apk",
                "android_apk sha256",
                "android_apk_sha256",
                "android_release_apk_preflight.json",
                "android_device_connectivity.json",
                "zipfile.ZipFile",
                "namelist",
            ),
        ),
        SourceContract(
            name="publishable-release-bundle-archive-verifier",
            path=root / "tools" / "verify_publishable_release_bundle.py",
            required=(
                "visionforge-publishable-release-bundle-archive-v1",
                "PAYLOAD_SCHEMA",
                "ENVELOPE_SCHEMA",
                "verify_manifest_envelope",
                "external trusted manifest public key is required",
                "manifest-signature",
                "manifest-rollback-policy",
                "archive-entry-structure",
                "archive-entry-closure",
                "duplicate ZIP entries",
                "unsigned extra ZIP entries",
                "anti_rollback_enforced",
                "--public-key",
                "--minimum-bundle-sequence",
                "visionforge-formal-release-acceptance-v1",
                "formal_release_manifest.json",
                "formal_release_acceptance.json",
                "formal_release_bundle_verify.json",
                "formal_device_evidence.json",
                "REQUIRED_MANIFEST_ARTIFACT_ROLES",
                "formal_acceptance_report",
                "formal_bundle_report",
                "archive-sha256-sidecar",
                "manifest-schema",
                "manifest-artifacts",
                "manifest artifact role {role} must point to {expected_archive_path}",
                '"required_roles"',
                '"role_paths"',
                "formal-acceptance-report",
                "evidence-source-files",
                "device-evidence-sources",
                "device-evidence-contract",
                "_check_formal_acceptance_report",
                "formal acceptance release_blockers must be empty",
                "formal acceptance next_actions must be empty",
                '"release_blocker_count"',
                '"next_action_count"',
                "_check_device_evidence_contract",
                "device evidence installed_package_name is invalid",
                "device evidence game_model_tokens are incomplete",
                "game_display_name_errors",
                "model_target_contract_errors",
                "final_safe_idle_errors",
                "decode_ui_xml",
                "device evidence {hash_field} does not match archive entry",
                "_is_safe_archive_path",
                "_check_device_evidence_sources",
                "sources.ui_evidence_dir is not a valid archive directory",
                "sources.{key} is empty",
                "archive sha256 does not match sidecar",
                "publishable release bundle archive verified",
                "publishable release bundle archive verification failed",
            ),
        ),
        SourceContract(
            name="publishable-release-bundle-archive-verifier-tests",
            path=root / "tests" / "test_verify_publishable_release_bundle.py",
            required=(
                "test_verify_publishable_release_bundle_accepts_self_contained_archive",
                "test_verify_publishable_release_bundle_rejects_wrong_external_key",
                "test_verify_publishable_release_bundle_rejects_tampered_signature",
                "test_verify_publishable_release_bundle_rejects_unsigned_legacy_manifest",
                "test_verify_publishable_release_bundle_rejects_unsigned_extra_zip_entry",
                "test_verify_publishable_release_bundle_rejects_duplicate_zip_entry",
                "test_verify_publishable_release_bundle_requires_external_rollback_floor",
                "test_verify_publishable_release_bundle_rejects_sidecar_mismatch",
                "test_verify_publishable_release_bundle_rejects_artifact_hash_mismatch",
                "test_verify_publishable_release_bundle_rejects_unhashed_acceptance_report",
                "omit_manifest_roles",
                "manifest artifact role formal_acceptance_report",
                "test_verify_publishable_release_bundle_rejects_stale_acceptance_next_actions",
                "formal acceptance next_actions must be empty",
                'acceptance_check["evidence"]["next_actions_empty"] is True',
                'acceptance_check["evidence"]["next_action_count"] == 0',
                'check["evidence"]["next_action_count"] == 1',
                "test_verify_publishable_release_bundle_rejects_absolute_evidence_source",
                "test_verify_publishable_release_bundle_rejects_device_evidence_hash_mismatch",
                "test_verify_publishable_release_bundle_rejects_incomplete_device_evidence_checks",
                "test_verify_publishable_release_bundle_recomputes_final_safe_idle_records",
                "test_verify_publishable_release_bundle_rejects_wrong_game_display_name",
                "game_display_names.valorant-yellow-416-v11s-no-flash",
                "test_verify_publishable_release_bundle_rejects_wrong_overwatch_target_contract",
                "model_target_contracts.overwatch2-416-yolov5.ignored_class_names",
                "test_verify_publishable_release_bundle_rejects_wrong_cs2_target_contract",
                "model_target_contracts.counter-strike-2-vombit-416-v8s.t_head_class_id",
                "test_verify_publishable_release_bundle_cli_writes_failure_report",
                "device_evidence_sources/device-ui/control.xml",
                "device_evidence_sources/mobile_logs/01-mobile-logcat.txt",
                "C:/old/mobile-logcat.txt",
                "archive-sha256-sidecar",
                "device-evidence-sources",
                "device-evidence-contract",
            ),
        ),
        SourceContract(
            name="android-qnn-htp-multi-architecture-doc",
            path=root / "android_inference_benchmark" / "README_QNN_HTP.md",
            required=(
                "V68/V69/V73/V75/V79",
                "QAIRT `2.37.1.250807` does not contain a V81 stub/skeleton pair",
                "VISIONFORGE_REQUIRED_QNN_HTP_ARCHITECTURES",
                "requesting V81 with",
                "the current SDK fails the build before an APK can be published",
                "reads `version` and",
                "`build_id` from the SDK's `sdk.yaml`",
                "verifies the full embedded `QNN_SDK_VERSION`",
                "four models must",
                "be rebuilt and reapproved with the same newer SDK",
                "libvalorant_416_v11s_no_flash_w8a16.so",
                "libow2_416_w8a16.so",
                "libdelta_416_v8s_w8a16.so",
                "libcs2_vombit_416_v8s_w8a16.so",
                "not the current shipping model",
                "Portable fallback is a separate compatibility path",
                "must never",
                "inherit an HTP readiness or performance claim",
            ),
            forbidden=(
                "library, V75 stub",
                "extracts the V75 skeleton",
                "Selected performance/precision configuration",
            ),
        ),
        SourceContract(
            name="formal-security-host-capability-switch",
            path=(
                root
                / "dual_machine_runtime"
                / "formal_security_capability.cmake"
            ),
            required=("set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ",),
        ),
        SourceContract(
            name="formal-security-android-capability-switch",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "formal-security-capability.properties"
            ),
            required=("formalSecureDataPlaneImplemented=",),
        ),
        SourceContract(
            name="formal-security-host-loader-contract",
            path=(
                root
                / "dual_machine_runtime"
                / "formal_security_loader.cmake"
            ),
            required=(
                'include("${CMAKE_CURRENT_LIST_DIR}/formal_security_capability.cmake")',
                "NOT DEFINED VFDUAL_FORMAL_SECURITY_IMPLEMENTED",
                'MATCHES "^(ON|OFF)$"',
                "VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY",
                "NOT VFDUAL_FORMAL_SECURITY_IMPLEMENTED",
                "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT",
                "visionforge-formal-security-loader-v1",
            ),
            forbidden=("set(VFDUAL_FORMAL_SECURITY_IMPLEMENTED ",),
        ),
        SourceContract(
            name="formal-security-android-loader-contract",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "formal-security-loader.gradle"
            ),
            required=(
                "file('formal-security-capability.properties')",
                "new Properties()",
                ".getProperty('formalSecureDataPlaneImplemented')",
                "formalSecurityCapabilityValue in ['true', 'false']",
                "Boolean.parseBoolean(",
                "visionforgeFormalSecureDataPlaneOnly",
                "tasks.register('verifyFormalSecureDataPlaneImplemented')",
                "if (!formalSecureDataPlaneOnly)",
                "if (!formalSecureDataPlaneImplemented)",
                "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT=v1:",
                "tasks.configureEach { task ->",
                "formalReleaseArtifactTaskNames",
                "if (task.name in formalReleaseArtifactTaskNames)",
                "task.dependsOn(tasks.named('verifyFormalSecureDataPlaneImplemented'))",
                "tasks.register('probeFormalSecurityReleaseGraphContract')",
                "formalReleaseArtifactTaskNames.each",
                ".getDependencies(releaseTask)",
                "dependencies.contains(formalTask)",
                "VFDUAL_FORMAL_SECURITY_RELEASE_GRAPH=v1:",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-design-contract",
            path=(
                root
                / "dual_machine_runtime"
                / "docs"
                / "PAIR_GENERATION_PROPOSAL_V1.md"
            ),
            required=(
                "visionforge-peer-generation-proposal-v1",
                "17 fields",
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098",
                "actual direct-link/socket context used by this attempt",
                "consume a new higher generation",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-python-foundation",
            path=sidecar_root / "pair_generation_proposal_v1.py",
            required=(
                "class VerifiedPairGenerationProposalV1",
                "WeakKeyDictionary",
                "parse_pair_generation_proposal_v1(snapshot.canonical)",
                "type(connection_id) is not int",
                "type(generation) is not int",
                "PairGenerationProposalErrorCode",
            ),
            forbidden=(
                "caller_provided_hash",
                "def sign",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-python-regressions",
            path=(
                sidecar_root
                / "tests"
                / "test_pair_generation_proposal_v1.py"
            ),
            required=(
                "test_frozen_cross_language_vector_and_final_transcript_mapping",
                "test_builder_validates_converted_memoryview_byte_length",
                "test_verified_owner_rejects_private_integrity_slot_tampering",
                "test_connection_id_rejects_int_subclass_behavior_override",
                "test_port_rejects_int_subclass_behavior_override",
                "test_generation_rejects_int_subclass_behavior_override",
                "test_pair_id_rejects_str_subclass_behavior_override",
                "test_host_runtime_version_rejects_str_subclass_behavior_override",
                "test_android_runtime_version_rejects_str_subclass_behavior_override",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-cpp-foundation",
            path=(
                root
                / "dual_machine_runtime"
                / "shared"
                / "include"
                / "vfdual"
                / "pair_generation_proposal_v1.hpp"
            ),
            required=(
                "PairGenerationProposalFields",
                "VerifiedPairGenerationProposalV1",
                "build_pair_generation_proposal_v1",
                "parse_pair_generation_proposal_v1",
                "build_final_peer_handshake_transcript_from_proposal_v1",
                "kPairGenerationProposalMaximumCanonicalBytes",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-cpp-regressions",
            path=(
                root
                / "dual_machine_runtime"
                / "tests"
                / "pair_generation_proposal_v1_tests.cpp"
            ),
            required=(
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098",
                "allocation_failed",
                "verify_noexcept_allocation_boundaries_source_contract",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-cmake-isolation",
            path=root / "dual_machine_runtime" / "CMakeLists.txt",
            required=(
                "vfdual_pair_generation_proposal_v1 STATIC",
                "vfdual_pair_generation_proposal_v1_tests",
                "VFDUAL_SINGLE_CONFIG_BUILD_TYPE",
                "use a fresh build directory",
                "formal_security_loader.cmake",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-android-foundation",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "PairGenerationProposalV1.java"
            ),
            required=(
                "visionforge-peer-generation-proposal-v1",
                "parse(byte[] encoded)",
                "buildFinalHandshakeTranscript",
                "requirePositiveSigned64",
                "requirePairId",
            ),
            forbidden=(
                "forTestPrivateScalar",
                "fixedAgreement",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-android-regressions",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "PairGenerationProposalV1SelfTest.java"
            ),
            required=(
                "PairGenerationProposalV1SelfTest: PASS",
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098",
            ),
        ),
        SourceContract(
            name="pair-generation-proposal-v1-android-gradle-gate",
            path=root / "android_inference_benchmark" / "app" / "build.gradle",
            required=(
                "compilePairGenerationProposalV1SelfTest",
                "verifyPairGenerationProposalV1",
                "tasks.named('check')",
                "preReleaseBuild",
                "verifyMobileReleaseContracts",
                "apply from: 'formal-security-loader.gradle'",
            ),
        ),
        SourceContract(
            name="pair-generation-credential-v1-design-contract",
            path=(
                root
                / "dual_machine_runtime"
                / "docs"
                / "PAIR_GENERATION_CREDENTIAL_V1.md"
            ),
            required=(
                "vf-dual-machine-pair-generation-credential-v1",
                "transactional_issuance_service_present=true",
                "authoritative_service_wired=true",
                "immutable_issuance_journal_wired=true",
                "public_route_registered=true",
                "host_operation_boundary_verifier_wired=false",
                "android_operation_boundary_verifier_wired=false",
                "append-only/immutable issuance journal before",
                "return the same persisted",
            ),
        ),
        SourceContract(
            name="pair-generation-credential-v1-crypto-foundation",
            path=sidecar_root / "pair_generation_credential_v1.py",
            required=(
                "class PairGenerationCredentialExpectedV1",
                "class PairGenerationCredentialV1Verifier",
                "class VerifiedPairGenerationCredentialV1",
                "class _PairGenerationCredentialV1Signer",
                "WeakKeyDictionary",
                "RSAPublicNumbers",
                "RSAPrivateNumbers",
                "def _build_verified_owner_boundary(",
                "del _build_verified_owner_boundary",
                '"allocation_request_id"',
                "_require_disjoint_key_purposes",
                "MAX_CREDENTIAL_TTL_SECONDS = 30",
                "MAX_ALLOCATION_TO_ISSUE_SECONDS = 5",
            ),
            forbidden=(
                "class PairGenerationCredentialV1Signer",
                "class PairGenerationCredentialSourceV1",
                "def sign_bytes(",
                "def sign_digest(",
                "def sign_payload(",
            ),
        ),
        SourceContract(
            name="pair-generation-credential-v1-regressions",
            path=(
                sidecar_root
                / "tests"
                / "test_pair_generation_credential_v1.py"
            ),
            required=(
                "test_public_api_contains_no_signer_source_or_raw_signing_oracle",
                "test_pair_credential_keys_must_be_disjoint_from_other_purposes",
                "test_verifier_rebuilds_caller_public_key_before_signature_check",
                "test_signer_rebuilds_caller_private_key_before_signing",
                "test_imported_sentinel_cannot_create_a_registered_verified_owner",
                "test_verified_owner_slot_tampering_fails_closed",
                "test_verified_owner_write_side_state_is_not_module_visible",
                "test_noncanonical_json_duplicate_keys_and_padding_are_rejected",
                "test_expected_integer_types_and_signed64_bounds_are_strict",
                "test_signing_fails_closed_when_immediate_post_verify_fails",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-draft-contract",
            path=(
                root
                / "dual_machine_runtime"
                / "docs"
                / "AUTHENTICATED_PEER_HANDSHAKE_V1.md"
            ),
            required=(
                "基础密码合同草案",
                "不得解除 formal gate",
                "pairing_only",
                "pending key-confirmation owner",
                "BCRYPT_KDF_RAW_SECRET",
                "36 bytes：AES key[32] + nonce prefix[4]",
                "generic unauthenticated drop",
                "LEASE_OFFER(raw bytes) -> LEASE_ACCEPT -> LEASE_COMMIT",
                "production blocker",
                "不能构成 formal proof",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-cpp-foundation",
            path=(
                root
                / "dual_machine_runtime"
                / "shared"
                / "include"
                / "vfdual"
                / "authenticated_peer_handshake_v1.hpp"
            ),
            required=(
                "class PendingPeerHandshakeConfirmationV1 final",
                "class ConfirmedPeerHandshakeSessionV1 final",
                "derive_pending_after_peer_identity_verified",
                "pair_binding_required_for_key_derivation",
                "ConfirmedPeerHandshakeSessionV1(\n"
                "        ConfirmedPeerHandshakeSessionV1&&) = delete",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-cpp-regressions",
            path=(
                root
                / "dual_machine_runtime"
                / "tests"
                / "authenticated_peer_handshake_v1_tests.cpp"
            ),
            required=(
                "VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS",
                "pair_binding_required_for_key_derivation",
                "!std::is_move_constructible_v<",
                "verify_ephemeral_private_key_is_one_shot_on_all_attempts",
                "verify_ecdh_hkdf_finished_and_channel_binding_vector",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-cmake-isolation",
            path=root / "dual_machine_runtime" / "CMakeLists.txt",
            required=(
                "add_library(vfdual_authenticated_peer_handshake_v1 STATIC",
                "add_executable(vfdual_authenticated_peer_handshake_v1_tests",
                "VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS=1",
                "shared/src/authenticated_peer_handshake_v1.cpp",
                "formal_security_loader.cmake",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-android-fresh-owner",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "FreshP256KeyAgreement.java"
            ),
            required=(
                "public final class FreshP256KeyAgreement",
                "deriveAfterPeerIdentityVerified",
                "PendingPeerHandshakeConfirmation",
                "transcript.pairId().isEmpty()",
                "destroyPrivateKey(consumedPrivateKey)",
            ),
            forbidden=("forTestPrivateScalar", "sec1ForTestScalar"),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-android-confirmation-gate",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "PendingPeerHandshakeConfirmation.java"
            ),
            required=(
                "public final class PendingPeerHandshakeConfirmation",
                "createLocalFinishedMac",
                "confirmPeerFinishedMac",
                "PeerHandshakeSecrets confirmed",
                "localFinishedCreated",
            ),
            forbidden=(
                "controlHostToAndroidMaterial",
                "channelBindingSha256",
                "finishedKeyForTest",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-android-provider-boundaries",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "AuthenticatedPeerHandshakeV1Internals.java"
            ),
            required=(
                "field instanceof ECFieldFp",
                "((ECFieldFp) field).getP().equals(P256_PRIME)",
                "normalizeP256SharedSecret",
                "providerSecret.length > 32",
            ),
            forbidden=(
                "sec1ForTestScalar",
                "channelBindingExporterForTest",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-android-regressions",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "test"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "handshake"
                / "AuthenticatedPeerHandshakeV1SelfTest.java"
            ),
            required=(
                "AuthenticatedPeerHandshakeV1SelfTest: PASS",
                "fixedAgreement",
                "new byte[33]",
                "new byte[64]",
                "expectUnauthenticated",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-android-gradle-gate",
            path=root / "android_inference_benchmark" / "app" / "build.gradle",
            required=(
                "compileAuthenticatedPeerHandshakeV1SelfTest",
                "verifyAuthenticatedPeerHandshakeV1",
                "tasks.named('check')",
                "preReleaseBuild",
                "verifyMobileReleaseContracts",
                "JavaVersion.VERSION_1_8",
                "options.release.set(8)",
                "testInstrumentationRunner(",
                "com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation",
                "apply from: 'formal-security-loader.gradle'",
            ),
        ),
        SourceContract(
            name="authenticated-peer-handshake-v1-api29-plus-probe",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "androidTest"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "AuthenticatedPeerHandshakeV1InstrumentationProbe.java"
            ),
            required=(
                "runFreshSession",
                "generateFreshEphemeralKeyAgreement",
                "createLocalFinishedMac",
                "confirmPeerFinishedMac",
                "requireMatchingSecrets",
                "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q",
            ),
            forbidden=(
                "forTestPrivateScalar",
                "sec1ForTestScalar",
                "fixedAgreement",
            ),
        ),
        SourceContract(
            name="host-restricted-peer-transcript-signer-foundation",
            path=(
                root
                / "dual_machine_runtime"
                / "host"
                / "windows"
                / "security"
                / "include"
                / "vfdual"
                / "host_peer_handshake_transcript_signer_v1.hpp"
            ),
            required=(
                "HostPeerHandshakeSigningInputV1",
                "std::unique_ptr<PlatformP256EphemeralKeyAgreementV1>",
                "HostSignedPeerHandshakeContextV1",
                "build_and_sign_bound_transcript",
                "derive_pending_after_peer_identity_verified_for_bound_transcript",
            ),
            forbidden=(
                "sign_bytes",
                "sign_digest",
                "sign_sha256_digest",
                "caller_canonical",
            ),
        ),
        SourceContract(
            name="host-restricted-peer-transcript-signer-regressions",
            path=(
                root
                / "dual_machine_runtime"
                / "host"
                / "windows"
                / "security"
                / "tests"
                / "host_peer_handshake_transcript_signer_v1_tests.cpp"
            ),
            required=(
                "canonical_low_s_der_to_p1363",
                "build_and_sign_bound_transcript",
                "ephemeral_private_key_already_consumed",
                "test_public_api_and_cmake_remain_restricted_foundations",
                '"sign_sha256_digest"',
                "VisionForgeHost",
            ),
        ),
        SourceContract(
            name="host-restricted-peer-transcript-signer-cmake-isolation",
            path=root / "dual_machine_runtime" / "CMakeLists.txt",
            required=(
                "vfdual_host_peer_handshake_transcript_signer_v1 STATIC",
                "host_peer_handshake_transcript_signer_v1_tests.cpp",
                "NAME vfdual_host_peer_handshake_transcript_signer_v1_tests",
                "formal_security_loader.cmake",
            ),
        ),
        SourceContract(
            name="android-bound-peer-session-foundation",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "AndroidBoundPeerHandshakeSession.java"
            ),
            required=(
                "bindExpectedPair",
                "hostIdentityPublicKeyDer",
                "requireHostTranscriptSignature",
                "createVerifiedAndroidTranscriptSignature",
                "deriveAfterPeerIdentityVerified",
                "confirmHostFinished",
            ),
            forbidden=(
                "LOCAL_AUTHORIZATION_HOST_ALIAS",
                "androidOnlyChannelBinding",
                "sign(byte[]",
            ),
        ),
        SourceContract(
            name="android-bound-peer-session-confirmed-owner",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "ConfirmedAndroidPeerSession.java"
            ),
            required=(
                "channelBindingSha256",
                "controlHostToAndroidMaterial",
                "videoHostToAndroidMaterial",
                "sessionGeneration",
                "ownedSecrets.close()",
            ),
            forbidden=("PeerHandshakeSecrets secrets()",),
        ),
        SourceContract(
            name="android-bound-peer-session-typed-identity-signer",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "main"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "AndroidPairingIdentityStore.java"
            ),
            required=(
                "signHandshakeTranscript(",
                "DualMachineEntitlementRecord expectedPair",
                "transcript.androidIdentitySpkiSha256()",
                "transcript.hostIdentitySpkiSha256()",
                "DualMachinePairingIdentityCodec.verify(",
            ),
            forbidden=("public byte[] sign(byte[] payload)",),
        ),
        SourceContract(
            name="android-bound-peer-session-regression-gate",
            path=(root / "android_inference_benchmark" / "app" / "build.gradle"),
            required=(
                "compileAndroidBoundPeerHandshakeSessionSelfTest",
                "verifyAndroidBoundPeerHandshakeSession",
                "AndroidBoundPeerHandshakeSessionSelfTest",
                "JavaVersion.VERSION_1_8",
                "options.release.set(8)",
                "verifyMobileReleaseContracts",
            ),
        ),
        SourceContract(
            name="android-bound-peer-session-api29-plus-public-bind-probe",
            path=(
                root
                / "android_inference_benchmark"
                / "app"
                / "src"
                / "androidTest"
                / "java"
                / "com"
                / "visionforge"
                / "inferencebenchmark"
                / "AndroidBoundPeerHandshakeSessionInstrumentationProbe.java"
            ),
            required=(
                "verifySuccessfulPublicBinding",
                "verifyAliasMismatchBurnsFresh",
                "verifyRecordHashMismatchBurnsFresh",
                "AndroidPairingIdentityStore",
                "bindExpectedPair",
                "confirmHostFinished",
                "hardwareBacked",
                "requireMatchingSecrets",
                "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q",
            ),
            forbidden=(
                "forTestPrivateScalar",
                "sec1ForTestScalar",
                "fixedAgreement",
            ),
        ),
        SourceContract(
            name="dual-machine-reverse-resistance-threat-model",
            path=root / "docs" / "DUAL_MACHINE_REVERSE_RESISTANCE_THREAT_MODEL.md",
            required=(
                "已证实的本地逆向能力",
                "必须保留的事实纠偏",
                "安全不变量",
                "当前双机 P0 阻断",
                "双机数据面 v2 设计合同",
                "完成定义",
                "不承诺本地管理员/root 永远看不到运行时明文",
            ),
        ),
        SourceContract(
            name="dual-machine-reverse-resistance-release-gate-tests",
            path=root / "tests" / "test_dual_machine_release_readiness.py",
            required=(
                "test_formal_reverse_resistance_blocks_known_legacy_data_plane",
                "REQUIRED_REVERSE_RESISTANCE_CHECKS",
                "test_reverse_resistance_registry_fails_when_required_check_is_missing",
                "test_host_development_contract_does_not_require_insecure_formal_behavior",
                "test_formal_capability_rejects_nonexecuted_main_file_string_decoys",
                "test_enabled_formal_loaders_execute_real_build_system_probes",
                "test_schema_lineage_requires_one_exact_top_level_string_assignment",
                "test_schema_lineage_rejects_module_level_rebinding_forms",
                "REVERSE_RESISTANCE_REGISTRY_CHECK",
                "test_development_diagnostic_never_reports_formal_release_success",
                "test_strict_report_cannot_claim_formal_eligibility",
            ),
        ),
    ))
    return tuple(inherited)


REVERSE_RESISTANCE_CHECK_PREFIX = "reverse-resistance-"
REVERSE_RESISTANCE_REGISTRY_CHECK = (
    REVERSE_RESISTANCE_CHECK_PREFIX + "check-registry-complete"
)
REQUIRED_REVERSE_RESISTANCE_CHECKS = frozenset(
    {
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-data-plane-gate",
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-independent-hardware-identity",
        REVERSE_RESISTANCE_CHECK_PREFIX + "android-no-local-fake-host",
        REVERSE_RESISTANCE_CHECK_PREFIX + "handshake-channel-binding",
        REVERSE_RESISTANCE_CHECK_PREFIX + "video-aead-envelope",
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-path-probe",
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-idr",
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-mouse-button",
        REVERSE_RESISTANCE_CHECK_PREFIX + "anti-replay-nonce-contract",
        REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-fallback",
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-public-security-inputs",
        REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-model-payload",
        REVERSE_RESISTANCE_CHECK_PREFIX + "encrypted-model-key-release",
        REVERSE_RESISTANCE_CHECK_PREFIX + "cryptographic-behavior-evidence",
    }
)


def _check_host_authenticated_permit(root: Path) -> CheckResult:
    path = root / "dual_machine_runtime" / "host" / "windows" / "src" / "host_runtime_service.cpp"
    if not path.exists():
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "host-data-plane-gate",
            "Host runtime source is missing",
            {"path": str(path)},
        )
    text = _read_text(path)
    constant_permit_count = len(
        re.findall(
            r"\[\]\(\)\s*noexcept\s*\{\s*return\s+true\s*;\s*\}",
            text,
        )
    )
    missing = [
        token
        for token in (
            "VideoDataPlanePermitSource",
            "install_authenticated_formal_runtime",
        )
        if token not in text
    ]
    evidence = {
        "path": str(path),
        "constant_permit_count": constant_permit_count,
        "missing_authenticated_gate_tokens": missing,
    }
    if constant_permit_count or missing:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "host-data-plane-gate",
            "Host video publishing is not bound to an authenticated lease gate",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-data-plane-gate",
        "Host video publishing uses an authenticated lease gate",
        evidence,
    )


def _check_host_independent_hardware_identity(root: Path) -> CheckResult:
    header_path = (
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "security"
        / "include"
        / "vfdual"
        / "host_cng_device_identity.h"
    )
    source_path = (
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "security"
        / "src"
        / "host_cng_device_identity.cpp"
    )
    cmake_path = root / "dual_machine_runtime" / "CMakeLists.txt"
    runtime_path = (
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "host_runtime_service.cpp"
    )
    header_text = _read_text(header_path) if header_path.is_file() else ""
    source_text = _read_text(source_path) if source_path.is_file() else ""
    cmake_text = _read_text(cmake_path) if cmake_path.is_file() else ""
    runtime_text = _read_text(runtime_path) if runtime_path.is_file() else ""
    foundation_text = "\n".join((header_text, source_text))
    required_foundation_tokens = (
        "HostCngDeviceIdentity",
        "NCryptCreatePersistedKey",
        "NCRYPT_MACHINE_KEY_FLAG",
        "NCRYPT_EXPORT_POLICY_PROPERTY",
        "kMicrosoftPlatformCryptoProvider",
        "kCngImplementationHardwareFlag",
        "kCngImplementationSoftwareFlag",
        "untrusted_local_assurance_claim",
    )
    missing_foundation_tokens = [
        token for token in required_foundation_tokens if token not in foundation_text
    ]
    host_link_match = re.search(
        r"target_link_libraries\(\s*VisionForgeHost\s+PRIVATE(?P<body>.*?)\)",
        cmake_text,
        flags=re.DOTALL,
    )
    linked_into_host = bool(
        host_link_match
        and "vfdual_host_cng_device_identity" in host_link_match.group("body")
    )
    missing_runtime_tokens = [
        token
        for token in ("HostCngDeviceIdentity", "open_windows(")
        if token not in runtime_text
    ]
    acl_markers = (
        "NCRYPT_SECURITY_DESCR_PROPERTY",
        "DACL_SECURITY_INFORMATION",
        "service_sid",
    )
    missing_acl_markers = [
        token for token in acl_markers if token not in foundation_text
    ]
    evidence = {
        "header": str(header_path),
        "source": str(source_path),
        "cmake": str(cmake_path),
        "runtime": str(runtime_path),
        "header_present": header_path.is_file(),
        "source_present": source_path.is_file(),
        "foundation_present": bool(
            header_path.is_file()
            and source_path.is_file()
            and not missing_foundation_tokens
        ),
        "missing_non_exportable_cng_tokens": missing_foundation_tokens,
        "linked_into_host": linked_into_host,
        "missing_host_runtime_identity_tokens": missing_runtime_tokens,
        "missing_machine_key_acl_markers": missing_acl_markers,
    }
    if (
        not header_path.is_file()
        or not source_path.is_file()
        or missing_foundation_tokens
        or not linked_into_host
        or missing_runtime_tokens
        or missing_acl_markers
    ):
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "host-independent-hardware-identity",
            "Host CNG/TPM identity foundation is not fully wired and ACL-isolated",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-independent-hardware-identity",
        "Host wires an ACL-isolated per-device non-exportable CNG/TPM identity",
        evidence,
    )


def _check_android_no_local_fake_host(root: Path) -> CheckResult:
    mobile_path = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "MobileRuntimeService.java"
    )
    if not mobile_path.exists():
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "android-no-local-fake-host",
            "Android runtime source is missing",
            {"path": str(mobile_path)},
        )
    text = _read_text(mobile_path)
    forbidden_present = [
        token
        for token in (
            "VisionForge.Android.LocalAuthorizationHost.v1",
            "localAndroidAuthorizationAttachment(",
            "visionforge.android-only-authorization.v1",
            "LOCAL_AUTHORIZATION_HOST_ALIAS",
        )
        if token in text
    ]
    evidence = {
        "android_path": str(mobile_path),
        "android_local_host_simulation_tokens": forbidden_present,
    }
    if forbidden_present:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "android-no-local-fake-host",
            "Android release runtime still simulates the Host identity locally",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "android-no-local-fake-host",
        "Android release runtime does not construct a local fake Host identity",
        evidence,
    )


def _text_contract_gaps(
    contracts: Mapping[str, tuple[Path, tuple[str, ...]]],
) -> tuple[list[str], dict[str, list[str]]]:
    missing_paths: list[str] = []
    missing_tokens: dict[str, list[str]] = {}
    for name, (path, required) in contracts.items():
        if not path.is_file():
            missing_paths.append(str(path))
            continue
        text = _read_text(path)
        absent = [token for token in required if token not in text]
        if absent:
            missing_tokens[name] = absent
    return missing_paths, missing_tokens


def _replace_comment_with_whitespace(match: re.Match[str]) -> str:
    value = match.group(0)
    if value.startswith(("//", "/*", "#")):
        return "".join("\n" if character == "\n" else " " for character in value)
    return value


def _code_without_comments(path: Path) -> str:
    text = _read_text(path)
    if path.suffix == ".py":
        try:
            tokens = tokenize.generate_tokens(io.StringIO(text).readline)
            return tokenize.untokenize(
                token
                for token in tokens
                if token.type != tokenize.COMMENT
            )
        except (IndentationError, SyntaxError, tokenize.TokenError):
            return ""
    if path.name == "CMakeLists.txt" or path.suffix == ".cmake":
        without_bracket_comments = re.sub(
            r"#\[(=*)\[.*?\]\1\]",
            _replace_comment_with_whitespace,
            text,
            flags=re.DOTALL,
        )
        return re.sub(
            r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\#[^\r\n]*)',
            _replace_comment_with_whitespace,
            without_bracket_comments,
        )
    if path.suffix in {".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".gradle"}:
        return re.sub(
            r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\r\n]*|/\*.*?\*/)',
            _replace_comment_with_whitespace,
            text,
            flags=re.DOTALL,
        )
    return text


def _code_contract_gaps(
    contracts: Mapping[str, tuple[Path, tuple[str, ...]]],
) -> tuple[list[str], dict[str, list[str]]]:
    missing_paths: list[str] = []
    missing_tokens: dict[str, list[str]] = {}
    for name, (path, required) in contracts.items():
        if not path.is_file():
            missing_paths.append(str(path))
            continue
        code = _code_without_comments(path)
        absent = [token for token in required if token not in code]
        if absent:
            missing_tokens[name] = absent
    return missing_paths, missing_tokens


def _python_route_literals(path: Path) -> tuple[str, ...]:
    if not path.is_file():
        return ()
    probe = r'''
import importlib
import importlib.util
import json
import sys
from pathlib import Path

from fastapi.routing import APIRoute

path = Path(sys.argv[1]).resolve()
probe_root = Path(sys.argv[2]).resolve()
package_init = path.parent / "__init__.py"
if package_init.is_file():
    sys.path.insert(0, str(path.parent.parent))
    module = importlib.import_module(f"{path.parent.name}.{path.stem}")
    main_module = importlib.import_module(f"{path.parent.name}.main")
    settings_module = importlib.import_module(f"{path.parent.name}.settings")
    settings = settings_module.DualMachineSettings(
        database_path=probe_root / "readiness_probe.db",
        license_code_secret=b"L" * 32,
        token_secret=b"T" * 32,
        minimum_host_client_version="1.0.0",
        minimum_android_client_version="1.0.0",
        ticket_private_key_path=probe_root / "probe-private.pem",
        ticket_public_key_path=probe_root / "probe-public.pem",
        pair_credential_private_key_path=(
            probe_root / "probe-pair-private.pem"
        ),
        pair_credential_public_key_path=(
            probe_root / "probe-pair-public.pem"
        ),
    )
    route_container = main_module.create_app(settings)
else:
    spec = importlib.util.spec_from_file_location("vf_readiness_routes", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("route module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    route_container = getattr(module, "router", None)
routes = []
for route in getattr(route_container, "routes", ()):
    if isinstance(route, APIRoute) and type(route.path) is str:
        routes.append(route.path)
print("VFDUAL_RUNTIME_ROUTES=" + json.dumps(routes, separators=(",", ":")))
'''
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix="vfdual-route-probe-") as probe_dir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    probe,
                    str(path),
                    probe_dir,
                ],
                cwd=str(
                    path.parent.parent
                    if (path.parent / "__init__.py").is_file()
                    else path.parent
                ),
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        return ()
    if result.returncode != 0:
        return ()
    prefix = "VFDUAL_RUNTIME_ROUTES="
    lines = [line for line in result.stdout.splitlines() if line.startswith(prefix)]
    if len(lines) != 1:
        return ()
    try:
        routes = json.loads(lines[0][len(prefix):])
    except (json.JSONDecodeError, TypeError):
        return ()
    if type(routes) is not list or any(type(route) is not str for route in routes):
        return ()
    return tuple(routes)


def _normalized_file_bytes(path: Path) -> bytes:
    if not path.is_file():
        return b""
    return path.read_bytes().replace(b"\r\n", b"\n")


def _find_cmake_executable(root: Path) -> Path | None:
    discovered = shutil.which("cmake")
    if discovered:
        return Path(discovered).resolve()
    for search_root in (root, ROOT):
        bundled_root = search_root / ".android-sdk" / "cmake"
        candidates = sorted(
            (
                candidate
                for pattern in ("*/bin/cmake.exe", "*/bin/cmake")
                for candidate in bundled_root.glob(pattern)
                if candidate.is_file()
            ),
            reverse=True,
        )
        if candidates:
            return candidates[0].resolve()
    return None


def _probe_host_formal_security_loader(root: Path) -> dict[str, Any]:
    source_root = root / "dual_machine_runtime"
    cmake_executable = _find_cmake_executable(root)
    if cmake_executable is None:
        return {"ok": False, "detail": "cmake_missing", "returncode": None}
    if not (source_root / "CMakeLists.txt").is_file():
        return {
            "ok": False,
            "detail": "cmake_source_missing",
            "returncode": None,
            "executable": str(cmake_executable),
        }
    try:
        with tempfile.TemporaryDirectory(prefix="vfdual-cmake-probe-") as build_dir:
            result = subprocess.run(
                [
                    str(cmake_executable),
                    "-S",
                    str(source_root),
                    "-B",
                    build_dir,
                    "-DVFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY=ON",
                    "-DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF",
                ],
                cwd=str(source_root),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            cache_path = Path(build_dir) / "CMakeCache.txt"
            cache_text = (
                _read_text(cache_path) if cache_path.is_file() else ""
            )
    except (OSError, subprocess.SubprocessError):
        return {
            "ok": False,
            "detail": "cmake_probe_failed",
            "returncode": None,
            "executable": str(cmake_executable),
        }
    marker = (
        "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT:INTERNAL="
        "visionforge-formal-security-loader-v1"
    )
    ok = result.returncode == 0 and marker in cache_text.splitlines()
    return {
        "ok": ok,
        "detail": "configured" if ok else "cmake_contract_marker_missing",
        "returncode": result.returncode,
        "executable": str(cmake_executable),
    }


def _probe_android_formal_security_loader(root: Path) -> dict[str, Any]:
    project_root = root / "android_inference_benchmark"
    wrapper_name = "gradlew.bat" if os.name == "nt" else "gradlew"
    wrapper = next(
        (
            candidate.resolve()
            for candidate in (
                project_root / wrapper_name,
                ROOT / "android_inference_benchmark" / wrapper_name,
            )
            if candidate.is_file()
        ),
        None,
    )
    if wrapper is None:
        return {"ok": False, "detail": "gradle_wrapper_missing", "returncode": None}
    environment = dict(os.environ)
    environment["GRADLE_OPTS"] = (
        environment.get("GRADLE_OPTS", "")
        + " -Dorg.gradle.daemon=false"
    ).strip()
    try:
        with tempfile.TemporaryDirectory(prefix="vfdual-gradle-probe-") as cache_dir:
            arguments = [
                "--no-daemon",
                "--console=plain",
                "--offline",
                "--project-cache-dir",
                cache_dir,
                "-PvisionforgeFormalSecureDataPlaneOnly=true",
                ":app:verifyFormalSecureDataPlaneImplemented",
                ":app:probeFormalSecurityReleaseGraphContract",
            ]
            if os.name == "nt":
                comspec = os.environ.get("COMSPEC", "cmd.exe")
                command = [
                    comspec,
                    "/d",
                    "/s",
                    "/c",
                    subprocess.list2cmdline([str(wrapper), *arguments]),
                ]
            else:
                command = [str(wrapper), *arguments]
            result = subprocess.run(
                command,
                cwd=str(project_root),
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
    except (OSError, subprocess.SubprocessError):
        return {
            "ok": False,
            "detail": "gradle_probe_failed",
            "returncode": None,
            "executable": str(wrapper),
        }
    loader_marker = "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT=v1:true"
    graph_marker = (
        "VFDUAL_FORMAL_SECURITY_RELEASE_GRAPH=v1:"
        "packageRelease,bundleRelease->verifyFormalSecureDataPlaneImplemented"
    )
    loader_marker_lines = [
        line
        for line in result.stdout.splitlines()
        if line.strip() == loader_marker
    ]
    graph_marker_lines = [
        line
        for line in result.stdout.splitlines()
        if line.strip() == graph_marker
    ]
    ok = (
        result.returncode == 0
        and len(loader_marker_lines) == 1
        and len(graph_marker_lines) == 1
    )
    return {
        "ok": ok,
        "detail": "executed" if ok else "gradle_contract_marker_missing",
        "returncode": result.returncode,
        "executable": str(wrapper),
    }


def _formal_security_marker_evidence(root: Path) -> dict[str, Any]:
    cmake_path = root / "dual_machine_runtime" / "CMakeLists.txt"
    gradle_path = root / "android_inference_benchmark" / "app" / "build.gradle"
    host_capability_path = (
        root / "dual_machine_runtime" / "formal_security_capability.cmake"
    )
    android_capability_path = (
        root
        / "android_inference_benchmark"
        / "app"
        / "formal-security-capability.properties"
    )
    host_loader_path = (
        root / "dual_machine_runtime" / "formal_security_loader.cmake"
    )
    android_loader_path = (
        root
        / "android_inference_benchmark"
        / "app"
        / "formal-security-loader.gradle"
    )
    host_bytes = _normalized_file_bytes(host_capability_path)
    android_bytes = _normalized_file_bytes(android_capability_path)
    host_loader_bytes = _normalized_file_bytes(host_loader_path)
    android_loader_bytes = _normalized_file_bytes(android_loader_path)
    host_value = HOST_FORMAL_SECURITY_CAPABILITIES.get(host_bytes)
    android_value = ANDROID_FORMAL_SECURITY_CAPABILITIES.get(android_bytes)
    cmake = _code_without_comments(cmake_path) if cmake_path.is_file() else ""
    gradle = _code_without_comments(gradle_path) if gradle_path.is_file() else ""
    host_loader_source_valid = (
        host_loader_bytes == EXPECTED_HOST_FORMAL_SECURITY_LOADER
        and cmake.count(
            'include("${CMAKE_CURRENT_SOURCE_DIR}/formal_security_loader.cmake")'
        )
        == 1
        and cmake.count("formal_security_loader.cmake") == 1
        and "formal_security_capability.cmake" not in cmake
        and "VFDUAL_FORMAL_SECURITY_IMPLEMENTED" not in cmake
        and "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT" not in cmake
    )
    android_loader_source_valid = (
        android_loader_bytes == EXPECTED_ANDROID_FORMAL_SECURITY_LOADER
        and gradle.count("apply from: 'formal-security-loader.gradle'") == 1
        and gradle.count("formal-security-loader.gradle") == 1
        and "formal-security-capability.properties" not in gradle
        and "formalSecureDataPlaneImplemented" not in gradle
        and "VFDUAL_FORMAL_SECURITY_LOADER_CONTRACT" not in gradle
    )
    host_probe: dict[str, Any] = {
        "ok": False,
        "detail": "disabled_capability_not_probed",
        "returncode": None,
    }
    android_probe: dict[str, Any] = {
        "ok": False,
        "detail": "disabled_capability_not_probed",
        "returncode": None,
    }
    if host_value == "ON" and host_loader_source_valid:
        host_probe = _probe_host_formal_security_loader(root)
    if android_value is True and android_loader_source_valid:
        android_probe = _probe_android_formal_security_loader(root)
    host_loader_valid = host_loader_source_valid and (
        host_value != "ON" or bool(host_probe["ok"])
    )
    android_loader_valid = android_loader_source_valid and (
        android_value is not True or bool(android_probe["ok"])
    )
    host_enabled = host_value == "ON" and host_loader_valid
    android_enabled = android_value is True and android_loader_valid
    return {
        "formal_capability_markers_enabled": host_enabled and android_enabled,
        "host_formal_security_marker_enabled": host_enabled,
        "android_formal_security_marker_enabled": android_enabled,
        "host_formal_security_marker_value": host_value,
        "android_formal_security_marker_value": android_value,
        "host_formal_security_loader_valid": host_loader_valid,
        "android_formal_security_loader_valid": android_loader_valid,
        "host_formal_security_loader_source_valid": host_loader_source_valid,
        "android_formal_security_loader_source_valid": (
            android_loader_source_valid
        ),
        "host_formal_security_entry_probe": host_probe,
        "android_formal_security_entry_probe": android_probe,
        "formal_security_cmake_path": str(cmake_path),
        "formal_security_gradle_path": str(gradle_path),
        "host_formal_security_capability_path": str(host_capability_path),
        "android_formal_security_capability_path": str(
            android_capability_path
        ),
        "host_formal_security_loader_path": str(host_loader_path),
        "android_formal_security_loader_path": str(android_loader_path),
    }


def _android_peer_handshake_source_dir(root: Path) -> Path:
    return (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "handshake"
    )


def _peer_handshake_core_contracts(
    root: Path,
) -> dict[str, tuple[Path, tuple[str, ...]]]:
    runtime_root = root / "dual_machine_runtime"
    handshake_java = _android_peer_handshake_source_dir(root)
    return {
        "cpp_header": (
            runtime_root
            / "shared"
            / "include"
            / "vfdual"
            / "authenticated_peer_handshake_v1.hpp",
            (
                "PendingPeerHandshakeConfirmationV1",
                "ConfirmedPeerHandshakeSessionV1",
                "derive_pending_after_peer_identity_verified",
            ),
        ),
        "cpp_source": (
            runtime_root / "shared" / "src" / "authenticated_peer_handshake_v1.cpp",
            ("BCRYPT_ECDH_P256_ALGORITHM", "pair_binding_required_for_key_derivation"),
        ),
        "host_restricted_transcript_signer": (
            runtime_root
            / "host"
            / "windows"
            / "security"
            / "include"
            / "vfdual"
            / "host_peer_handshake_transcript_signer_v1.hpp",
            (
                "HostSignedPeerHandshakeContextV1",
                "build_and_sign_bound_transcript",
                "derive_pending_after_peer_identity_verified_for_bound_transcript",
            ),
        ),
        "android_fresh_owner": (
            handshake_java / "FreshP256KeyAgreement.java",
            ("deriveAfterPeerIdentityVerified", "transcript.pairId().isEmpty()"),
        ),
        "android_pending_owner": (
            handshake_java / "PendingPeerHandshakeConfirmation.java",
            ("createLocalFinishedMac", "confirmPeerFinishedMac"),
        ),
        "android_confirmed_owner": (
            handshake_java / "PeerHandshakeSecrets.java",
            ("controlHostToAndroidMaterial", "channelBindingSha256"),
        ),
        "android_bound_peer_owner": (
            handshake_java.parent / "AndroidBoundPeerHandshakeSession.java",
            (
                "bindExpectedPair",
                "requireHostTranscriptSignature",
                "confirmHostFinished",
            ),
        ),
        "android_bound_confirmed_owner": (
            handshake_java.parent / "ConfirmedAndroidPeerSession.java",
            ("channelBindingSha256", "sessionGeneration"),
        ),
    }


def _peer_handshake_gate_contracts(
    root: Path,
) -> dict[str, tuple[Path, tuple[str, ...]]]:
    runtime_root = root / "dual_machine_runtime"
    android_app = root / "android_inference_benchmark" / "app"
    return {
        "cpp_regressions": (
            runtime_root / "tests" / "authenticated_peer_handshake_v1_tests.cpp",
            ("VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS",),
        ),
        "cmake_isolation": (
            runtime_root / "CMakeLists.txt",
            (
                "vfdual_authenticated_peer_handshake_v1_tests",
                "VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS=1",
                "vfdual_host_peer_handshake_transcript_signer_v1",
                "NAME vfdual_host_peer_handshake_transcript_signer_v1_tests",
            ),
        ),
        "host_restricted_signer_regressions": (
            runtime_root
            / "host"
            / "windows"
            / "security"
            / "tests"
            / "host_peer_handshake_transcript_signer_v1_tests.cpp",
            ("build_and_sign_bound_transcript", "canonical_low_s_der_to_p1363"),
        ),
        "android_regressions": (
            android_app
            / "src"
            / "test"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "handshake"
            / "AuthenticatedPeerHandshakeV1SelfTest.java",
            ("AuthenticatedPeerHandshakeV1SelfTest: PASS",),
        ),
        "android_bound_regressions": (
            android_app
            / "src"
            / "test"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "AndroidBoundPeerHandshakeSessionSelfTest.java",
            ("AndroidBoundPeerHandshakeSessionSelfTest: PASS",),
        ),
        "gradle_gate": (
            android_app / "build.gradle",
            (
                "verifyAuthenticatedPeerHandshakeV1",
                "verifyAndroidBoundPeerHandshakeSession",
                "preReleaseBuild",
                "JavaVersion.VERSION_1_8",
                "options.release.set(8)",
                "com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation",
            ),
        ),
        "api29_plus_provider_probe": (
            android_app
            / "src"
            / "androidTest"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "AuthenticatedPeerHandshakeV1InstrumentationProbe.java",
            (
                "generateFreshEphemeralKeyAgreement",
                "confirmPeerFinishedMac",
                "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q",
            ),
        ),
        "api29_plus_bound_peer_probe": (
            android_app
            / "src"
            / "androidTest"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "AndroidBoundPeerHandshakeSessionInstrumentationProbe.java",
            (
                "verifySuccessfulPublicBinding",
                "verifyAliasMismatchBurnsFresh",
                "verifyRecordHashMismatchBurnsFresh",
                "bindExpectedPair",
                "confirmHostFinished",
                "requireMatchingSecrets",
                "Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q",
            ),
        ),
        "instrumentation_runner": (
            android_app
            / "src"
            / "androidTest"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "PairingIdentityTestInstrumentation.java",
            (
                "AuthenticatedPeerHandshakeV1InstrumentationProbe.verify()",
                "ANDROID_AUTHENTICATED_PEER_HANDSHAKE_V1_INSTRUMENTATION_OK",
                "AndroidBoundPeerHandshakeSessionInstrumentationProbe.verify()",
                "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK",
            ),
        ),
    }


def _android_peer_handshake_test_seams(root: Path) -> list[str]:
    handshake_java = _android_peer_handshake_source_dir(root)
    forbidden_markers = (
        "forTestPrivateScalar",
        "sec1ForTestScalar",
        "finishedKeyForTest",
        "channelBindingExporterForTest",
    )
    main_text = "\n".join(
        _read_text(path) for path in sorted(handshake_java.glob("*.java"))
    )
    return [token for token in forbidden_markers if token in main_text]


def _peer_handshake_wiring_errors(root: Path) -> list[str]:
    cmake_path = root / "dual_machine_runtime" / "CMakeLists.txt"
    gradle_path = root / "android_inference_benchmark" / "app" / "build.gradle"
    cmake = _read_text(cmake_path) if cmake_path.is_file() else ""
    gradle = _read_text(gradle_path) if gradle_path.is_file() else ""
    errors: list[str] = []
    dependency = "tasks.named('verifyAuthenticatedPeerHandshakeV1')"
    if gradle.count(dependency) < 3:
        errors.append("handshake Gradle gate does not reach all three release paths")
    bound_dependency = "tasks.named('verifyAndroidBoundPeerHandshakeSession')"
    if gradle.count(bound_dependency) < 3:
        errors.append("Android bound-session gate does not reach all release paths")
    if "JavaVersion.VERSION_1_8" not in gradle or "options.release.set(8)" not in gradle:
        errors.append("handshake self-test is not constrained to the Java 8 API")
    if cmake.count("shared/src/authenticated_peer_handshake_v1.cpp") != 2:
        errors.append("CMake does not isolate production and test handshake objects")
    if cmake.count(
        "VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS=1"
    ) != 1:
        errors.append("CMake test-access macro is not isolated to one target")
    return errors


def _pair_generation_proposal_foundation_evidence(
    root: Path,
) -> dict[str, Any]:
    sidecar_root = root / "server" / "visionforge-platform" / "dual_machine_service"
    runtime_root = root / "dual_machine_runtime"
    android_handshake = _android_peer_handshake_source_dir(root)
    contracts = {
        "python_implementation": (
            sidecar_root / "pair_generation_proposal_v1.py",
            (
                'PROPOSAL_DOMAIN = b"visionforge-peer-generation-proposal-v1"',
                "class VerifiedPairGenerationProposalV1",
                "build_pair_generation_proposal_v1",
                "parse_pair_generation_proposal_v1",
                "build_final_handshake_transcript_v1",
                "WeakKeyDictionary",
                "type(value) is not str",
            ),
        ),
        "python_regressions": (
            sidecar_root / "tests" / "test_pair_generation_proposal_v1.py",
            (
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098",
                "test_pair_id_rejects_str_subclass_behavior_override",
                "test_host_runtime_version_rejects_str_subclass_behavior_override",
                "test_android_runtime_version_rejects_str_subclass_behavior_override",
            ),
        ),
        "cpp_implementation": (
            runtime_root / "shared" / "src" / "pair_generation_proposal_v1.cpp",
            (
                "build_pair_generation_proposal_v1",
                "parse_pair_generation_proposal_v1",
                "build_final_peer_handshake_transcript_from_proposal_v1",
                "catch (const std::bad_alloc&)",
            ),
        ),
        "cpp_regressions": (
            runtime_root / "tests" / "pair_generation_proposal_v1_tests.cpp",
            (
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "verify_noexcept_allocation_boundaries_source_contract",
            ),
        ),
        "android_implementation": (
            android_handshake / "PairGenerationProposalV1.java",
            (
                "visionforge-peer-generation-proposal-v1",
                "parse(byte[] encoded)",
                "buildFinalHandshakeTranscript",
                "requirePositiveSigned64",
            ),
        ),
        "android_regressions": (
            root
            / "android_inference_benchmark"
            / "app"
            / "src"
            / "test"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "handshake"
            / "PairGenerationProposalV1SelfTest.java",
            (
                "89669a6d4e73b4ae9e9e44e042c75426a520f611009077d5caa5a8fafad9732d",
                "ea8f01700d0921665958fcb8dc0f9abf657499cc7423ff37dd6efbd233025098",
            ),
        ),
    }
    missing_paths, missing_tokens = _text_contract_gaps(contracts)
    return {
        "pair_generation_proposal_foundation_present": (
            not missing_paths and not missing_tokens
        ),
        "pair_generation_proposal_foundation_paths": {
            name: str(contract[0]) for name, contract in contracts.items()
        },
        "pair_generation_proposal_foundation_missing_paths": missing_paths,
        "pair_generation_proposal_foundation_missing_tokens": missing_tokens,
    }


def _pair_generation_credential_foundation_evidence(
    root: Path,
) -> dict[str, Any]:
    sidecar_root = root / "server" / "visionforge-platform" / "dual_machine_service"
    credential_path = sidecar_root / "pair_generation_credential_v1.py"
    crypto_contracts = {
        "credential_implementation": (
            credential_path,
            (
                "class PairGenerationCredentialV1Verifier",
                "class VerifiedPairGenerationCredentialV1",
                "class _PairGenerationCredentialV1Signer",
                "WeakKeyDictionary",
                "RSAPublicNumbers",
                "RSAPrivateNumbers",
                '"allocation_request_id"',
                "MAX_CREDENTIAL_TTL_SECONDS = 30",
                "MAX_ALLOCATION_TO_ISSUE_SECONDS = 5",
            ),
        ),
        "credential_regressions": (
            sidecar_root / "tests" / "test_pair_generation_credential_v1.py",
            (
                "test_verifier_rebuilds_caller_public_key_before_signature_check",
                "test_signer_rebuilds_caller_private_key_before_signing",
                "test_imported_sentinel_cannot_create_a_registered_verified_owner",
                "test_verified_owner_write_side_state_is_not_module_visible",
                "test_signing_fails_closed_when_immediate_post_verify_fails",
            ),
        ),
    }
    crypto_missing_paths, crypto_missing_tokens = _text_contract_gaps(
        crypto_contracts
    )

    service_path = sidecar_root / "pair_generation_credential_service.py"
    transactional_service_contracts = {
        "credential_service": (
            service_path,
            (
                "class PairGenerationCredentialService",
                "def issue_pair_generation_credential(",
                "def issue(",
                "_PairGenerationCredentialV1Signer",
                "VerifiedPairGenerationProposalV1",
                "_AuthoritativePairGenerationCredentialSourceV1",
                "class _JournalCredentialVerifierArchive",
                "archived_public_keys",
            ),
        ),
        "credential_service_regressions": (
            sidecar_root / "tests" / "test_pair_generation_credential_service.py",
            (
                "test_issue_persists_and_restart_returns_exact_token_even_after_expiry",
                "test_signing_or_post_verify_failure_rolls_back_every_state_change",
                "test_live_assurance_revocation_or_binding_drift_blocks_replay",
                "test_four_generation_rotation_replays_from_trusted_archival_key",
            ),
        ),
    }
    route_contracts = {
        "credential_pop_contract": (
            sidecar_root / "pair_generation_pop_v1.py",
            (
                "CHALLENGE_REQUEST_DOMAIN",
                "FINAL_CREDENTIAL_PROOF_DOMAIN",
                "build_pair_generation_challenge_request_v1",
                "derive_pair_generation_server_nonce_v1",
                "derive_pair_generation_connection_id_v1",
                "build_pair_generation_final_credential_proof_v1",
            ),
        ),
        "credential_pop_regressions": (
            sidecar_root / "tests" / "test_pair_generation_pop_v1.py",
            (
                "f5fe7552fdd4009c4fcf6bb795cc8fe49c8ced14f90e82fdef384029f171acea",
                "dc66120c8c1a81e879aac654e34421b55111d30c5e6836df235f18e90c0b0e69",
                "63191577505803677",
                "2fe727665a08adf4893b869a8d5c9842064b53f8952a32693ca37fd2a83a72e1",
            ),
        ),
        "credential_authorization_service": (
            sidecar_root / "pair_generation_authorization_service.py",
            (
                "class PairGenerationAuthorizationService",
                "build_pair_generation_challenge_request_v1",
                "build_pair_generation_final_credential_proof_v1",
                "derive_pair_generation_server_nonce_v1",
                "pair_generation_challenge_unit_of_work",
                "pair_generation_credential_unit_of_work",
                "load_peer_authority_for_context",
                "_verify_dual_signatures",
                "issue_pair_generation_credential_in_unit_of_work",
                "record_security_audit",
            ),
        ),
        "credential_route": (
            sidecar_root / "routes.py",
            (
                "PairGenerationAuthorizationService",
                "/pair-generations/challenges",
                "/pair-generations/credentials",
            ),
        ),
        "credential_composition": (
            sidecar_root / "pair_generation_composition.py",
            (
                "build_pair_generation_authorization_service",
                "pair_credential_private_key_path",
                "pair_credential_public_key_path",
                "pair_credential_previous_public_key_paths",
                "pair_credential_archived_public_key_paths",
                "archived_public_keys=archived_public_keys",
                "other_purpose_public_keys=ticket_public_keys",
            ),
        ),
        "credential_settings": (
            sidecar_root / "settings.py",
            (
                "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON",
                "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PASSWORD",
                "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS",
                "require_pair_credential_keys=True",
                "_MAX_PAIR_CREDENTIAL_VERIFICATION_KEYS = 16",
            ),
        ),
        "credential_composition_regressions": (
            sidecar_root / "tests" / "test_pair_generation_composition.py",
            (
                "test_composition_loads_dedicated_current_previous_and_archive_keys",
                "test_composition_rejects_ticket_spki_reused_through_other_paths",
                "test_pair_key_path_limits_and_total_verifier_closure_are_strict",
                "test_environment_rejects_non_array_empty_or_invalid_pair_key_json",
                "test_composition_rejects_wrong_pair_private_key_password",
            ),
        ),
        "credential_deployment_bootstrap": (
            root
            / "server"
            / "visionforge-platform"
            / "deploy"
            / "bootstrap_dual_machine_sidecar.sh",
            (
                "usage-ticket-private.pem",
                "pair-credential-private.pem",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH",
                "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON=[]",
                "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON=[]",
                "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS=15",
            ),
        ),
        "credential_deployment_regressions": (
            sidecar_root / "tests" / "test_deployment_contract.py",
            (
                "test_bootstrap_generates_independent_pair_credential_keypair",
                "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS=15",
            ),
        ),
        "credential_application_wiring": (
            sidecar_root / "main.py",
            (
                "build_pair_generation_authorization_service",
                "application.state.pair_generation_service",
            ),
        ),
        "credential_authorization_regressions": (
            sidecar_root
            / "tests"
            / "test_pair_generation_authorization_service.py",
            (
                "test_challenge_signature_binds_allocation_request_id",
                "test_final_proof_cannot_move_challenge_to_another_allocation",
                "test_server_rejects_proposal_with_non_derived_connection_id",
                "test_challenge_rechecks_registered_key_after_acquiring_write_lock",
                "test_credential_rechecks_registered_key_inside_issuance_transaction",
                "test_success_audit_failure_rolls_back_credential_and_challenge",
                "test_public_routes_use_composed_dedicated_key_and_strict_wire_types",
            ),
        ),
    }
    service_contracts = {
        **transactional_service_contracts,
        **route_contracts,
    }
    transactional_missing_paths, transactional_missing_tokens = (
        _code_contract_gaps(transactional_service_contracts)
    )
    transactional_issuance_service_present = (
        not transactional_missing_paths and not transactional_missing_tokens
    )
    service_missing_paths, service_missing_tokens = _code_contract_gaps(
        service_contracts
    )
    application_routes = set(_python_route_literals(sidecar_root / "routes.py"))
    required_credential_routes = {
        DUAL_MACHINE_API_PREFIX + "/pair-generations/challenges",
        DUAL_MACHINE_API_PREFIX + "/pair-generations/credentials",
    }
    credential_route_registered = (
        required_credential_routes.issubset(application_routes)
    )
    authoritative_service_wired = (
        not service_missing_paths
        and not service_missing_tokens
        and credential_route_registered
    )

    journal_contracts = {
        "credential_journal_schema": (
            sidecar_root / "database.py",
            (
                "CREATE TABLE dm_pair_generation_credentials (",
                "allocation_request_id TEXT PRIMARY KEY REFERENCES",
                "credential_nonce_sha256",
                "credential_sha256",
                "credential_token",
                "_PAIR_GENERATION_CREDENTIAL_TABLE_SQL",
                "_normalized_schema_sql",
                "pair generation credential journal requires operator recovery",
                "dm_pair_credentials_reject_update",
                "dm_pair_credentials_reject_delete",
            ),
        ),
        "credential_journal_service": (
            service_path,
            (
                "pair_generation_credential_unit_of_work",
                "persist_generation_credential_issuance",
                "_credential_record_from_signed",
                "_verified_journal_result",
                "JOURNAL_MISSING",
            ),
        ),
        "credential_journal_repository": (
            sidecar_root / "pair_security_repository.py",
            (
                "class PairGenerationCredentialUnitOfWork",
                "def load_generation_credential_issuance(",
                "def persist_generation_credential_issuance(",
                'connection.execute("BEGIN IMMEDIATE")',
            ),
        ),
        "credential_journal_regressions": (
            sidecar_root / "tests" / "test_pair_generation_credential_service.py",
            (
                "test_concurrent_exact_issue_mints_one_token",
                "test_issue_persists_and_restart_returns_exact_token_even_after_expiry",
                "test_credential_journal_is_append_only_and_schema_history_is_preserved",
                "test_initialization_rebuilds_empty_weak_credential_journal_schema",
                "test_initialization_rejects_nonempty_weak_credential_journal_schema",
            ),
        ),
    }
    journal_missing_paths, journal_missing_tokens = _code_contract_gaps(
        journal_contracts
    )
    immutable_issuance_journal_wired = (
        not journal_missing_paths and not journal_missing_tokens
    )

    host_verifier = (
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "security"
        / "src"
        / "host_pair_generation_credential_verifier_v1.cpp"
    )
    android_verifier = (
        _android_peer_handshake_source_dir(root)
        / "PairGenerationCredentialV1Verifier.java"
    )
    client_contracts = {
        "host_credential_verifier": (
            host_verifier,
            (
                "PairGenerationCredentialV1Verifier",
                "allocation_request_id",
                "transcript_proposal_sha256",
                "generation",
                "RS256",
            ),
        ),
        "host_credential_runtime_wiring": (
            root
            / "dual_machine_runtime"
            / "host"
            / "windows"
            / "src"
            / "authenticated_pairing_handshake.cpp",
            (
                "PairGenerationCredentialV1Verifier",
                "transcript_proposal_sha256",
            ),
        ),
        "host_credential_build_wiring": (
            root / "dual_machine_runtime" / "CMakeLists.txt",
            (
                "host_pair_generation_credential_verifier_v1.cpp",
                "vfdual_host_pair_generation_credential_verifier_v1_tests",
                "add_test(",
            ),
        ),
        "host_credential_regressions": (
            root
            / "dual_machine_runtime"
            / "host"
            / "windows"
            / "security"
            / "tests"
            / "host_pair_generation_credential_verifier_v1_tests.cpp",
            (
                "rejects_invalid_signature",
                "rejects_proposal_generation_or_identity_mismatch",
                "rejects_expired_or_rolled_back_credential",
            ),
        ),
        "android_credential_verifier": (
            android_verifier,
            (
                "PairGenerationCredentialV1Verifier",
                "allocation_request_id",
                "transcript_proposal_sha256",
                "generation",
                "RS256",
            ),
        ),
        "android_credential_runtime_wiring": (
            root
            / "android_inference_benchmark"
            / "app"
            / "src"
            / "main"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "MobileRuntimeService.java",
            (
                "PairGenerationCredentialV1Verifier",
                "transcriptProposalSha256",
            ),
        ),
        "android_credential_regressions": (
            root
            / "android_inference_benchmark"
            / "app"
            / "src"
            / "test"
            / "java"
            / "com"
            / "visionforge"
            / "inferencebenchmark"
            / "handshake"
            / "PairGenerationCredentialV1VerifierSelfTest.java",
            (
                "rejectsInvalidSignature",
                "rejectsProposalGenerationOrIdentityMismatch",
                "rejectsExpiredOrRolledBackCredential",
            ),
        ),
        "android_credential_build_wiring": (
            root / "android_inference_benchmark" / "app" / "build.gradle",
            (
                "verifyPairGenerationCredentialV1",
                "PairGenerationCredentialV1VerifierSelfTest",
                "preReleaseBuild",
            ),
        ),
    }
    client_missing_paths, client_missing_tokens = _code_contract_gaps(
        client_contracts
    )
    client_generation_verifiers_wired = (
        not client_missing_paths and not client_missing_tokens
    )

    crypto_foundation_present = (
        not crypto_missing_paths and not crypto_missing_tokens
    )
    marker_evidence = _formal_security_marker_evidence(root)
    host_formal_marker_enabled = marker_evidence[
        "host_formal_security_marker_enabled"
    ]
    android_formal_marker_enabled = marker_evidence[
        "android_formal_security_marker_enabled"
    ]
    formal_capability_markers_enabled = marker_evidence[
        "formal_capability_markers_enabled"
    ]
    signed_credential_implemented = (
        crypto_foundation_present
        and authoritative_service_wired
        and immutable_issuance_journal_wired
        and client_generation_verifiers_wired
        and formal_capability_markers_enabled
    )
    incomplete_contracts: list[str] = []
    for category, paths, tokens in (
        ("crypto", crypto_missing_paths, crypto_missing_tokens),
        ("service", service_missing_paths, service_missing_tokens),
        ("journal", journal_missing_paths, journal_missing_tokens),
        ("clients", client_missing_paths, client_missing_tokens),
    ):
        incomplete_contracts.extend(f"{category}:missing_path:{path}" for path in paths)
        incomplete_contracts.extend(
            f"{category}:{name}:missing_token:{token}"
            for name, missing in tokens.items()
            for token in missing
        )
    if not host_formal_marker_enabled:
        incomplete_contracts.append(
            "formal_marker:host:VFDUAL_FORMAL_SECURITY_IMPLEMENTED=ON"
        )
    if not android_formal_marker_enabled:
        incomplete_contracts.append(
            "formal_marker:android:formalSecureDataPlaneImplemented=true"
        )
    if not credential_route_registered:
        incomplete_contracts.extend(
            "service:missing_application_route:" + route
            for route in sorted(required_credential_routes - application_routes)
        )
    return {
        "pair_generation_credential_crypto_foundation_present": (
            crypto_foundation_present
        ),
        "pair_generation_credential_crypto_paths": {
            name: str(contract[0]) for name, contract in crypto_contracts.items()
        },
        "pair_generation_credential_crypto_missing_paths": crypto_missing_paths,
        "pair_generation_credential_crypto_missing_tokens": crypto_missing_tokens,
        "authoritative_service_wired": authoritative_service_wired,
        "transactional_issuance_service_present": (
            transactional_issuance_service_present
        ),
        "transactional_issuance_service_missing_paths": (
            transactional_missing_paths
        ),
        "transactional_issuance_service_missing_tokens": (
            transactional_missing_tokens
        ),
        "authoritative_service_paths": {
            name: str(contract[0]) for name, contract in service_contracts.items()
        },
        "authoritative_service_missing_paths": service_missing_paths,
        "authoritative_service_missing_tokens": service_missing_tokens,
        "authoritative_credential_route_registered": (
            credential_route_registered
        ),
        "immutable_issuance_journal_wired": immutable_issuance_journal_wired,
        "immutable_issuance_journal_paths": {
            name: str(contract[0]) for name, contract in journal_contracts.items()
        },
        "immutable_issuance_journal_missing_paths": journal_missing_paths,
        "immutable_issuance_journal_missing_tokens": journal_missing_tokens,
        "client_generation_verifiers_wired": client_generation_verifiers_wired,
        "client_generation_verifier_paths": {
            name: str(contract[0]) for name, contract in client_contracts.items()
        },
        "client_generation_verifier_missing_paths": client_missing_paths,
        "client_generation_verifier_missing_tokens": client_missing_tokens,
        **marker_evidence,
        "signed_generation_credential_implemented": signed_credential_implemented,
        "signed_generation_credential_path": str(service_path),
        "signed_generation_credential_missing_tokens": incomplete_contracts,
    }


def _server_pair_generation_foundation_evidence(root: Path) -> dict[str, Any]:
    sidecar_root = root / "server" / "visionforge-platform" / "dual_machine_service"
    contracts = {
        "database": (
            sidecar_root / "database.py",
            (
                "CREATE TABLE IF NOT EXISTS dm_pair_security_state (",
                "CREATE TABLE IF NOT EXISTS dm_pair_generation_challenges (",
                "CREATE TABLE IF NOT EXISTS dm_pair_generation_allocations (",
                'connection.execute("BEGIN IMMEDIATE")',
                "_migrate_pair_security_schema(connection)",
                "_migrate_pair_generation_allocation_schema",
                "_reinstall_pair_security_triggers",
                "PAIR_SECURITY_TRIGGER_NAMES = (",
                "PAIR_SECURITY_INDEX_NAMES",
                "_reinstall_pair_security_indexes",
                "CREATE UNIQUE INDEX idx_dm_pair_one_issued_challenge ",
                "ON dm_pair_generation_challenges(pair_id) ",
                "WHERE status = 'issued'",
                "dm_pair_allocations_reject_update",
                "dm_pair_allocations_reject_delete",
                "dm_pair_state_reject_delete",
                "dm_pair_state_reject_identity_update",
                "dm_pair_state_reject_rollback",
                "dm_pair_state_validate_transition",
                "dm_pair_challenge_reject_delete",
                "dm_pair_challenge_reject_content_update",
                "dm_pair_challenge_reject_terminal_update",
                'legacy_table = "dm_pair_generation_allocations_with_credential_v7"',
                'removed_columns = {"credential_token", "credential_sha256"}',
                "pair generation allocation migration requires operator recovery",
                "DROP TRIGGER IF EXISTS",
                "BEGIN IMMEDIATE",
            ),
        ),
        "repository": (
            sidecar_root / "pair_security_repository.py",
            (
                "def register_pending_pair(",
                "binding_revision = _next_binding_revision(",
                "def issue_generation_challenge(",
                "def allocate_generation(",
                "_require_exact_allocation_retry",
                "_require_live_binding(connection, identity)",
                "_require_issued_challenge(",
                "_advance_generation_high_water(",
                "_consume_challenge(",
                "_insert_allocation(",
                'connection.execute("BEGIN IMMEDIATE")',
            ),
        ),
        "verified_activation_bootstrap": (
            sidecar_root / "pair_security_bootstrap.py",
            (
                "class _VerifiedActivationBindingProof",
                "class _PairSecurityBootstrapService",
                "def commit_verified_binding(",
                "_verified_activation_binding_proof",
                "PairSecurityRepository._register_pending",
                "pair_security_bootstrap_reactivation_revision_invalid",
                "__all__: tuple[str, ...] = ()",
            ),
        ),
        "card_activation_bootstrap_wiring": (
            sidecar_root / "card_service.py",
            (
                "verified_pair_proof = self._verify_confirmation(",
                "self._commit_pair_security_binding(",
                "pair_security_binding_activated",
                "_response_with_pair_security",
            ),
        ),
        "regressions": (
            sidecar_root / "tests" / "test_pair_generation.py",
            (
                "test_pending_revision_is_server_allocated_and_retry_revalidates_binding",
                "test_concurrent_exact_allocation_retry_returns_one_stored_tuple",
                "test_same_challenge_different_allocation_requests_have_one_winner",
                "test_same_allocation_request_different_payload_has_one_exact_winner",
                "test_initialization_replaces_a_weak_known_security_trigger",
                "test_initialization_replaces_wrong_one_issued_challenge_index",
                "test_initialization_rejects_preexisting_duplicate_issued_challenges",
                "test_true_legacy_schema_without_pair_tables_upgrades_fail_closed",
                "test_orphaned_allocation_migration_table_requires_operator_recovery",
                "test_half_upgraded_credential_schema_is_removed_and_reentry_is_exact",
            ),
        ),
        "activation_bootstrap_regressions": (
            sidecar_root / "tests" / "test_card_activation.py",
            (
                "test_activation_credits_balance_without_starting_billing",
                "test_invalid_device_proof_never_consumes_card",
                "test_pair_security_bootstrap_failure_rolls_back_activation_transaction",
            ),
        ),
    }
    missing_paths, missing_tokens = _text_contract_gaps(contracts)
    database_path = sidecar_root / "database.py"
    static_schema_version = _python_top_level_string_assignment(
        database_path,
        "SCHEMA_VERSION",
    )
    runtime_schema_version = _python_runtime_exact_string_constant(
        database_path,
        "SCHEMA_VERSION",
    )
    schema_version = runtime_schema_version
    schema_version_approved = (
        static_schema_version == runtime_schema_version
        and runtime_schema_version in APPROVED_PAIR_GENERATION_SCHEMA_LINEAGE
    )
    if not schema_version_approved:
        missing_tokens.setdefault("database", []).append(
            "approved exact top-level SCHEMA_VERSION assignment"
        )

    repository_path = sidecar_root / "pair_security_repository.py"
    repository_text = _read_text(repository_path) if repository_path.is_file() else ""
    forbidden_repository_tokens = [
        token
        for token in (
            "def activate_pair(",
        )
        if token in repository_text
    ]
    database_text = _read_text(database_path) if database_path.is_file() else ""
    forbidden_database_tokens = [
        token
        for token in (
            "CREATE TRIGGER IF NOT EXISTS dm_pair_",
            "CREATE INDEX idx_dm_pair_one_issued_challenge ",
        )
        if token in database_text
    ]

    public_route_references: dict[str, list[str]] = {}
    for route_path in (sidecar_root / "routes.py", sidecar_root / "main.py"):
        present = [
            route
            for route in _python_route_literals(route_path)
            if route.startswith(
                DUAL_MACHINE_API_PREFIX + "/pair-generations"
            )
        ]
        if present:
            public_route_references[str(route_path)] = present

    foundation_present = (
        not missing_paths
        and not missing_tokens
        and not forbidden_repository_tokens
        and not forbidden_database_tokens
    )
    return {
        **_pair_generation_proposal_foundation_evidence(root),
        **_pair_generation_credential_foundation_evidence(root),
        "pair_generation_foundation_present": foundation_present,
        "pair_generation_foundation_paths": {
            name: str(contract[0]) for name, contract in contracts.items()
        },
        "pair_generation_foundation_missing_paths": missing_paths,
        "pair_generation_foundation_missing_tokens": missing_tokens,
        "pair_generation_schema_version": schema_version,
        "pair_generation_static_schema_version": static_schema_version,
        "pair_generation_runtime_schema_version": runtime_schema_version,
        "pair_generation_schema_version_approved": schema_version_approved,
        "pair_generation_approved_schema_lineage": sorted(
            APPROVED_PAIR_GENERATION_SCHEMA_LINEAGE
        ),
        "pair_generation_forbidden_database_tokens": (
            forbidden_database_tokens
        ),
        "pair_generation_forbidden_repository_tokens": (
            forbidden_repository_tokens
        ),
        "pair_generation_public_route_registered": bool(public_route_references),
        "pair_generation_public_route_references": public_route_references,
    }


def _peer_handshake_foundation_evidence(root: Path) -> dict[str, Any]:
    core_contracts = _peer_handshake_core_contracts(root)
    gate_contracts = _peer_handshake_gate_contracts(root)
    core_missing_paths, core_missing_tokens = _text_contract_gaps(core_contracts)
    gate_missing_paths, gate_missing_tokens = _text_contract_gaps(gate_contracts)
    forbidden_present = _android_peer_handshake_test_seams(root)
    wiring_errors = _peer_handshake_wiring_errors(root)
    return {
        **_server_pair_generation_foundation_evidence(root),
        "foundation_present": not core_missing_paths and not core_missing_tokens,
        "foundation_tests_wired": (
            not gate_missing_paths
            and not gate_missing_tokens
            and not forbidden_present
            and not wiring_errors
        ),
        "foundation_paths": {
            name: str(contract[0]) for name, contract in core_contracts.items()
        },
        "gate_paths": {
            name: str(contract[0]) for name, contract in gate_contracts.items()
        },
        "foundation_missing_paths": core_missing_paths,
        "foundation_missing_tokens": core_missing_tokens,
        "gate_missing_paths": gate_missing_paths,
        "gate_missing_tokens": gate_missing_tokens,
        "android_main_test_seams": forbidden_present,
        "wiring_errors": wiring_errors,
    }


def _check_handshake_channel_binding(root: Path) -> CheckResult:
    host_path = (
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "authenticated_pairing_handshake.cpp"
    )
    android_path = (
        root
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
    mobile_runtime = android_path.with_name("MobileRuntimeService.java")
    host_text = _code_without_comments(host_path) if host_path.is_file() else ""
    android_text = (
        _code_without_comments(android_path) if android_path.is_file() else ""
    )
    host_required_tokens = (
        "ECDH",
        "transcript",
        "channel_binding",
        "connection_id",
        "key_epoch",
    )
    android_required_tokens = (
        "ECDH",
        "transcript",
        "channelBinding",
        "connectionId",
        "keyEpoch",
    )
    host_missing = [
        token for token in host_required_tokens if token not in host_text
    ]
    android_missing = [
        token for token in android_required_tokens if token not in android_text
    ]
    missing = [
        *(f"host:{token}" for token in host_missing),
        *(f"android:{token}" for token in android_missing),
    ]
    mobile_text = (
        _code_without_comments(mobile_runtime)
        if mobile_runtime.is_file()
        else ""
    )
    forbidden = [
        token
        for token in ("androidOnlyChannelBinding(", "video_encrypted=false")
        if token in mobile_text
    ]
    foundation = _peer_handshake_foundation_evidence(root)
    production_runtime_wired = (
        host_path.is_file()
        and android_path.is_file()
        and not missing
        and not forbidden
    )
    evidence = {
        **foundation,
        "host_handshake": str(host_path),
        "android_handshake": str(android_path),
        "missing_handshake_tokens": missing,
        "host_missing_handshake_tokens": host_missing,
        "android_missing_handshake_tokens": android_missing,
        "forbidden_local_binding_tokens": forbidden,
        "production_runtime_wired": production_runtime_wired,
    }
    if (
        not foundation["foundation_present"]
        or not foundation["foundation_tests_wired"]
        or not foundation["pair_generation_foundation_present"]
        or not foundation["pair_generation_proposal_foundation_present"]
        or not foundation[
            "pair_generation_credential_crypto_foundation_present"
        ]
        or not foundation["authoritative_service_wired"]
        or not foundation["immutable_issuance_journal_wired"]
        or not foundation["client_generation_verifiers_wired"]
        or not foundation["formal_capability_markers_enabled"]
        or not foundation["signed_generation_credential_implemented"]
        or not foundation["pair_generation_public_route_registered"]
        or not production_runtime_wired
    ):
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "handshake-channel-binding",
            "Pairing lacks a wired fresh ECDHE transcript/exporter channel binding",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "handshake-channel-binding",
        "Pairing derives the channel binding from a fresh authenticated handshake",
        evidence,
    )


def _check_video_aead_envelope(root: Path) -> CheckResult:
    secure_header = (
        root
        / "dual_machine_runtime"
        / "shared"
        / "include"
        / "vfdual"
        / "authenticated_data_plane_v2.hpp"
    )
    secure_source = (
        root
        / "dual_machine_runtime"
        / "shared"
        / "src"
        / "authenticated_data_plane_v2.cpp"
    )
    legacy_protocol = (
        root
        / "dual_machine_runtime"
        / "shared"
        / "include"
        / "vfdual"
        / "protocol.hpp"
    )
    secure_text = "\n".join(
        _read_text(path) for path in (secure_header, secure_source) if path.is_file()
    )
    required_tokens = (
        "kAuthenticatedDataPlaneVersion",
        "connection_id",
        "key_epoch",
        "packet_counter",
        "AES",
        "GCM",
        "authentication_tag",
    )
    missing = [token for token in required_tokens if token not in secure_text]
    legacy_markers: dict[str, list[str]] = {}
    for path, tokens in ((legacy_protocol, ("VFRG", "VFRR")),):
        text = _read_text(path) if path.exists() else ""
        present = [token for token in tokens if token in text]
        if present:
            legacy_markers[str(path)] = present
    evidence = {
        "secure_header": str(secure_header),
        "secure_source": str(secure_source),
        "missing_secure_header_tokens": missing,
        "legacy_plaintext_markers": legacy_markers,
    }
    if not secure_header.is_file() or not secure_source.is_file() or missing or legacy_markers:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "video-aead-envelope",
            "Video packets are not wired through the required AEAD v2 envelope",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "video-aead-envelope",
        "Video packets use the authenticated v2 envelope",
        evidence,
    )


def _check_authenticated_path_probe(root: Path) -> CheckResult:
    probe = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "HostVideoPresenceProbe.java"
    )
    text = _read_text(probe) if probe.is_file() else ""
    forbidden = [
        token
        for token in ("VFRG", "VFRR", "does not authenticate", "does not encrypt")
        if token in text
    ]
    required = ("AuthenticatedDataPlane", "connectionId", "keyEpoch", "fresh")
    missing = [token for token in required if token not in text]
    evidence = {
        "path": str(probe),
        "plaintext_probe_tokens": forbidden,
        "missing_authenticated_probe_tokens": missing,
    }
    if not probe.is_file() or forbidden or missing:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-path-probe",
            "Host presence can still be inferred from an unauthenticated plaintext probe",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-path-probe",
        "Host presence requires fresh authenticated data-plane progress",
        evidence,
    )


def _check_authenticated_idr(root: Path) -> CheckResult:
    paths = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "cpp"
        / "DualMachineReceiver.cpp",
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "idr_request_listener.cpp",
    )
    insecure = {
        str(path): [token for token in ("IDR1",) if token in _read_text(path)]
        for path in paths
        if path.is_file() and "IDR1" in _read_text(path)
    }
    missing_paths = [str(path) for path in paths if not path.is_file()]
    evidence = {"legacy_idr_markers": insecure, "missing_paths": missing_paths}
    if missing_paths or insecure:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-idr",
            "IDR requests remain forgeable outside the authenticated session",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-idr",
        "IDR requests are authenticated and session-bound",
        evidence,
    )


def _check_authenticated_mouse_button(root: Path) -> CheckResult:
    paths = (
        root
        / "dual_machine_runtime"
        / "shared"
        / "include"
        / "vfdual"
        / "mouse_button_protocol.hpp",
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "Cat6MouseButtonProtocol.java",
        root
        / "dual_machine_runtime"
        / "host"
        / "windows"
        / "src"
        / "host_mouse_button_publisher.cpp",
    )
    insecure = {
        str(path): ["VFMB"]
        for path in paths
        if path.is_file() and "VFMB" in _read_text(path)
    }
    missing_paths = [str(path) for path in paths if not path.is_file()]
    evidence = {"legacy_mouse_button_markers": insecure, "missing_paths": missing_paths}
    if missing_paths or insecure:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-mouse-button",
            "Mouse-button packets remain forgeable outside the authenticated session",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "authenticated-mouse-button",
        "Mouse-button packets are authenticated and session-bound",
        evidence,
    )


def _check_anti_replay_nonce_contract(root: Path) -> CheckResult:
    cpp_header = (
        root
        / "dual_machine_runtime"
        / "shared"
        / "include"
        / "vfdual"
        / "authenticated_data_plane_v2.hpp"
    )
    cpp_tests = (
        root
        / "dual_machine_runtime"
        / "tests"
        / "authenticated_data_plane_v2_tests.cpp"
    )
    android_root = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
    )
    android_contract = (
        android_root
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "dataplane"
        / "AuthenticatedDataPlaneV2.java"
    )
    android_sender = android_contract.with_name("AuthenticatedDataPlaneV2Sender.java")
    android_receiver = android_contract.with_name("AuthenticatedDataPlaneV2Receiver.java")
    android_tests = (
        android_root
        / "test"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "dataplane"
        / "AuthenticatedDataPlaneV2SelfTest.java"
    )
    gradle = root / "android_inference_benchmark" / "app" / "build.gradle"
    contracts = {
        "cpp_header": (
            cpp_header,
            (
                "kReplayWindowBits = 1024U",
                "kMaximumPacketsPerTrafficKey",
                "kMaximumAuthenticatedPacketCounter",
                "compose_authenticated_packet_nonce",
                "counter_exceeds_key_lifetime",
            ),
        ),
        "cpp_behavior_tests": (
            cpp_tests,
            (
                "verify_encryption_failure_burns_nonce_counter",
                "verify_exact_replay_window_shift_boundaries",
                "verify_key_lifetime_requires_rekey_before_counter_wrap",
                "verify_tag_aad_and_ciphertext_fail_closed",
                "verify_java_cpp_interop_vector",
            ),
        ),
        "android_contract": (
            android_contract,
            (
                "DEFAULT_REPLAY_WINDOW_SIZE = 1024",
                "MAX_PACKETS_PER_TRAFFIC_KEY = 1L << 23",
                "MAX_COUNTER_PER_TRAFFIC_KEY",
            ),
        ),
        "android_sender": (
            android_sender,
            ("burnCounter(counter)", "NO_ENCRYPTION_FAILURE"),
        ),
        "android_receiver": (
            android_receiver,
            ("commitAuthenticated", "UNAUTHENTICATED_PACKET"),
        ),
        "android_behavior_tests": (
            android_tests,
            (
                "verifiesExactReplayWindowShiftBoundaries",
                "verifiesCounterBurnLifetimeLimitAndRekey",
                "VECTOR_WIRE_HEX",
                "Long.MIN_VALUE",
            ),
        ),
        "android_gradle_gate": (
            gradle,
            ("verifyAuthenticatedDataPlaneV2", "preReleaseBuild"),
        ),
    }
    missing_by_contract: dict[str, list[str]] = {}
    missing_paths: list[str] = []
    for name, (path, required_tokens) in contracts.items():
        if not path.is_file():
            missing_paths.append(str(path))
            continue
        text = _read_text(path)
        missing = [token for token in required_tokens if token not in text]
        if missing:
            missing_by_contract[name] = missing
    evidence = {
        "contracts": {name: str(value[0]) for name, value in contracts.items()},
        "missing_paths": missing_paths,
        "missing_nonce_replay_test_tokens": missing_by_contract,
    }
    if missing_paths or missing_by_contract:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "anti-replay-nonce-contract",
            "Nonce uniqueness and the anti-replay window lack executable boundary tests",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "anti-replay-nonce-contract",
        "C++ and Android nonce lifetime and anti-replay boundaries have wired executable tests",
        evidence,
    )


def _check_no_plaintext_fallback(root: Path) -> CheckResult:
    cmake_path = root / "dual_machine_runtime" / "CMakeLists.txt"
    gradle_path = root / "android_inference_benchmark" / "app" / "build.gradle"
    cmake = _code_without_comments(cmake_path) if cmake_path.is_file() else ""
    gradle = _code_without_comments(gradle_path) if gradle_path.is_file() else ""
    host_required = (
        "VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY",
        'include("${CMAKE_CURRENT_SOURCE_DIR}/formal_security_loader.cmake")',
    )
    android_required = (
        "apply from: 'formal-security-loader.gradle'",
    )
    host_missing = [token for token in host_required if token not in cmake]
    android_missing = [token for token in android_required if token not in gradle]
    missing = [
        *(f"host:{token}" for token in host_missing),
        *(f"android:{token}" for token in android_missing),
    ]
    marker_evidence = _formal_security_marker_evidence(root)
    implementation_blockers: list[str] = []
    if not marker_evidence["host_formal_security_marker_enabled"]:
        implementation_blockers.append("Host formal implementation marker is not ON")
    if not marker_evidence["android_formal_security_marker_enabled"]:
        implementation_blockers.append(
            "Android formal implementation marker is not true"
        )
    evidence = {
        "cmake": str(cmake_path),
        "gradle": str(gradle_path),
        "missing_no_downgrade_gates": missing,
        "formal_implementation_blockers": implementation_blockers,
        **marker_evidence,
    }
    if (
        not cmake_path.is_file()
        or not gradle_path.is_file()
        or missing
        or implementation_blockers
    ):
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-fallback",
            "Formal Host/APK builds do not yet prove plaintext downgrade is unreachable",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-fallback",
        "Formal Host/APK builds fail closed without a plaintext fallback",
        evidence,
    )


def _check_host_public_security_inputs(root: Path) -> CheckResult:
    cmake_path = root / "dual_machine_runtime" / "CMakeLists.txt"
    material_path = root / "tools" / "prepare_dual_machine_release_materials.py"
    combined = "\n".join(
        _read_text(path) for path in (cmake_path, material_path) if path.is_file()
    )
    required = (
        "VFDUAL_ENFORCE_HOST_RELEASE_SECURITY_INPUTS",
        "VFDUAL_DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64",
        "HOST_AUTHORIZATION_GATE",
    )
    missing = [token for token in required if token not in combined]
    forbidden = [
        token
        for token in ('"HOST_AUTHORIZATION_GATE": "disabled"',)
        if token in combined
    ]
    evidence = {
        "cmake": str(cmake_path),
        "release_materials": str(material_path),
        "missing_public_verification_inputs": missing,
        "disabled_host_gate_tokens": forbidden,
    }
    if not cmake_path.is_file() or not material_path.is_file() or missing or forbidden:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "host-public-security-inputs",
            "Formal Host build does not require the public verification keyring and policy",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "host-public-security-inputs",
        "Formal Host build requires public verification material without server secrets",
        evidence,
    )


def _check_no_plaintext_model_payload(root: Path) -> CheckResult:
    build_path = root / "android_inference_benchmark" / "app" / "build.gradle"
    installer_path = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "PortableModelAssetInstaller.java"
    )
    build_text = _read_text(build_path) if build_path.exists() else ""
    plaintext_model_markers = [
        token
        for token in (
            "include 'libvalorant_416_v11s_no_flash_w8a16.so'",
            "include 'libow2_416_w8a16.so'",
            "include 'libdelta_416_v8s_w8a16.so'",
            "include 'libcs2_vombit_416_v8s_w8a16.so'",
        )
        if token in build_text
    ]
    evidence = {
        "build_path": str(build_path),
        "portable_model_installer_present": installer_path.is_file(),
        "plaintext_model_packaging_markers": plaintext_model_markers,
    }
    if not build_path.is_file() or plaintext_model_markers or installer_path.is_file():
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-model-payload",
            "Release APK can still carry portable ONNX or plaintext QNN model payloads",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "no-plaintext-model-payload",
        "Release APK source contract contains no plaintext business-model payload",
        evidence,
    )


def _check_encrypted_model_key_release(root: Path) -> CheckResult:
    build_path = root / "android_inference_benchmark" / "app" / "build.gradle"
    client_path = (
        root
        / "android_inference_benchmark"
        / "app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "visionforge"
        / "inferencebenchmark"
        / "EncryptedModelProvisioningClient.java"
    )
    server_path = (
        root
        / "server"
        / "visionforge-platform"
        / "app"
        / "routes"
        / "dual_machine_model_api.py"
    )
    combined = "\n".join(
        _read_text(path) for path in (build_path, client_path, server_path) if path.is_file()
    )
    required = (
        "stageEncryptedModelEnvelopes",
        "verifyReleaseContainsNoPlaintextModelPayloads",
        "attestation",
        "lease",
        "key_epoch",
        "model_key",
    )
    missing = [token for token in required if token not in combined]
    evidence = {
        "build": str(build_path),
        "client": str(client_path),
        "server": str(server_path),
        "missing_encrypted_key_release_tokens": missing,
    }
    if not client_path.is_file() or not server_path.is_file() or missing:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "encrypted-model-key-release",
            "Model decryption keys are not released as short-lived attested capabilities",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "encrypted-model-key-release",
        "Model keys are short-lived, device/session/version bound capabilities",
        evidence,
    )


def _check_cryptographic_behavior_evidence(root: Path) -> CheckResult:
    verifier_path = root / "tools" / "verify_dual_machine_cryptographic_evidence.py"
    tests_path = root / "tests" / "test_dual_machine_cryptographic_evidence.py"
    evidence = {
        "verifier": str(verifier_path),
        "tests": str(tests_path),
        "verifier_present": verifier_path.is_file(),
        "tests_present": tests_path.is_file(),
    }
    if not verifier_path.is_file() or not tests_path.is_file():
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "cryptographic-behavior-evidence",
            "Formal mutation/replay/artifact evidence verifier is not implemented",
            evidence,
        )
    combined = _read_text(verifier_path) + "\n" + _read_text(tests_path)
    required = (
        "tag_bit_flip",
        "aad_bit_flip",
        "ciphertext_bit_flip",
        "duplicate_counter",
        "wrong_connection",
        "wrong_epoch",
        "wrong_direction",
        "cross_session",
        "plaintext_downgrade",
        "artifact_sha256",
    )
    missing = [token for token in required if token not in combined]
    evidence["missing_behavior_cases"] = missing
    if missing:
        return _fail(
            REVERSE_RESISTANCE_CHECK_PREFIX + "cryptographic-behavior-evidence",
            "Formal cryptographic evidence matrix is incomplete",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_CHECK_PREFIX + "cryptographic-behavior-evidence",
        "Formal mutation/replay evidence verifier covers the required attack matrix",
        evidence,
    )


def _check_reverse_resistance_registry(results: Sequence[CheckResult]) -> CheckResult:
    names = [result.name for result in results]
    seen = set(names)
    duplicates = sorted({name for name in names if names.count(name) > 1})
    missing = sorted(REQUIRED_REVERSE_RESISTANCE_CHECKS - seen)
    unexpected = sorted(seen - REQUIRED_REVERSE_RESISTANCE_CHECKS)
    evidence = {
        "required": sorted(REQUIRED_REVERSE_RESISTANCE_CHECKS),
        "observed": names,
        "missing": missing,
        "duplicates": duplicates,
        "unexpected": unexpected,
    }
    if missing or duplicates or unexpected:
        return _fail(
            REVERSE_RESISTANCE_REGISTRY_CHECK,
            "Reverse-resistance check registry is incomplete or ambiguous",
            evidence,
        )
    return _pass(
        REVERSE_RESISTANCE_REGISTRY_CHECK,
        "Every required reverse-resistance blocker is registered exactly once",
        evidence,
    )


def check_reverse_resistance_contracts(root: Path = ROOT) -> list[CheckResult]:
    """Return formal blockers derived from the local reverse-engineering corpus."""
    results = [
        _check_host_authenticated_permit(root),
        _check_host_independent_hardware_identity(root),
        _check_android_no_local_fake_host(root),
        _check_handshake_channel_binding(root),
        _check_video_aead_envelope(root),
        _check_authenticated_path_probe(root),
        _check_authenticated_idr(root),
        _check_authenticated_mouse_button(root),
        _check_anti_replay_nonce_contract(root),
        _check_no_plaintext_fallback(root),
        _check_host_public_security_inputs(root),
        _check_no_plaintext_model_payload(root),
        _check_encrypted_model_key_release(root),
        _check_cryptographic_behavior_evidence(root),
    ]
    return [*results, _check_reverse_resistance_registry(results)]


def validate_security_headers(headers: Mapping[str, str]) -> list[str]:
    normalized_headers = {
        key.lower(): value.strip()
        for key, value in headers.items()
        if value.strip()
    }
    errors: list[str] = []
    for header_name, required_tokens in EXPECTED_SECURITY_HEADER_TOKENS.items():
        actual = normalized_headers.get(header_name, "")
        if not actual:
            errors.append(f"{header_name} is missing")
            continue
        actual_lower = actual.lower()
        for token in required_tokens:
            if token.lower() not in actual_lower:
                errors.append(
                    f"{header_name} is missing token {token!r}: {actual!r}"
                )
    if not normalized_headers.get("x-trace-id", ""):
        errors.append("x-trace-id is missing or empty")
    return errors


def build_api_url(base_url: str, route_path: str) -> str:
    if not route_path.startswith("/"):
        raise ValueError("route_path must start with '/'")

    parsed = urllib.parse.urlsplit(base_url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"base_url must be absolute: {base_url!r}")

    base_path = parsed.path.rstrip("/")
    if base_path.endswith(DUAL_MACHINE_API_PREFIX):
        final_path = base_path + route_path
    else:
        final_path = base_path + DUAL_MACHINE_API_PREFIX + route_path
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, final_path, "", "")
    )


def _header_map(message: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key in message.keys():
        values = message.get_all(key) or []
        headers[key.lower()] = ", ".join(values)
    return headers


def _fetch_get(url: str, timeout_sec: float) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "VisionForgeDualMachineVerifier/1"},
        method="GET",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_sec) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status": int(response.status),
                "headers": _header_map(response.headers),
                "body_prefix": body,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            }
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="replace")
        return {
            "ok": True,
            "status": int(exc.code),
            "headers": _header_map(exc.headers),
            "body_prefix": body,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "error": str(exc.reason),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def check_public_api_endpoint(
    base_url: str,
    *,
    timeout_sec: float,
) -> CheckResult:
    try:
        url = build_api_url(base_url, ACTIVATION_CHALLENGE_ROUTE)
    except ValueError as exc:
        return _fail(
            "public-api-url",
            str(exc),
            {"base_url": base_url},
        )

    response = _fetch_get(url, timeout_sec)
    if not response.get("ok"):
        return _fail(
            "public-api-post-only-route",
            "public API GET probe failed",
            {"url": url, **response},
        )

    status = response["status"]
    headers = response["headers"]
    header_errors = validate_security_headers(headers)
    if status != 405 or header_errors:
        return _fail(
            "public-api-post-only-route",
            "public API route is not deployment-ready",
            {
                "url": url,
                "expected_status": 405,
                "status": status,
                "header_errors": header_errors,
                "headers": headers,
                "elapsed_ms": response["elapsed_ms"],
            },
        )

    return _pass(
        "public-api-post-only-route",
        "GET is rejected on POST-only card activation route with hardened headers",
        {
            "url": url,
            "status": status,
            "headers": _selected_header_evidence(headers),
            "elapsed_ms": response["elapsed_ms"],
        },
    )


def check_health_url(health_url: str, *, timeout_sec: float) -> CheckResult:
    response = _fetch_get(health_url, timeout_sec)
    if not response.get("ok"):
        return _fail(
            "sidecar-health",
            "health probe failed",
            {"url": health_url, **response},
        )

    status = response["status"]
    headers = response["headers"]
    header_errors = validate_security_headers(headers)
    body_prefix = str(response.get("body_prefix", ""))
    body_errors: list[str] = []
    try:
        payload = json.loads(body_prefix)
    except json.JSONDecodeError:
        payload = {}
        body_errors.append("health response is not JSON")

    if payload.get("ok") is not True:
        body_errors.append("health payload ok is not true")
    if payload.get("service") != "dual-machine":
        body_errors.append("health payload service is not dual-machine")

    if status != 200 or header_errors or body_errors:
        return _fail(
            "sidecar-health",
            "health endpoint is not deployment-ready",
            {
                "url": health_url,
                "expected_status": 200,
                "status": status,
                "header_errors": header_errors,
                "body_errors": body_errors,
                "body_prefix": body_prefix,
                "headers": headers,
                "elapsed_ms": response["elapsed_ms"],
            },
        )

    return _pass(
        "sidecar-health",
        "health endpoint reports the isolated dual-machine sidecar",
        {
            "url": health_url,
            "status": status,
            "headers": _selected_header_evidence(headers),
            "elapsed_ms": response["elapsed_ms"],
        },
    )


def _selected_header_evidence(headers: Mapping[str, str]) -> dict[str, str]:
    names = (
        "cache-control",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "cross-origin-resource-policy",
        "permissions-policy",
        "x-trace-id",
    )
    return {
        name: headers.get(name, "")
        for name in names
        if headers.get(name, "")
    }


def run_checks(
    *,
    root: Path = ROOT,
    public_api_base_url: str | None = None,
    health_url: str | None = None,
    timeout_sec: float = 10.0,
    mode: str = "strict",
) -> list[CheckResult]:
    if mode not in READINESS_MODES:
        raise ValueError("mode must be diagnostic, strict, formal or development")
    results = check_source_contracts(root)
    results.extend(check_reverse_resistance_contracts(root))
    if public_api_base_url:
        results.append(check_public_api_endpoint(
            public_api_base_url,
            timeout_sec=timeout_sec,
        ))
    if health_url:
        results.append(check_health_url(health_url, timeout_sec=timeout_sec))
    return results


def _is_reverse_resistance_check(result: CheckResult) -> bool:
    return result.name.startswith(REVERSE_RESISTANCE_CHECK_PREFIX)


def _canonical_mode(mode: str) -> str:
    if mode == DEVELOPMENT_MODE_ALIAS:
        return "diagnostic"
    if mode not in READINESS_MODES:
        raise ValueError("mode must be diagnostic, strict, formal or development")
    return mode


def _json_report(
    results: Sequence[CheckResult],
    *,
    mode: str = "strict",
) -> str:
    canonical_mode = _canonical_mode(mode)
    base_checks_ok = all(
        result.ok for result in results if not _is_reverse_resistance_check(result)
    )
    reverse_resistance_ok = all(
        result.ok for result in results if _is_reverse_resistance_check(result)
    )
    checks_ok = all(result.ok for result in results)
    registry_ok = any(
        result.name == REVERSE_RESISTANCE_REGISTRY_CHECK and result.ok
        for result in results
    )
    bypasses: list[str] = []
    strict_ok = (
        canonical_mode in {"strict", "formal"}
        and checks_ok
        and registry_ok
        and not bypasses
    )
    formal_ok = canonical_mode == "formal" and strict_ok
    top_level_ok = strict_ok if canonical_mode == "strict" else formal_ok
    payload = {
        "schema": READINESS_SCHEMA,
        "requested_mode": mode,
        "mode": canonical_mode,
        "diagnostic_completed": True,
        "diagnostic_ok": True,
        "ok": top_level_ok,
        "checks_ok": checks_ok,
        "base_checks_ok": base_checks_ok,
        "reverse_resistance_ok": reverse_resistance_ok,
        "reverse_resistance_registry_ok": registry_ok,
        "strict_ok": strict_ok,
        "formal_eligible": formal_ok,
        "formal_ok": formal_ok,
        "formal_release_ok": formal_ok,
        "bypasses": bypasses,
        "checks": [
            {
                "name": result.name,
                "ok": result.ok,
                "detail": result.detail,
                "evidence": result.evidence,
            }
            for result in results
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _text_report(
    results: Sequence[CheckResult],
    *,
    mode: str = "strict",
) -> str:
    canonical_mode = _canonical_mode(mode)
    lines = [
        f"VisionForge dual-machine release readiness mode={canonical_mode}:",
    ]
    if canonical_mode == "diagnostic":
        lines.append("DIAGNOSTIC ONLY / NOT FORMAL ELIGIBLE")
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        lines.append(f"- [{status}] {result.name}: {result.detail}")
        if not result.ok and result.evidence:
            lines.append(
                "  evidence="
                + json.dumps(result.evidence, ensure_ascii=False, sort_keys=True)
            )
    reverse_resistance_ok = all(
        result.ok for result in results if _is_reverse_resistance_check(result)
    )
    lines.append(
        "strict_ok="
        + str(
            canonical_mode in {"strict", "formal"}
            and all(result.ok for result in results)
        ).lower()
        + " formal_release_ok="
        + str(canonical_mode == "formal" and all(result.ok for result in results)).lower()
        + " reverse_resistance_ok="
        + str(reverse_resistance_ok).lower()
    )
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify dual-machine card-key, billing, network-hardening and "
            "Host video-boundary release contracts."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=READINESS_MODES,
        default="strict",
        help=(
            "diagnostic reports findings without release eligibility; strict enforces "
            "all checks; formal additionally emits formal eligibility. development is "
            "a compatibility alias for diagnostic"
        ),
    )
    parser.add_argument(
        "--public-api-base-url",
        help=(
            "Optional public deployment base URL, for example "
            "https://www.visionforge.cloud. Only a safe GET probe is sent."
        ),
    )
    parser.add_argument(
        "--health-url",
        help=(
            "Optional sidecar-local health URL, for example "
            "http://127.0.0.1:8010/healthz. Do not expose /healthz publicly."
        ),
    )
    parser.add_argument(
        "--timeout-sec",
        default=10.0,
        type=float,
        help="Per-request network timeout in seconds.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of text.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_stdio()
    args = parse_args(argv if argv is not None else sys.argv[1:])
    results = run_checks(
        public_api_base_url=args.public_api_base_url,
        health_url=args.health_url,
        timeout_sec=args.timeout_sec,
        mode=args.mode,
    )
    print(
        _json_report(results, mode=args.mode)
        if args.json
        else _text_report(results, mode=args.mode)
    )
    if _canonical_mode(args.mode) == "diagnostic":
        return 0
    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
