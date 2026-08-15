from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-runtime-catalog")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.security import create_access_token


class RuntimeCatalogApiTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        self.private_key = Ed25519PrivateKey.generate()
        config.RUNTIME_CATALOG_PUBLIC_KEY = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        config.RUNTIME_CATALOG_PUBLIC_KEY_PATH = ""
        config.SITE_URL = "https://www.visionforge.cloud"
        config.RUNTIME_ARTIFACT_HMAC_SECRET = "runtime-artifact-test-secret-32-bytes"
        config.RUNTIME_ARTIFACT_TTL_SECONDS = 900
        config.RUNTIME_ARTIFACT_ROOT = str(Path(self.tmpdir.name) / "runtime-artifacts")
        self.default_artifact = b"default-runtime-component"
        self.default_digest = hashlib.sha256(self.default_artifact).hexdigest()
        artifact_path = Path(config.RUNTIME_ARTIFACT_ROOT) / f"{self.default_digest}.zip"
        artifact_path.parent.mkdir(parents=True)
        artifact_path.write_bytes(self.default_artifact)
        init_db()
        conn = get_connection()
        try:
            self.admin_id = int(conn.execute(
                "INSERT INTO users (username,email,password_hash,is_admin) VALUES ('admin','admin@test','x',1)"
            ).lastrowid)
            self.user_id = int(conn.execute(
                "INSERT INTO users (username,email,password_hash) VALUES ('user','user@test','x')"
            ).lastrowid)
            conn.execute("INSERT INTO time_balance (user_id,balance_seconds) VALUES (?,0)", (self.user_id,))
            conn.commit()
        finally:
            conn.close()
        self.client = TestClient(app)
        self.admin_headers = {"Authorization": f"Bearer {create_access_token(self.admin_id, True)}"}
        self.user_headers = {
            "Authorization": f"Bearer {create_access_token(self.user_id, False, client_version='v20.0.0')}"
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def _envelope(
        self,
        *,
        channel: str = "stable",
        catalog_version: str = "2026.7.1",
        tamper_signature: bool = False,
        archive_sha256: str | None = None,
        archive_size: int | None = None,
        object_key: str | None = None,
    ) -> dict[str, str]:
        archive_sha256 = archive_sha256 or self.default_digest
        archive_size = len(self.default_artifact) if archive_size is None else archive_size
        artifact_key = object_key or (
            "runtime/cuda12-runtime/12.8.1/" + archive_sha256 + ".zip"
        )
        payload = json.dumps({
            "schema_version": 1,
            "catalog_version": catalog_version,
            "channel": channel,
            "components": [{
                "component_id": "cuda12-runtime",
                "version": "12.8.1",
                "platform": "windows",
                "architecture": "x64",
                "gpu_families": ["all"],
                "dependencies": [],
                "object_key": artifact_key,
                "archive_sha256": archive_sha256,
                "archive_size": archive_size,
                "expanded_size": 45678,
                "files": [{"path": "bin/cudart64_12.dll", "size": 1, "sha256": "b" * 64}],
                "licenses": ["CUDA-EULA"],
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        signature = self.private_key.sign(payload)
        if tamper_signature:
            signature = b"x" * len(signature)
        return {
            "channel": channel,
            "algorithm": "Ed25519",
            "key_id": "runtime-release-2026-01",
            "payload_b64": base64.b64encode(payload).decode(),
            "signature_b64": base64.b64encode(signature).decode(),
        }

    def test_catalog_requires_login_but_not_positive_balance(self):
        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(),
        )
        self.assertEqual(published.status_code, 200, published.text)
        self.assertEqual(self.client.get("/api/client/runtime/catalog").status_code, 401)

        response = self.client.get("/api/client/runtime/catalog", headers=self.user_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["algorithm"], "Ed25519")

    def test_catalog_publish_rejects_unsigned_envelope_fields(self):
        envelope = self._envelope()
        envelope["components"] = []

        response = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("extra_forbidden", response.text)
        self.assertIn("components", response.text)

    def test_catalog_publish_rejects_incomplete_sm120_native_closure(self):
        payload = json.dumps({
            "schema_version": 1,
            "catalog_version": "2026.7.1",
            "channel": "stable",
            "components": [{
                "component_id": "tensorrt10-sm120",
                "version": "10.16.1.11",
                "platform": "windows",
                "architecture": "x64",
                "gpu_families": ["sm120"],
                "dependencies": [],
                "object_key": "runtime/tensorrt10-sm120/10.16.1.11/" + "a" * 64 + ".zip",
                "archive_sha256": "a" * 64,
                "archive_size": 1,
                "expanded_size": 1,
                "files": [{"path": "bin/runtime.bin", "size": 1, "sha256": "b" * 64}],
                "licenses": ["TensorRT-EULA"],
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        envelope = {
            "channel": "stable",
            "algorithm": "Ed25519",
            "key_id": "runtime-release-2026-01",
            "payload_b64": base64.b64encode(payload).decode(),
            "signature_b64": base64.b64encode(self.private_key.sign(payload)).decode(),
        }

        response = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("SM120 TensorRT native closure", response.text)

    def test_catalog_publish_rejects_incomplete_sm80_native_closure(self):
        payload = json.dumps({
            "schema_version": 1,
            "catalog_version": "2026.7.1",
            "channel": "stable",
            "components": [{
                "component_id": "tensorrt10-sm80",
                "version": "10.16.1.11",
                "platform": "windows",
                "architecture": "x64",
                "gpu_families": ["sm80"],
                "dependencies": [],
                "object_key": "runtime/tensorrt10-sm80/10.16.1.11/" + "a" * 64 + ".zip",
                "archive_sha256": "a" * 64,
                "archive_size": 1,
                "expanded_size": 1,
                "files": [{"path": "bin/runtime.bin", "size": 1, "sha256": "b" * 64}],
                "licenses": ["TensorRT-EULA"],
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        envelope = {
            "channel": "stable",
            "algorithm": "Ed25519",
            "key_id": "runtime-release-2026-01",
            "payload_b64": base64.b64encode(payload).decode(),
            "signature_b64": base64.b64encode(self.private_key.sign(payload)).decode(),
        }

        response = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("SM80 TensorRT native closure", response.text)

    def test_catalog_publish_rejects_unapproved_native_target(self):
        payload = json.dumps({
            "schema_version": 1,
            "catalog_version": "2026.7.1",
            "channel": "stable",
            "components": [{
                "component_id": "tensorrt10-sm103",
                "version": "10.16.1.11",
                "platform": "windows",
                "architecture": "x64",
                "gpu_families": ["sm103"],
                "dependencies": [],
                "object_key": "runtime/tensorrt10-sm103/10.16.1.11/" + "a" * 64 + ".zip",
                "archive_sha256": "a" * 64,
                "archive_size": 1,
                "expanded_size": 1,
                "files": [{"path": "bin/nvinfer_builder_resource_sm103_10.dll", "size": 1, "sha256": "b" * 64}],
                "licenses": ["TensorRT-EULA"],
            }],
        }, sort_keys=True, separators=(",", ":")).encode()
        envelope = {
            "channel": "stable",
            "algorithm": "Ed25519",
            "key_id": "runtime-release-2026-01",
            "payload_b64": base64.b64encode(payload).decode(),
            "signature_b64": base64.b64encode(self.private_key.sign(payload)).decode(),
        }

        response = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("not approved", response.text)

    def test_ticket_is_limited_to_catalog_and_uses_same_origin_hmac(self):
        self.client.post("/api/admin/runtime/catalogs", headers=self.admin_headers, json=self._envelope())
        response = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        split = urlsplit(response.json()["url"])
        expires = response.json()["expires_at"]
        query = parse_qs(split.query, strict_parsing=True)
        self.assertEqual(query["tv"], ["2"])
        self.assertEqual(query["uid"], [str(self.user_id)])
        self.assertEqual(query["ver"], ["v20.0.0"])
        self.assertEqual(len(query["catalog"][0]), 64)
        expected = hmac.new(
            config.RUNTIME_ARTIFACT_HMAC_SECRET.encode(),
            "\n".join(
                (
                    "visionforge-runtime-download-ticket-v2",
                    str(self.user_id),
                    "v20.0.0",
                    query["catalog"][0],
                    f"runtime/cuda12-runtime/12.8.1/{self.default_digest}.zip",
                    str(expires),
                )
            ).encode(),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(split.scheme, "https")
        self.assertEqual(split.netloc, "www.visionforge.cloud")
        self.assertEqual(query["sig"], [expected])

        rejected = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "tensorrt10-sm86", "version": "10.0.0"},
        )
        self.assertEqual(rejected.status_code, 404)

    def test_catalog_and_ticket_enforce_jwt_application_version_floor(self):
        self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(),
        )
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO releases "
                "(version, channel, min_supported_version, published, payload_b64) "
                "VALUES ('v20.0.0', 'stable', 'v20.0.0', 1, 'signed')"
            )
            conn.commit()
        finally:
            conn.close()
        old_headers = {
            "Authorization": f"Bearer {create_access_token(self.user_id, False, client_version='v19.9.9')}"
        }

        catalog = self.client.get(
            "/api/client/runtime/catalog",
            headers=old_headers,
        )
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=old_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )

        self.assertEqual(catalog.status_code, 426, catalog.text)
        self.assertEqual(ticket.status_code, 426, ticket.text)
        self.assertEqual(catalog.json()["detail"]["error"], "client_update_required")

    def test_ticket_is_revoked_when_floor_rises_after_issuance(self):
        self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(),
        )
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        self.assertEqual(ticket.status_code, 200, ticket.text)
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO releases "
                "(version, channel, min_supported_version, published, payload_b64) "
                "VALUES ('v21.0.0', 'stable', 'v21.0.0', 1, 'signed')"
            )
            conn.commit()
        finally:
            conn.close()

        response = self.client.get(ticket.json()["url"])

        self.assertEqual(response.status_code, 426, response.text)

    def test_ticket_hmac_binds_application_version(self):
        self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(),
        )
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        split = urlsplit(ticket.json()["url"])
        query = parse_qs(split.query, strict_parsing=True)
        query["ver"] = ["v99.0.0"]

        response = self.client.get(
            split.path + "?" + urlencode(query, doseq=True)
        )

        self.assertEqual(response.status_code, 403, response.text)

    def test_same_origin_ticket_authorizes_private_nginx_artifact(self):
        content = b"0123456789-runtime-component"
        digest = hashlib.sha256(content).hexdigest()
        object_key = f"runtime/cuda12-runtime/12.8.1/{digest}.zip"
        artifact = Path(config.RUNTIME_ARTIFACT_ROOT) / f"{digest}.zip"
        artifact.write_bytes(content)

        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(
                archive_sha256=digest,
                archive_size=len(content),
                object_key=object_key,
            ),
        )
        self.assertEqual(published.status_code, 200, published.text)
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        self.assertEqual(ticket.status_code, 200, ticket.text)

        split = urlsplit(ticket.json()["url"])
        self.assertEqual(split.scheme, "https")
        self.assertEqual(split.netloc, "www.visionforge.cloud")
        signed_path = split.path + "?" + split.query
        downloaded = self.client.get(signed_path)
        self.assertEqual(downloaded.status_code, 200, downloaded.text)
        self.assertEqual(downloaded.content, b"")
        self.assertEqual(
            downloaded.headers["x-accel-redirect"],
            f"/_runtime_artifacts/{digest}.zip",
        )

        query = parse_qs(split.query, strict_parsing=True)
        query["sig"] = ["0" * 64]
        tampered = self.client.get(split.path + "?" + urlencode(query, doseq=True))
        self.assertEqual(tampered.status_code, 403, tampered.text)

    def test_same_origin_publish_rejects_missing_artifact(self):
        missing_digest = "a" * 64

        response = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(
                archive_sha256=missing_digest,
                archive_size=12345,
            ),
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("runtime artifact does not exist", response.text)

    def test_ticket_request_rejects_unknown_fields(self):
        response = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={
                "component_id": "cuda12-runtime",
                "version": "12.8.1",
                "object_key": "runtime/other.zip",
            },
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("extra_forbidden", response.text)
        self.assertIn("object_key", response.text)

    def test_install_events_are_idempotent_and_account_linked(self):
        body = {
            "attempt_id": "trace-1",
            "events": [{
                "event_id": "event-1",
                "event_type": "activation_ready",
                "status": "ok",
                "gpu_model": "RTX 3080",
                "failure_stage": "catalog_fetch",
                "http_status": 503,
                "duration_ms": 123,
                "os_name": "Windows",
                "architecture": "AMD64",
                "cpu_model": "Intel Core i7-14700K",
                "cpu_cores_physical": 20,
                "cpu_cores_logical": 28,
                "compute_capability": "12.0",
                "final_provider": "TensorrtExecutionProvider",
            }],
        }
        first = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)
        second = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)
        self.assertEqual(first.json()["accepted"], 1)
        self.assertEqual(second.json()["accepted"], 0)
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM runtime_install_events WHERE event_id='event-1'").fetchone()
            self.assertEqual(int(row["user_id"]), self.user_id)
            self.assertEqual(row["attempt_id"], "trace-1")
            self.assertEqual(row["failure_stage"], "catalog_fetch")
            self.assertEqual(int(row["http_status"]), 503)
            self.assertEqual(row["cpu_model"], "Intel Core i7-14700K")
            self.assertEqual(int(row["cpu_cores_physical"]), 20)
            self.assertEqual(int(row["cpu_cores_logical"]), 28)
            self.assertEqual(row["compute_capability"], "12.0")
            self.assertEqual(row["final_provider"], "TensorrtExecutionProvider")
        finally:
            conn.close()

    def test_install_events_reject_unknown_final_provider(self):
        body = {
            "attempt_id": "trace-provider-contract",
            "events": [{
                "event_id": "event-provider-contract",
                "event_type": "activation_ready",
                "status": "ok",
                "final_provider": "UnknownExecutionProvider",
            }],
        }

        response = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)

        self.assertEqual(response.status_code, 422, response.text)

    def test_install_events_normalize_bad_numeric_fields(self):
        body = {
            "attempt_id": "trace-2",
            "events": [{
                "event_id": "event-bad-numbers",
                "event_type": "download_finished",
                "status": "ok",
                "duration_ms": "not-a-number",
                "bytes_count": {"bad": "shape"},
            }, {
                "event_id": "event-huge-numbers",
                "event_type": "download_finished",
                "status": "ok",
                "duration_ms": 10**100,
                "bytes_count": -1,
            }],
        }

        response = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["accepted"], 2)
        conn = get_connection()
        try:
            row = conn.execute(
                "SELECT duration_ms, bytes_count FROM runtime_install_events WHERE event_id='event-bad-numbers'"
            ).fetchone()
            huge_row = conn.execute(
                "SELECT duration_ms, bytes_count FROM runtime_install_events WHERE event_id='event-huge-numbers'"
            ).fetchone()
            self.assertEqual(int(row["duration_ms"]), 0)
            self.assertEqual(int(row["bytes_count"]), 0)
            self.assertEqual(int(huge_row["duration_ms"]), 2**63 - 1)
            self.assertEqual(int(huge_row["bytes_count"]), 0)
        finally:
            conn.close()

    def test_install_event_retention_preserves_failure_dimensions(self):
        old_event = {
            "attempt_id": "trace-old",
            "events": [{
                "event_id": "event-old-failure",
                "event_type": "provision_failed",
                "status": "failed",
                "error_code": "server_rejected",
                "failure_stage": "ticket_fetch",
                "http_status": 503,
                "app_version": "v17.8.81",
                "gpu_model": "RTX 5060",
            }],
        }
        response = self.client.post(
            "/api/client/runtime/events",
            headers=self.user_headers,
            json=old_event,
        )
        self.assertEqual(response.status_code, 200, response.text)
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE runtime_install_events SET created_at = datetime('now','-31 days') "
                "WHERE event_id = 'event-old-failure'"
            )
            conn.commit()
        finally:
            conn.close()

        trigger = self.client.post(
            "/api/client/runtime/events",
            headers=self.user_headers,
            json={
                "attempt_id": "trace-current",
                "events": [{
                    "event_id": "event-current",
                    "event_type": "activation_ready",
                    "status": "ok",
                }],
            },
        )
        self.assertEqual(trigger.status_code, 200, trigger.text)
        conn = get_connection()
        try:
            aggregate = conn.execute(
                "SELECT * FROM runtime_install_events "
                "WHERE anonymized = 1 AND event_type = 'aggregate:provision_failed'"
            ).fetchone()
            raw = conn.execute(
                "SELECT 1 FROM runtime_install_events WHERE event_id = 'event-old-failure'"
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(aggregate)
        self.assertEqual(aggregate["failure_stage"], "ticket_fetch")
        self.assertEqual(int(aggregate["http_status"]), 503)
        self.assertEqual(int(aggregate["bytes_count"]), 1)
        self.assertIsNone(raw)

    def test_install_events_reject_unknown_event_fields(self):
        body = {
            "attempt_id": "trace-3",
            "events": [{
                "event_id": "event-extra-field",
                "event_type": "activation_ready",
                "status": "ok",
                "unexpected": "ignored-before",
            }],
        }

        response = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("extra_forbidden", response.text)
        self.assertIn("unexpected", response.text)

    def test_install_event_batch_rejects_unknown_top_level_fields(self):
        body = {
            "attempt_id": "trace-4",
            "events": [{
                "event_id": "event-valid",
                "event_type": "activation_ready",
            }],
            "user_id": self.admin_id,
        }

        response = self.client.post("/api/client/runtime/events", headers=self.user_headers, json=body)

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("extra_forbidden", response.text)
        self.assertIn("user_id", response.text)

    def test_admin_rejects_forged_catalog_and_can_stop_component(self):
        forged = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(tamper_signature=True),
        )
        self.assertEqual(forged.status_code, 422)

        self.client.post("/api/admin/runtime/catalogs", headers=self.admin_headers, json=self._envelope())
        disabled = self.client.post(
            "/api/admin/runtime/components/cuda12-runtime/12.8.1/disable",
            headers=self.admin_headers,
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        self.assertEqual(ticket.status_code, 404)

    def test_allowlist_uses_pilot_and_admin_can_rollback_signed_catalog(self):
        stable_one = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(catalog_version="2026.7.1"),
        ).json()["release_id"]
        self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(catalog_version="2026.7.2"),
        )
        self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(channel="pilot", catalog_version="2026.7.9"),
        )
        allowlisted = self.client.put(
            f"/api/admin/runtime/allowlist/{self.user_id}",
            headers=self.admin_headers,
            json={"channel": "pilot", "note": "real machine"},
        )
        self.assertEqual(allowlisted.status_code, 200, allowlisted.text)
        pilot = self.client.get("/api/client/runtime/catalog", headers=self.user_headers).json()
        pilot_payload = json.loads(base64.b64decode(pilot["payload_b64"]))
        self.assertEqual(pilot_payload["catalog_version"], "2026.7.9")

        self.client.delete(f"/api/admin/runtime/allowlist/{self.user_id}", headers=self.admin_headers)
        rolled_back = self.client.post(
            f"/api/admin/runtime/catalogs/{stable_one}/activate",
            headers=self.admin_headers,
            json={"reason": "emergency rollback"},
        )
        self.assertEqual(rolled_back.status_code, 200, rolled_back.text)
        stable = self.client.get("/api/client/runtime/catalog", headers=self.user_headers).json()
        stable_payload = json.loads(base64.b64decode(stable["payload_b64"]))
        self.assertEqual(stable_payload["catalog_version"], "2026.7.1")

    def test_pilot_allowlist_falls_back_to_active_stable_catalog(self):
        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(catalog_version="2026.7.1"),
        )
        self.assertEqual(published.status_code, 200, published.text)
        allowlisted = self.client.put(
            f"/api/admin/runtime/allowlist/{self.user_id}",
            headers=self.admin_headers,
            json={"channel": "pilot", "note": "pilot not published yet"},
        )
        self.assertEqual(allowlisted.status_code, 200, allowlisted.text)

        response = self.client.get("/api/client/runtime/catalog", headers=self.user_headers)

        self.assertEqual(response.status_code, 200, response.text)
        payload = json.loads(base64.b64decode(response.json()["payload_b64"]))
        self.assertEqual(payload["channel"], "stable")
        self.assertEqual(payload["catalog_version"], "2026.7.1")

    def test_catalog_version_is_immutable_and_disabled_component_stays_disabled(self):
        envelope = self._envelope(catalog_version="2026.7.1")
        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )
        self.assertEqual(published.status_code, 200, published.text)

        disabled = self.client.post(
            "/api/admin/runtime/components/cuda12-runtime/12.8.1/disable",
            headers=self.admin_headers,
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        republished = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=envelope,
        )

        self.assertEqual(republished.status_code, 422, republished.text)
        self.assertIn("runtime component is disabled", republished.text)
        ticket = self.client.post(
            "/api/client/runtime/download-ticket",
            headers=self.user_headers,
            json={"component_id": "cuda12-runtime", "version": "12.8.1"},
        )
        self.assertEqual(ticket.status_code, 404, ticket.text)

    def test_catalog_activation_rechecks_local_artifact(self):
        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(catalog_version="2026.7.1"),
        )
        self.assertEqual(published.status_code, 200, published.text)
        Path(config.RUNTIME_ARTIFACT_ROOT, f"{self.default_digest}.zip").unlink()

        activated = self.client.post(
            f"/api/admin/runtime/catalogs/{published.json()['release_id']}/activate",
            headers=self.admin_headers,
            json={"reason": "verify artifact before rollback"},
        )

        self.assertEqual(activated.status_code, 422, activated.text)
        self.assertIn("runtime artifact does not exist", activated.text)

    def test_allowlist_rejects_deleted_user_and_missing_removal_has_no_audit(self):
        conn = get_connection()
        try:
            conn.execute("UPDATE users SET deleted_at = datetime('now'), status = 'disabled' WHERE id = ?", (self.user_id,))
            conn.commit()
        finally:
            conn.close()

        rejected = self.client.put(
            f"/api/admin/runtime/allowlist/{self.user_id}",
            headers=self.admin_headers,
            json={"channel": "pilot", "note": "deleted user"},
        )
        removed = self.client.delete(
            f"/api/admin/runtime/allowlist/{self.user_id}", headers=self.admin_headers
        )
        self.assertEqual(rejected.status_code, 404, rejected.text)
        self.assertEqual(removed.status_code, 200, removed.text)

        conn = get_connection()
        try:
            audit_count = conn.execute(
                "SELECT COUNT(*) FROM admin_audit WHERE action = 'runtime.allowlist.remove' AND target_id = ?",
                (str(self.user_id),),
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(audit_count, 0)

    def test_admin_runtime_requests_reject_unknown_fields(self):
        allowlist = self.client.put(
            f"/api/admin/runtime/allowlist/{self.user_id}",
            headers=self.admin_headers,
            json={"channel": "pilot", "note": "real machine", "enabled": True},
        )
        self.assertEqual(allowlist.status_code, 422, allowlist.text)
        self.assertIn("extra_forbidden", allowlist.text)
        self.assertIn("enabled", allowlist.text)

        published = self.client.post(
            "/api/admin/runtime/catalogs",
            headers=self.admin_headers,
            json=self._envelope(),
        )
        self.assertEqual(published.status_code, 200, published.text)
        activate = self.client.post(
            f"/api/admin/runtime/catalogs/{published.json()['release_id']}/activate",
            headers=self.admin_headers,
            json={"reason": "valid reason", "force": True},
        )
        self.assertEqual(activate.status_code, 422, activate.text)
        self.assertIn("extra_forbidden", activate.text)
        self.assertIn("force", activate.text)

    def test_admin_runtime_path_parameters_are_bounded(self):
        bad_component = self.client.post(
            "/api/admin/runtime/components/CUDA/runtime/disable",
            headers=self.admin_headers,
        )
        self.assertEqual(bad_component.status_code, 422, bad_component.text)

        bad_allowlist = self.client.put(
            "/api/admin/runtime/allowlist/0",
            headers=self.admin_headers,
            json={"channel": "pilot", "note": "invalid user id"},
        )
        self.assertEqual(bad_allowlist.status_code, 422, bad_allowlist.text)

        bad_channel = self.client.put(
            f"/api/admin/runtime/allowlist/{self.user_id}",
            headers=self.admin_headers,
            json={"channel": "canary", "note": "unknown rollout channel"},
        )
        self.assertEqual(bad_channel.status_code, 422, bad_channel.text)
        self.assertIn("channel", bad_channel.text)

        bad_release = self.client.post(
            "/api/admin/runtime/catalogs/0/activate",
            headers=self.admin_headers,
            json={"reason": "invalid release id"},
        )
        self.assertEqual(bad_release.status_code, 422, bad_release.text)


if __name__ == "__main__":
    unittest.main()
