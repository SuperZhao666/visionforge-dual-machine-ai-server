import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-release-update-v2")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app
from app.main import _is_immutable_release_response
from app.security import CSRF_COOKIE_NAME, create_access_token, hash_password
from app.services.release_service import ReleaseValidationError, public_manifest


class ReleaseUpdateV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.release_root = self.root / "releases"
        self.release_root.mkdir()
        self.previous_database_path = config.DATABASE_PATH
        self.previous_site_url = config.SITE_URL
        self.previous_public_key = config.RUNTIME_CATALOG_PUBLIC_KEY
        self.previous_public_key_path = config.RUNTIME_CATALOG_PUBLIC_KEY_PATH
        self.previous_cookie_secure = config.COOKIE_SECURE
        config.DATABASE_PATH = str(self.root / "vf.db")
        config.SITE_URL = "https://visionforge.test"
        config.COOKIE_SECURE = False
        self.private_key = Ed25519PrivateKey.generate()
        config.RUNTIME_CATALOG_PUBLIC_KEY = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        config.RUNTIME_CATALOG_PUBLIC_KEY_PATH = ""
        self.release_root_patch = mock.patch(
            "app.services.release_service.RELEASE_STATIC_ROOT", self.release_root
        )
        self.release_root_patch.start()
        init_db()
        conn = get_connection()
        try:
            self.admin_id = int(
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                    ("release-admin", "release-admin@example.test", hash_password("correct-password")),
                ).lastrowid
            )
            conn.commit()
        finally:
            conn.close()
        self.client = TestClient(app, base_url="https://visionforge.test")
        self.admin_headers = {
            "Authorization": f"Bearer {create_access_token(self.admin_id, True)}"
        }

    def tearDown(self):
        self.release_root_patch.stop()
        config.DATABASE_PATH = self.previous_database_path
        config.SITE_URL = self.previous_site_url
        config.RUNTIME_CATALOG_PUBLIC_KEY = self.previous_public_key
        config.RUNTIME_CATALOG_PUBLIC_KEY_PATH = self.previous_public_key_path
        config.COOKIE_SECURE = self.previous_cookie_secure
        self.tmpdir.cleanup()

    def _write_artifact(self, name: str, content: bytes) -> tuple[str, str, int]:
        path = self.release_root / name
        path.write_bytes(content)
        return f"/static/releases/{name}", hashlib.sha256(content).hexdigest(), len(content)

    def _payload(self, **changes):
        target_content = b"target-v2"
        target_hash = hashlib.sha256(target_content).hexdigest()
        target_url, target_hash, target_size = self._write_artifact(
            f"{target_hash}.exe", target_content
        )
        delta_content = b"delta-v1"
        delta_hash = hashlib.sha256(delta_content).hexdigest()
        delta_url, delta_hash, delta_size = self._write_artifact(
            f"{delta_hash}.vfdiff", delta_content
        )
        payload = {
            "schema_version": 2,
            "channel": "stable",
            "version": "v20.0.0",
            "min_supported_version": "v19.0.0",
            "mandatory": False,
            "published_at": "2025-07-15T12:00:00Z",
            "target": {
                "url": target_url,
                "sha256": target_hash,
                "size": target_size,
                "kind": "onefile_exe",
            },
            "deltas": [
                {
                    "base_sha256": "b" * 64,
                    "url": delta_url,
                    "sha256": delta_hash,
                    "size": delta_size,
                    "algorithm": "visionforge-exe-delta-v1",
                }
            ],
            "notes": "signed update",
        }
        payload.update(changes)
        return payload

    def _envelope(self, payload: dict, *, signature: bytes | None = None):
        payload_bytes = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return {
            "algorithm": "Ed25519",
            "key_id": "release-test-key",
            "payload_b64": base64.b64encode(payload_bytes).decode(),
            "signature_b64": base64.b64encode(
                signature if signature is not None else self.private_key.sign(payload_bytes)
            ).decode(),
        }

    def _login_html_admin(self):
        self.client.get("/login")
        token = self.client.cookies.get(CSRF_COOKIE_NAME)
        response = self.client.post(
            "/auth/login",
            data={
                "username": "release-admin",
                "password": "correct-password",
                "csrf_token": token,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        return token

    def test_legacy_json_publish_honors_optional_and_min_supported_version(self):
        legacy_content = b"legacy-content-addressed-exe"
        legacy_hash = hashlib.sha256(legacy_content).hexdigest()
        legacy_url, legacy_hash, _ = self._write_artifact(
            f"{legacy_hash}.exe", legacy_content
        )
        response = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v18.0.0",
                "channel": "stable",
                "url": legacy_url,
                "sha256": legacy_hash,
                "min_supported_version": "v17.0.0",
                "mandatory": False,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["deprecated_unsigned_release"])

        manifest = self.client.get("/update/stable.json?schema=2")
        self.assertEqual(manifest.status_code, 200, manifest.text)
        self.assertFalse(manifest.json()["mandatory"])
        self.assertEqual(manifest.json()["min_supported_version"], "v17.0.0")
        self.assertEqual(manifest.json()["url"], f"https://visionforge.test{legacy_url}")
        self.assertEqual(
            manifest.json()["download_url"], f"https://visionforge.test{legacy_url}"
        )
        self.assertEqual(manifest.headers["cache-control"], "no-store")
        for signed_field in (
            "schema_version",
            "target",
            "deltas",
            "algorithm",
            "key_id",
            "payload_b64",
            "signature_b64",
        ):
            self.assertNotIn(signed_field, manifest.json())

    def test_legacy_publish_requires_content_addressed_existing_artifact(self):
        content = b"legacy-mutable-name"
        digest = hashlib.sha256(content).hexdigest()
        (self.release_root / "legacy.exe").write_bytes(content)
        mutable = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v18.0.1",
                "channel": "stable",
                "url": "/static/releases/legacy.exe",
                "sha256": digest,
            },
        )
        self.assertEqual(mutable.status_code, 422, mutable.text)
        self.assertIn("filename must be", mutable.text)

        missing = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v18.0.2",
                "channel": "stable",
                "url": f"/static/releases/{digest}.exe",
                "sha256": digest,
            },
        )
        self.assertEqual(missing.status_code, 422, missing.text)
        self.assertIn("does not exist", missing.text)

    def test_legacy_absolute_artifact_url_rejects_query_and_fragment(self):
        content = b"legacy-absolute-url"
        digest = hashlib.sha256(content).hexdigest()
        self._write_artifact(f"{digest}.exe", content)
        base_url = f"https://visionforge.test/static/releases/{digest}.exe"

        for index, suffix in enumerate(
            ("?download=1", "#latest", "?", "#"),
            start=1,
        ):
            with self.subTest(suffix=suffix):
                response = self.client.post(
                    "/api/admin/releases",
                    headers=self.admin_headers,
                    json={
                        "version": f"v18.0.{index}",
                        "channel": "stable",
                        "url": f"{base_url}{suffix}",
                        "sha256": digest,
                    },
                )
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIn("query strings or fragments", response.text)

    def test_legacy_public_url_generation_rejects_invalid_site_url(self):
        content = b"legacy-site-url"
        digest = hashlib.sha256(content).hexdigest()
        url, digest, _ = self._write_artifact(f"{digest}.exe", content)
        published = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v18.0.3",
                "channel": "stable",
                "url": url,
                "sha256": digest,
            },
        )
        self.assertEqual(published.status_code, 200, published.text)
        release = published.json()["release"]

        try:
            for site_url in (
                "",
                "http://visionforge.test",
                "https://visionforge.test/releases",
                "https://visionforge.test?source=test",
                "https://visionforge.test#release",
            ):
                with self.subTest(site_url=site_url):
                    config.SITE_URL = site_url
                    with self.assertRaisesRegex(
                        ReleaseValidationError,
                        "SITE_URL must be an origin-only HTTPS URL",
                    ):
                        public_manifest(release)
        finally:
            config.SITE_URL = "https://visionforge.test"

    def test_legacy_api_publish_offloads_file_verification(self):
        content = b"legacy-api-offload"
        digest = hashlib.sha256(content).hexdigest()
        url, digest, _ = self._write_artifact(f"{digest}.exe", content)
        observed = []

        async def run_inline(func, *args, **kwargs):
            observed.append((func.__name__, dict(kwargs)))
            return func(*args, **kwargs)

        with mock.patch(
            "app.routes.admin_api.run_in_threadpool",
            side_effect=run_inline,
        ) as offload:
            response = self.client.post(
                "/api/admin/releases",
                headers=self.admin_headers,
                json={
                    "version": "v18.0.4",
                    "channel": "stable",
                    "url": url,
                    "sha256": digest,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(offload.await_count, 1)
        self.assertEqual(observed[0][0], "save_legacy")

    def test_legacy_html_create_and_update_offload_file_verification(self):
        content = b"legacy-html-offload"
        digest = hashlib.sha256(content).hexdigest()
        url, digest, _ = self._write_artifact(f"{digest}.exe", content)
        csrf_token = self._login_html_admin()
        observed = []

        async def run_inline(func, *args, **kwargs):
            observed.append((func.__name__, dict(kwargs)))
            return func(*args, **kwargs)

        with mock.patch(
            "app.routes.admin.run_in_threadpool",
            side_effect=run_inline,
        ) as offload:
            created = self.client.post(
                "/admin/releases/create",
                data={
                    "csrf_token": csrf_token,
                    "version": "v18.0.5",
                    "channel": "stable",
                    "url": url,
                    "sha256": digest,
                    "published": "1",
                },
                follow_redirects=False,
            )
            self.assertEqual(created.status_code, 303, created.text)
            conn = get_connection()
            try:
                release_id = int(
                    conn.execute(
                        "SELECT id FROM releases WHERE version = ? AND channel = ?",
                        ("v18.0.5", "stable"),
                    ).fetchone()["id"]
                )
            finally:
                conn.close()
            updated = self.client.post(
                "/admin/releases/update",
                data={
                    "csrf_token": csrf_token,
                    "release_id": release_id,
                    "version": "v18.0.5",
                    "channel": "stable",
                    "url": url,
                    "sha256": digest,
                    "published": "1",
                },
                follow_redirects=False,
            )

        self.assertEqual(updated.status_code, 303, updated.text)
        self.assertEqual(offload.await_count, 2)
        self.assertEqual([item[0] for item in observed], ["save_legacy", "save_legacy"])
        self.assertNotIn("release_id", observed[0][1])
        self.assertEqual(observed[1][1]["release_id"], release_id)

    def test_html_publish_cannot_bypass_url_or_hash_validation(self):
        csrf_token = self._login_html_admin()
        response = self.client.post(
            "/admin/releases/create",
            data={
                "csrf_token": csrf_token,
                "version": "v18.1.0",
                "channel": "stable",
                "url": "https://third-party.example/release.exe",
                "sha256": "not-a-sha256",
                "published": "1",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 422, response.text)
        conn = get_connection()
        try:
            count = conn.execute("SELECT COUNT(*) FROM releases").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)
        fallback = self.client.get("/api/client/version").json()
        self.assertEqual(
            fallback["download_url"],
            "https://visionforge.test/static/releases/",
        )
        self.assertEqual(fallback["release_id"], "visionforge-dual-machine-1.0.8")
        self.assertEqual(fallback["release_version"], "1.0.8")

    def test_signed_v2_publish_returns_envelope_and_creates_integrity_allowlist(self):
        payload = self._payload()
        envelope = self._envelope(payload)
        response = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=envelope
        )
        self.assertEqual(response.status_code, 200, response.text)

        manifest = self.client.get("/update/stable.json?schema=2")
        self.assertEqual(manifest.status_code, 200, manifest.text)
        data = manifest.json()
        self.assertEqual(data["algorithm"], "Ed25519")
        self.assertEqual(data["key_id"], envelope["key_id"])
        self.assertEqual(data["payload_b64"], envelope["payload_b64"])
        self.assertEqual(data["signature_b64"], envelope["signature_b64"])
        self.assertEqual(data["target"]["kind"], "onefile_exe")
        self.assertTrue(data["url"].startswith("https://visionforge.test/static/releases/"))
        self.assertEqual(data["download_url"], data["url"])
        self.assertEqual(data["target"]["url"], payload["target"]["url"])
        self.assertEqual(data["deltas"][0]["algorithm"], "visionforge-exe-delta-v1")
        self.assertFalse(data["mandatory"])
        self.assertEqual(data["min_supported_version"], "v19.0.0")
        self.assertEqual(data["published_at"], "2025-07-15T12:00:00Z")

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT file_hashes_json FROM client_integrity_allowlist WHERE client_version = ?",
                ("v20.0.0",),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 1)
        item = json.loads(rows[0]["file_hashes_json"])[0]
        self.assertEqual(item["path"], "@executable")
        self.assertEqual(item["role"], "executable")
        self.assertEqual(item["sha256"], data["target"]["sha256"])

    def test_signed_v2_publish_rejects_unsigned_envelope_fields(self):
        payload = self._payload()
        envelope = self._envelope(payload)
        envelope["target"] = {
            "kind": "onefile_exe",
            "url": "https://attacker.example/payload.exe",
            "sha256": "b" * 64,
            "size": 123,
        }
        response = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=envelope
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("extra_forbidden", response.text)
        self.assertIn("target", response.text)

    def test_signed_v2_serves_separate_legacy_installer_bridge(self):
        payload = self._payload(mandatory=True)
        bridge_content = b"legacy-installer-bridge"
        bridge_hash = hashlib.sha256(bridge_content).hexdigest()
        bridge_url, bridge_hash, _ = self._write_artifact(
            f"{bridge_hash}.exe",
            bridge_content,
        )
        envelope = self._envelope(payload)
        envelope.update(
            {
                "legacy_bridge_url": bridge_url,
                "legacy_bridge_sha256": bridge_hash,
            }
        )

        response = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=envelope,
        )
        self.assertEqual(response.status_code, 200, response.text)

        legacy = self.client.get("/update/stable.json")
        self.assertEqual(legacy.status_code, 200, legacy.text)
        legacy_data = legacy.json()
        self.assertTrue(legacy_data["mandatory"])
        self.assertEqual(legacy_data["artifact_kind"], "installer")
        self.assertEqual(legacy_data["url"], "")
        self.assertEqual(
            legacy_data["installer_url"],
            f"https://visionforge.test{bridge_url}",
        )
        self.assertEqual(legacy_data["installer_sha256"], bridge_hash)
        self.assertNotIn("payload_b64", legacy_data)
        self.assertNotIn("signature_b64", legacy_data)

        signed = self.client.get("/update/stable.json?schema=2")
        self.assertEqual(signed.status_code, 200, signed.text)
        signed_data = signed.json()
        self.assertEqual(signed_data["payload_b64"], envelope["payload_b64"])
        self.assertEqual(signed_data["signature_b64"], envelope["signature_b64"])
        self.assertEqual(signed_data["target"], payload["target"])

    def test_signed_v2_rejects_unverified_legacy_bridge(self):
        payload = self._payload()
        bridge_hash = "c" * 64
        response = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json={
                **self._envelope(payload),
                "legacy_bridge_url": f"/static/releases/{bridge_hash}.exe",
                "legacy_bridge_sha256": bridge_hash,
            },
        )

        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("does not exist", response.text)

    def test_signed_v2_publish_offloads_file_verification(self):
        envelope = self._envelope(self._payload(version="v20.0.9"))
        observed = {}

        async def run_inline(func, *args, **kwargs):
            observed["function"] = func
            return func(*args, **kwargs)

        with mock.patch(
            "app.routes.admin_api.run_in_threadpool",
            side_effect=run_inline,
        ) as offload:
            response = self.client.post(
                "/api/admin/releases/v2",
                headers=self.admin_headers,
                json=envelope,
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(offload.await_count, 1)
        self.assertEqual(observed["function"].__name__, "publish_signed")

    def test_legacy_editor_cannot_strip_signed_release_or_reactivate_old_envelope(self):
        payload = self._payload()
        envelope = self._envelope(payload)
        published = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=envelope
        )
        self.assertEqual(published.status_code, 200, published.text)
        release_id = int(published.json()["release"]["id"])
        idempotent = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=envelope
        )
        self.assertEqual(idempotent.status_code, 200, idempotent.text)

        changed_envelope = self._envelope(self._payload(notes="changed signed payload"))
        changed = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=changed_envelope
        )
        self.assertEqual(changed.status_code, 409, changed.text)
        self.assertIn("immutable", changed.text)

        stale_envelope = self._envelope(
            self._payload(
                version="v20.0.1",
                published_at="2025-07-15T11:59:59Z",
            )
        )
        stale = self.client.post(
            "/api/admin/releases/v2", headers=self.admin_headers, json=stale_envelope
        )
        self.assertEqual(stale.status_code, 409, stale.text)
        self.assertIn("published_at", stale.text)

        legacy_api = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v20.0.0",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
            },
        )
        self.assertEqual(legacy_api.status_code, 409, legacy_api.text)

        rollback = self.client.post(
            "/api/admin/releases/v20.0.0/rollback",
            headers=self.admin_headers,
            json={"channel": "stable"},
        )
        self.assertEqual(rollback.status_code, 409, rollback.text)

        csrf_token = self._login_html_admin()
        legacy_html = self.client.post(
            "/admin/releases/update",
            data={
                "csrf_token": csrf_token,
                "release_id": release_id,
                "version": "v20.0.0",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
                "published": "1",
            },
            follow_redirects=False,
        )
        self.assertEqual(legacy_html.status_code, 409, legacy_html.text)

        delete_signed = self.client.post(
            "/admin/releases/delete",
            data={"csrf_token": csrf_token, "release_id": release_id},
            follow_redirects=False,
        )
        self.assertEqual(delete_signed.status_code, 409, delete_signed.text)

        conn = get_connection()
        try:
            stored = conn.execute(
                "SELECT algorithm, key_id, payload_b64, signature_b64 FROM releases WHERE id = ?",
                (release_id,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(stored["algorithm"], "Ed25519")
        self.assertEqual(stored["payload_b64"], envelope["payload_b64"])
        self.assertEqual(stored["signature_b64"], envelope["signature_b64"])

    def test_signed_channel_rejects_all_legacy_writes_and_rollback(self):
        payload = self._payload()
        legacy = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v19.0.0",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
            },
        )
        self.assertEqual(legacy.status_code, 200, legacy.text)
        legacy_id = int(legacy.json()["release"]["id"])
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE releases SET created_at = ? WHERE id = ?",
                ("2025-07-15 11:59:00", legacy_id),
            )
            conn.commit()
        finally:
            conn.close()

        signed_envelope = self._envelope(payload)
        signed = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=signed_envelope,
        )
        self.assertEqual(signed.status_code, 200, signed.text)

        legacy_publish = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v21.0.0",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
            },
        )
        self.assertEqual(legacy_publish.status_code, 409, legacy_publish.text)
        self.assertIn("signed v2", legacy_publish.text)

        legacy_rollback = self.client.post(
            "/api/admin/releases/v19.0.0/rollback",
            headers=self.admin_headers,
            json={"channel": "stable"},
        )
        self.assertEqual(legacy_rollback.status_code, 409, legacy_rollback.text)
        self.assertIn("signed v2", legacy_rollback.text)

        csrf_token = self._login_html_admin()
        legacy_create = self.client.post(
            "/admin/releases/create",
            data={
                "csrf_token": csrf_token,
                "version": "v21.0.1",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
                "published": "0",
            },
            follow_redirects=False,
        )
        self.assertEqual(legacy_create.status_code, 409, legacy_create.text)

        legacy_update = self.client.post(
            "/admin/releases/update",
            data={
                "csrf_token": csrf_token,
                "release_id": legacy_id,
                "version": "v19.0.0",
                "channel": "stable",
                "url": payload["target"]["url"],
                "sha256": payload["target"]["sha256"],
                "published": "0",
            },
            follow_redirects=False,
        )
        self.assertEqual(legacy_update.status_code, 409, legacy_update.text)

        manifest = self.client.get("/update/stable.json?schema=2").json()
        self.assertEqual(manifest["version"], "v20.0.0")
        self.assertEqual(manifest["payload_b64"], signed_envelope["payload_b64"])
        self.assertEqual(manifest["signature_b64"], signed_envelope["signature_b64"])

    def test_signed_v2_rejects_impossible_version_floor_and_client_oversize(self):
        impossible = self._payload(
            version="v20.0.0",
            min_supported_version="v21.0.0",
        )
        response = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(impossible),
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("min_supported_version", response.text)

        oversize = self._payload(version="v20.0.1")
        oversize["target"]["size"] = 512 * 1024 * 1024 + 1
        response = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(oversize),
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertIn("512 MiB", response.text)

    def test_signed_v2_requires_strictly_increasing_numeric_versions(self):
        first = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(self._payload()),
        )
        self.assertEqual(first.status_code, 200, first.text)

        downgrade_payload = self._payload(
            version="v1.0.0",
            min_supported_version="",
            published_at="2025-07-15T12:00:01Z",
        )
        downgrade = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(downgrade_payload),
        )
        self.assertEqual(downgrade.status_code, 409, downgrade.text)
        self.assertIn("version must be newer", downgrade.text)

        non_numeric_payload = self._payload(
            version="next-release",
            min_supported_version="",
            published_at="2025-07-15T12:00:02Z",
        )
        non_numeric = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(non_numeric_payload),
        )
        self.assertEqual(non_numeric.status_code, 422, non_numeric.text)
        self.assertIn("dotted numeric version", non_numeric.text)

        next_payload = self._payload(
            version="v20.0.1",
            min_supported_version="v19.0.0",
            published_at="2025-07-15T12:00:03Z",
        )
        next_release = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(next_payload),
        )
        self.assertEqual(next_release.status_code, 200, next_release.text)
        self.assertEqual(
            self.client.get("/update/stable.json?schema=2").json()["version"],
            "v20.0.1",
        )

        future_payload = self._payload(
            version="v20.0.2",
            published_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        )
        future = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(future_payload),
        )
        self.assertEqual(future.status_code, 422, future.text)
        self.assertIn("future clock skew", future.text)

    def test_signed_floor_cannot_move_backwards_or_be_cleared(self):
        first = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(self._payload(min_supported_version="v19.0.0")),
        )
        self.assertEqual(first.status_code, 200, first.text)

        for version, floor, published_at in (
            ("v20.0.1", "v18.9.9", "2025-07-15T12:00:01Z"),
            ("v20.0.2", "", "2025-07-15T12:00:02Z"),
        ):
            response = self.client.post(
                "/api/admin/releases/v2",
                headers=self.admin_headers,
                json=self._envelope(
                    self._payload(
                        version=version,
                        min_supported_version=floor,
                        published_at=published_at,
                    )
                ),
            )
            self.assertEqual(response.status_code, 409, response.text)

        manifest = self.client.get("/update/stable.json?schema=2").json()
        self.assertEqual(manifest["version"], "v20.0.0")
        self.assertEqual(manifest["min_supported_version"], "v19.0.0")

    def test_stable_floor_atomically_disables_incompatible_allowlists(self):
        conn = get_connection()
        try:
            for index, client_version in enumerate(
                ("*", "invalid", "v18.9.9", "v20.0.0", "v21.0.0"),
                start=1,
            ):
                conn.execute(
                    "INSERT INTO client_integrity_allowlist "
                    "(client_version, manifest_hash, enabled) VALUES (?, ?, 1)",
                    (client_version, f"{index:064x}"),
                )
            conn.commit()
        finally:
            conn.close()

        response = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(
                self._payload(min_supported_version="v20.0.0")
            ),
        )
        self.assertEqual(response.status_code, 200, response.text)

        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT client_version, enabled FROM client_integrity_allowlist"
            ).fetchall()
        finally:
            conn.close()
        enabled_by_version = {
            str(row["client_version"]): bool(row["enabled"]) for row in rows
        }
        self.assertFalse(enabled_by_version["*"])
        self.assertFalse(enabled_by_version["invalid"])
        self.assertFalse(enabled_by_version["v18.9.9"])
        self.assertTrue(enabled_by_version["v20.0.0"])
        self.assertTrue(enabled_by_version["v21.0.0"])

    def test_first_signed_release_is_newer_than_all_legacy_history(self):
        legacy_payload = self._payload(version="v20.0.0")
        legacy = self.client.post(
            "/api/admin/releases",
            headers=self.admin_headers,
            json={
                "version": "v20.0.0",
                "channel": "stable",
                "url": legacy_payload["target"]["url"],
                "sha256": legacy_payload["target"]["sha256"],
            },
        )
        self.assertEqual(legacy.status_code, 200, legacy.text)
        legacy_id = int(legacy.json()["release"]["id"])
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE releases SET created_at = ? WHERE id = ?",
                ("2025-07-15 11:59:00", legacy_id),
            )
            conn.commit()
        finally:
            conn.close()

        for version in ("v20.0.0", "v19.9.9"):
            rejected = self.client.post(
                "/api/admin/releases/v2",
                headers=self.admin_headers,
                json=self._envelope(
                    self._payload(
                        version=version,
                        min_supported_version="",
                        published_at="2025-07-15T12:00:00Z",
                    )
                ),
            )
            self.assertEqual(rejected.status_code, 409, rejected.text)
            self.assertIn("version must be newer", rejected.text)

        stale_time = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(
                self._payload(
                    version="v20.0.1",
                    min_supported_version="",
                    published_at="2025-07-15T11:59:00Z",
                )
            ),
        )
        self.assertEqual(stale_time.status_code, 409, stale_time.text)
        self.assertIn("published_at", stale_time.text)

        accepted = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(
                self._payload(
                    version="v20.0.1",
                    min_supported_version="",
                    published_at="2025-07-15T12:00:00Z",
                )
            ),
        )
        self.assertEqual(accepted.status_code, 200, accepted.text)

    def test_signed_v2_rejects_bad_signature_third_party_and_missing_or_mismatched_files(self):
        bad_signature = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(self._payload(version="v20.0.1"), signature=b"x" * 64),
        )
        self.assertEqual(bad_signature.status_code, 422, bad_signature.text)

        third_party_payload = self._payload(
            version="v20.0.2",
            target={
                "url": "https://third-party.example/target.exe",
                "sha256": "a" * 64,
                "size": 100,
                "kind": "onefile_exe",
            },
        )
        third_party = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(third_party_payload),
        )
        self.assertEqual(third_party.status_code, 422, third_party.text)

        same_origin_non_static_payload = self._payload(
            version="v20.0.2a",
            target={
                "url": "https://visionforge.test/download/target.exe",
                "sha256": "a" * 64,
                "size": 100,
                "kind": "onefile_exe",
            },
        )
        same_origin_non_static = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(same_origin_non_static_payload),
        )
        self.assertEqual(same_origin_non_static.status_code, 422, same_origin_non_static.text)
        self.assertIn("/static/releases/", same_origin_non_static.text)

        missing_payload = self._payload(
            version="v20.0.3",
            target={
                "url": "/static/releases/missing.exe",
                "sha256": "a" * 64,
                "size": 100,
                "kind": "onefile_exe",
            },
        )
        missing = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(missing_payload),
        )
        self.assertEqual(missing.status_code, 422, missing.text)

        wrong_size_payload = self._payload(version="v20.0.4")
        wrong_size_payload["target"]["size"] += 1
        wrong_size = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(wrong_size_payload),
        )
        self.assertEqual(wrong_size.status_code, 422, wrong_size.text)

        traversal_payload = self._payload(version="v20.0.5")
        traversal_payload["target"]["url"] = "/static/releases/../outside.exe"
        traversal = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(traversal_payload),
        )
        self.assertEqual(traversal.status_code, 422, traversal.text)

        mismatch_payload = self._payload(version="v20.0.4")
        mismatch_payload["target"]["sha256"] = "f" * 64
        mismatch = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(mismatch_payload),
        )
        self.assertEqual(mismatch.status_code, 422, mismatch.text)

        bad_delta_payload = self._payload(version="v20.0.6")
        bad_delta_payload["deltas"][0]["sha256"] = "e" * 64
        bad_delta = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(bad_delta_payload),
        )
        self.assertEqual(bad_delta.status_code, 422, bad_delta.text)

        arbitrary_name_payload = self._payload(version="v20.0.7")
        arbitrary_name_payload["target"]["url"] = "/static/releases/arbitrary-name.exe"
        arbitrary_name = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(arbitrary_name_payload),
        )
        self.assertEqual(arbitrary_name.status_code, 422, arbitrary_name.text)
        self.assertIn("filename must be", arbitrary_name.text)

        nested_content = b"nested-release-must-not-publish"
        nested_hash = hashlib.sha256(nested_content).hexdigest()
        nested_dir = self.release_root / "stable"
        nested_dir.mkdir()
        (nested_dir / f"{nested_hash}.exe").write_bytes(nested_content)
        nested_payload = self._payload(version="v20.0.8")
        nested_payload["target"] = {
            "url": f"/static/releases/stable/{nested_hash}.exe",
            "sha256": nested_hash,
            "size": len(nested_content),
            "kind": "onefile_exe",
        }
        nested = self.client.post(
            "/api/admin/releases/v2",
            headers=self.admin_headers,
            json=self._envelope(nested_payload),
        )
        self.assertEqual(nested.status_code, 422, nested.text)
        self.assertIn("direct children of /static/releases/", nested.text)

    def test_each_channel_has_only_one_published_release_and_version_is_unique(self):
        for version in ("v100.0.0", "v1.0.0"):
            content = f"legacy-{version}".encode()
            digest = hashlib.sha256(content).hexdigest()
            url, digest, _ = self._write_artifact(f"{digest}.exe", content)
            response = self.client.post(
                "/api/admin/releases",
                headers=self.admin_headers,
                json={
                    "version": version,
                    "channel": "stable",
                    "url": url,
                    "sha256": digest,
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
        manifest = self.client.get("/update/stable.json")
        self.assertEqual(manifest.json()["version"], "v1.0.0")
        conn = get_connection()
        try:
            active = conn.execute(
                "SELECT COUNT(*) FROM releases WHERE channel = 'stable' AND published = 1"
            ).fetchone()[0]
            duplicate_error = None
            try:
                conn.execute(
                    "INSERT INTO releases (version, channel, url, sha256, published) VALUES (?, ?, ?, ?, 0)",
                    ("v1.0.0", "stable", "/static/releases/duplicate.exe", "b" * 64),
                )
            except sqlite3.IntegrityError as exc:
                duplicate_error = exc
        finally:
            conn.close()
        self.assertEqual(active, 1)
        self.assertIsNotNone(duplicate_error)

    def test_only_successful_content_hash_static_response_gets_immutable_cache_policy(self):
        digest = "a" * 64
        path = f"/static/releases/{digest}.exe"
        self.assertTrue(_is_immutable_release_response(path, 200))
        self.assertTrue(_is_immutable_release_response(path, 206))
        self.assertFalse(_is_immutable_release_response(path, 404))
        self.assertFalse(
            _is_immutable_release_response(f"/static/releases/VisionForge-{digest}.exe", 200)
        )
        response = self.client.get(path)
        self.assertNotEqual(
            response.headers.get("cache-control"),
            "public, max-age=31536000, immutable",
        )

    def test_single_server_static_release_supports_range_resume(self):
        payload = b"0123456789-visionforge-range"
        digest = hashlib.sha256(payload).hexdigest()
        static_release_root = Path(__file__).resolve().parents[1] / "app" / "static" / "releases"
        static_release_root.mkdir(parents=True, exist_ok=True)
        artifact = static_release_root / f"{digest}.exe"
        artifact.write_bytes(payload)
        try:
            response = self.client.get(
                f"/static/releases/{digest}.exe",
                headers={"Range": "bytes=3-8"},
            )
        finally:
            artifact.unlink(missing_ok=True)

        self.assertEqual(response.status_code, 206, response.text)
        self.assertEqual(response.content, payload[3:9])
        self.assertEqual(response.headers.get("content-range"), f"bytes 3-8/{len(payload)}")
        self.assertEqual(response.headers.get("accept-ranges"), "bytes")
        self.assertEqual(
            response.headers.get("cache-control"),
            "public, max-age=31536000, immutable",
        )

    def test_nested_release_static_artifact_is_hidden_by_404_contract(self):
        payload = b"nested-static-file-must-not-be-served"
        digest = hashlib.sha256(payload).hexdigest()
        static_release_root = Path(__file__).resolve().parents[1] / "app" / "static" / "releases"
        nested_dir = static_release_root / f"nested-{hashlib.sha256(str(self.root).encode()).hexdigest()[:12]}"
        nested_dir.mkdir(parents=True)
        artifact = nested_dir / f"{digest}.exe"
        artifact.write_bytes(payload)
        try:
            response = self.client.get(
                f"/static/releases/{nested_dir.name}/{digest}.exe"
            )
        finally:
            artifact.unlink(missing_ok=True)
            nested_dir.rmdir()

        self.assertEqual(response.status_code, 404)
        self.assertNotEqual(
            response.headers.get("cache-control"),
            "public, max-age=31536000, immutable",
        )

    def test_legacy_database_migration_deduplicates_before_unique_indexes(self):
        legacy_path = self.root / "legacy.db"
        raw = sqlite3.connect(legacy_path)
        try:
            raw.execute(
                "CREATE TABLE releases ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, "
                "channel TEXT NOT NULL DEFAULT 'stable', notes TEXT NOT NULL DEFAULT '', "
                "url TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL DEFAULT '', "
                "installer_url TEXT NOT NULL DEFAULT '', installer_sha256 TEXT NOT NULL DEFAULT '', "
                "mandatory INTEGER NOT NULL DEFAULT 0, published INTEGER NOT NULL DEFAULT 1, "
                "created_at TEXT NOT NULL DEFAULT (datetime('now')), "
                "updated_at TEXT NOT NULL DEFAULT (datetime('now')))"
            )
            raw.executemany(
                "INSERT INTO releases (version, channel, published) VALUES (?, 'stable', 1)",
                (("v1.0.0",), ("v1.0.0",), ("v2.0.0",)),
            )
            raw.commit()
        finally:
            raw.close()

        config.DATABASE_PATH = str(legacy_path)
        init_db()
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT version, published FROM releases ORDER BY id"
            ).fetchall()
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(releases)").fetchall()
            }
            indexes = {
                row["name"] for row in conn.execute("PRAGMA index_list(releases)").fetchall()
            }
        finally:
            conn.close()
        self.assertEqual(len(rows), 2)
        self.assertEqual(sum(int(row["published"]) for row in rows), 1)
        self.assertIn("min_supported_version", columns)
        self.assertIn("payload_b64", columns)
        self.assertIn("idx_releases_channel_version_unique", indexes)
        self.assertIn("idx_releases_one_published_channel", indexes)


if __name__ == "__main__":
    unittest.main()
