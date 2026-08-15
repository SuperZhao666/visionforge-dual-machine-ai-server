import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-update-manifest")

from fastapi.testclient import TestClient

from app.config import config
from app.database import get_connection, init_db
from app.main import app


class UpdateManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.previous_site_url = config.SITE_URL
        config.DATABASE_PATH = str(Path(self.tmpdir.name) / "vf.db")
        config.SITE_URL = "https://www.visionforge.cloud"
        init_db()

    def tearDown(self):
        config.SITE_URL = self.previous_site_url
        self.tmpdir.cleanup()

    def test_update_manifest_exposes_release_notes_and_hash_fields(self):
        conn = get_connection()
        try:
            conn.execute(
                "INSERT INTO releases "
                "(version, channel, notes, url, sha256, installer_url, installer_sha256, mandatory, published) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "v99.0.0",
                    "stable",
                    "修复更新页显示。",
                    "https://www.visionforge.cloud/downloads/VisionForge.exe",
                    "a" * 64,
                    "https://www.visionforge.cloud/downloads/VisionForge_Setup.exe",
                    "b" * 64,
                    1,
                    1,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        response = TestClient(app).get("/update/stable.json")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()

        self.assertTrue(data["ok"])
        self.assertEqual(data["version"], "v99.0.0")
        self.assertEqual(data["latest_version"], "v99.0.0")
        self.assertEqual(data["release_notes"], "修复更新页显示。")
        self.assertEqual(data["download_url"], "https://www.visionforge.cloud/downloads/VisionForge_Setup.exe")
        self.assertEqual(data["download_sha256"], "b" * 64)
        self.assertEqual(data["installer_sha256"], "b" * 64)
        self.assertEqual(data["artifact_kind"], "installer")
        self.assertTrue(data["mandatory"])


if __name__ == "__main__":
    unittest.main()
