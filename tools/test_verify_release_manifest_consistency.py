from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from verify_release_manifest_consistency import (
    DEFAULT_MANIFEST,
    ManifestError,
    validate_manifest,
)


class ReleaseManifestConsistencyTests(unittest.TestCase):
    def test_source_manifest_matches_all_component_sources(self):
        manifest = validate_manifest()
        self.assertEqual(manifest["release_id"], "visionforge-dual-machine-1.0.8")

    def test_manifest_version_tampering_is_rejected(self):
        payload = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        payload["components"]["android"]["version"] = "1.0.9"
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release-manifest.json"
            candidate.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            with self.assertRaisesRegex(ManifestError, "components.android.version"):
                validate_manifest(candidate)

    def test_unpublished_source_cannot_be_accepted_as_published(self):
        with self.assertRaisesRegex(ManifestError, "published manifest commit"):
            validate_manifest(require_published=True)


if __name__ == "__main__":
    unittest.main()
