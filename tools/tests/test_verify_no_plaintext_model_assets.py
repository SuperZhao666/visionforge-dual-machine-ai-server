from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "tools/verify_no_plaintext_model_assets.py"
    spec = importlib.util.spec_from_file_location("vf_plaintext_model_scan", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlaintextModelScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.private_bytes = b"locked-private-artifact"
        self.lock = self.root / "lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema": "visionforge-android-private-artifacts-lock-v1",
                    "policy": {
                        "public_source_tree_must_not_contain_locked_bytes": True,
                        "release_requires_encrypted_session_delivery": True,
                        "release_plaintext_allowed": False,
                        "plaintext_allowed_variants": ["debug", "qa"],
                        "source_root_environment":
                            "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT",
                    },
                    "artifacts": [
                        {
                            "size": len(self.private_bytes),
                            "sha256": hashlib.sha256(self.private_bytes).hexdigest(),
                            "allowed_variants": ["debug", "qa"],
                            "license_review_required": True,
                            "public_repository_allowed": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.lock_digests = self.module.load_locked_digests(self.lock)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_clean_source_passes(self) -> None:
        (self.source / "README.md").write_text("public", encoding="utf-8")
        files, _ = self.module.scan_source(self.source, self.lock, self.lock_digests)
        self.assertEqual(1, files)

    def test_onnx_extension_is_rejected(self) -> None:
        (self.source / "model.onnx").write_bytes(b"not-even-a-model")
        with self.assertRaisesRegex(self.module.ScanFailure, "plaintext_onnx"):
            self.module.scan_source(self.source, self.lock, self.lock_digests)

    def test_promoted_qnn_model_library_name_is_rejected(self) -> None:
        (self.source / "libvalorant_demo_w8a16.so").write_bytes(b"x")
        with self.assertRaisesRegex(self.module.ScanFailure, "weight_library"):
            self.module.scan_source(self.source, self.lock, self.lock_digests)

    def test_renamed_locked_bytes_are_rejected(self) -> None:
        (self.source / "innocent.bin").write_bytes(self.private_bytes)
        with self.assertRaisesRegex(self.module.ScanFailure, "locked_private"):
            self.module.scan_source(self.source, self.lock, self.lock_digests)


    def test_weakened_lock_policy_is_rejected(self) -> None:
        payload = json.loads(self.lock.read_text())
        payload["policy"]["plaintext_allowed_variants"] = ["release"]
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(self.module.ScanFailure, "variant policy"):
            self.module.load_locked_digests(self.lock)

    def test_archive_is_scanned_by_name_and_locked_hash(self) -> None:
        archive = self.root / "app.apk"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("assets/renamed.bin", self.private_bytes)
        with self.assertRaisesRegex(self.module.ScanFailure, "locked_private"):
            self.module.scan_archive(archive, self.lock_digests)


if __name__ == "__main__":
    unittest.main()
