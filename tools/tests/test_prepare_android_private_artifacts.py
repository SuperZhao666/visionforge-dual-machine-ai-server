from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import unittest.mock
import sys

ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "tools/prepare_android_private_artifacts.py"
    spec = importlib.util.spec_from_file_location("vf_private_artifacts", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrivateArtifactStagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "private"
        self.output = self.root / "output"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_lock(self, data: bytes = b"private-model") -> Path:
        source_path = self.source / "android/models/portable/model.onnx"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(data)
        lock = {
            "schema": "visionforge-android-private-artifacts-lock-v1",
            "policy": {
                "public_source_tree_must_not_contain_locked_bytes": True,
                "release_requires_encrypted_session_delivery": True,
                "plaintext_allowed_variants": ["debug", "qa"],
                "release_plaintext_allowed": False,
                "source_root_environment": "VISIONFORGE_ANDROID_PRIVATE_ARTIFACT_ROOT",
            },
            "artifacts": [
                {
                    "id": "portable_model",
                    "kind": "portable_model_weight",
                    "source_path": "android/models/portable/model.onnx",
                    "target_path": "assets/portable_models/model.onnx",
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "allowed_variants": ["debug", "qa"],
                    "license_review_required": True,
                    "public_repository_allowed": False,
                }
            ],
        }
        lock_path = self.root / "private-artifacts.lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        return lock_path

    def test_debug_staging_is_verified_and_atomic(self) -> None:
        lock = self.write_lock()
        result = self.module.stage_artifacts(
            lock, self.source, self.output, "debug"
        )
        self.assertEqual("debug", result["variant"])
        staged = self.output / "assets/portable_models/model.onnx"
        self.assertEqual(b"private-model", staged.read_bytes())
        manifest = json.loads((self.output / "artifact-manifest.json").read_text())
        self.assertEqual(
            hashlib.sha256(b"private-model").hexdigest(),
            manifest["files"][0]["sha256"],
        )
        self.assertNotIn(str(self.source), json.dumps(manifest))

    def test_release_plaintext_staging_is_rejected(self) -> None:
        lock = self.write_lock()
        with self.assertRaisesRegex(
            self.module.ArtifactPolicyError, "release plaintext"
        ):
            self.module.stage_artifacts(
                lock, self.source, self.output, "release", verify_only=True
            )

    def test_explicit_owner_private_staging_is_allowed_without_enabling_release(self) -> None:
        lock = self.write_lock()
        payload = json.loads(lock.read_text(encoding="utf-8"))
        payload["policy"]["owner_private_release_plaintext_allowed"] = True
        payload["policy"]["plaintext_allowed_variants"] = [
            "debug",
            "qa",
            "owner",
        ]
        payload["artifacts"][0]["allowed_variants"] = [
            "debug",
            "qa",
            "owner",
        ]
        lock.write_text(json.dumps(payload), encoding="utf-8")

        result = self.module.stage_artifacts(
            lock, self.source, self.output, "owner", verify_only=True
        )

        self.assertEqual("owner", result["variant"])
        self.assertTrue(result["owner_private_release_plaintext_allowed"])
        self.assertFalse(result["release_plaintext_allowed"])

    def test_hash_mismatch_does_not_replace_previous_output(self) -> None:
        lock = self.write_lock()
        self.output.mkdir()
        (self.output / "sentinel.txt").write_text("keep", encoding="utf-8")
        (self.source / "android/models/portable/model.onnx").write_bytes(b"tampered")
        with self.assertRaisesRegex(
            self.module.ArtifactPolicyError, "integrity mismatch"
        ):
            self.module.stage_artifacts(lock, self.source, self.output, "debug")
        self.assertEqual("keep", (self.output / "sentinel.txt").read_text())

    def test_symlink_source_is_rejected(self) -> None:
        lock = self.write_lock()
        source_path = self.source / "android/models/portable/model.onnx"
        real = self.root / "outside.onnx"
        real.write_bytes(source_path.read_bytes())
        source_path.unlink()
        try:
            source_path.symlink_to(real)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink privilege is unavailable")
            raise
        with self.assertRaisesRegex(self.module.ArtifactPolicyError, "symlink"):
            self.module.stage_artifacts(lock, self.source, self.output, "debug")


    def test_policy_fields_are_strictly_enforced(self) -> None:
        lock = self.write_lock()
        payload = json.loads(lock.read_text())
        payload["policy"]["plaintext_allowed_variants"] = ["qa", "debug"]
        lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.ArtifactPolicyError, "plaintext_allowed_variants"
        ):
            self.module.load_lock(lock)

        payload["policy"]["plaintext_allowed_variants"] = ["debug", "qa"]
        payload["policy"]["source_root_environment"] = "UNTRUSTED_ROOT"
        lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.ArtifactPolicyError, "source_root_environment"
        ):
            self.module.load_lock(lock)

    def test_copy_time_integrity_check_prevents_atomic_replace(self) -> None:
        lock = self.write_lock()
        self.output.mkdir()
        (self.output / "sentinel.txt").write_text("keep", encoding="utf-8")

        original_open = Path.open
        source_path = self.source / "android/models/portable/model.onnx"
        mutated = False

        def racing_open(path, *args, **kwargs):
            nonlocal mutated
            mode = args[0] if args else kwargs.get("mode", "r")
            if path == source_path and mode == "rb" and not mutated:
                # The first two reads are verification + prefix. Mutate before the
                # staging copy opens the same path a third time.
                racing_open.count += 1
                if racing_open.count == 3:
                    path.write_bytes(b"changed-after-verification")
                    mutated = True
            return original_open(path, *args, **kwargs)

        racing_open.count = 0
        with unittest.mock.patch.object(Path, "open", racing_open):
            with self.assertRaisesRegex(
                self.module.ArtifactPolicyError, "changed while staging"
            ):
                self.module.stage_artifacts(lock, self.source, self.output, "debug")
        self.assertEqual("keep", (self.output / "sentinel.txt").read_text())

    def test_path_traversal_and_public_policy_are_rejected(self) -> None:
        lock = self.write_lock()
        payload = json.loads(lock.read_text())
        payload["artifacts"][0]["target_path"] = "../escape.onnx"
        lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(self.module.ArtifactPolicyError):
            self.module.load_lock(lock)

    def test_user_trained_git_lfs_model_public_metadata_is_accepted(self) -> None:
        lock = self.write_lock()
        payload = json.loads(lock.read_text())
        artifact = payload["artifacts"][0]
        artifact.update(
            {
                "kind": "model_weight_library",
                "target_path": "jniLibs/arm64-v8a/model.so",
                "public_repository_allowed": True,
                "provenance": "user_trained",
                "repository_storage": "git_lfs",
                "repository_path": (
                    "android_inference_benchmark/app/src/main/"
                    "jniLibs/arm64-v8a/model.so"
                ),
            }
        )
        lock.write_text(json.dumps(payload), encoding="utf-8")

        _, artifacts = self.module.load_lock(lock)

        self.assertTrue(artifacts[0].public_repository_allowed)

    def test_vendor_runtime_cannot_opt_into_public_repository(self) -> None:
        lock = self.write_lock()
        payload = json.loads(lock.read_text())
        artifact = payload["artifacts"][0]
        artifact.update(
            {
                "kind": "vendor_runtime",
                "public_repository_allowed": True,
                "provenance": "user_trained",
                "repository_storage": "git_lfs",
                "repository_path": (
                    "android_inference_benchmark/app/src/main/"
                    "assets/portable_models/model.onnx"
                ),
            }
        )
        lock.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(
            self.module.ArtifactPolicyError, "user-trained Git LFS model"
        ):
            self.module.load_lock(lock)


if __name__ == "__main__":
    unittest.main()
