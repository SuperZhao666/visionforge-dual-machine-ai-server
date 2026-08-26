from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load_module():
    path = ROOT / "tools/check_private_artifact_source_boundary.py"
    spec = importlib.util.spec_from_file_location("vf_private_boundary", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PrivateArtifactSourceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.payload = b"private-weights"
        self.lock = self.repo / "private-artifacts.lock.json"
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
                            "id": "model",
                            "kind": "portable_model_weight",
                            "target_path": "assets/portable_models/model.onnx",
                            "size": len(self.payload),
                            "sha256": hashlib.sha256(self.payload).hexdigest(),
                            "allowed_variants": ["debug", "qa"],
                            "license_review_required": True,
                            "public_repository_allowed": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def scan(self, paths: list[str]):
        return self.module.scan_repository(self.repo, self.lock, paths)

    def write(self, relative: str, data: bytes) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def test_clean_source_tree_passes(self) -> None:
        self.write("src/manifest.json", b"metadata-only")
        result = self.scan(["src/manifest.json", "private-artifacts.lock.json"])
        self.assertTrue(result["ok"])
        self.assertEqual([], result["violations"])

    def test_exact_target_and_raw_model_are_rejected(self) -> None:
        relative = (
            "android_inference_benchmark/app/src/main/assets/portable_models/model.onnx"
        )
        self.write(relative, self.payload)
        result = self.scan([relative, "private-artifacts.lock.json"])
        codes = {item["code"] for item in result["violations"]}
        self.assertIn("LOCKED_TARGET_TRACKED", codes)
        self.assertIn("RAW_MODEL_TRACKED", codes)
        self.assertIn("LOCKED_BYTES_TRACKED", codes)

    def test_renamed_locked_bytes_are_rejected(self) -> None:
        self.write("docs/innocent.data", self.payload)
        result = self.scan(["docs/innocent.data", "private-artifacts.lock.json"])
        self.assertFalse(result["ok"])
        self.assertEqual("LOCKED_BYTES_TRACKED", result["violations"][0]["code"])

    def test_android_binary_lfs_pointer_is_rejected(self) -> None:
        relative = "android_inference_benchmark/app/src/main/jniLibs/arm64-v8a/a.so"
        self.write(
            relative,
            b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64,
        )
        result = self.scan([relative, "private-artifacts.lock.json"])
        self.assertIn(
            "GIT_LFS_POINTER", {item["code"] for item in result["violations"]}
        )

    def test_exact_user_trained_public_model_is_allowlisted(self) -> None:
        relative = (
            "android_inference_benchmark/app/src/main/jniLibs/arm64-v8a/model.so"
        )
        payload = json.loads(self.lock.read_text(encoding="utf-8"))
        artifact = payload["artifacts"][0]
        artifact.update(
            {
                "kind": "model_weight_library",
                "target_path": "jniLibs/arm64-v8a/model.so",
                "public_repository_allowed": True,
                "provenance": "user_trained",
                "repository_storage": "git_lfs",
                "repository_path": relative,
            }
        )
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        self.write(relative, self.payload)

        result = self.scan([relative, "private-artifacts.lock.json"])

        self.assertTrue(result["ok"])
        self.assertEqual([], result["violations"])
        self.assertEqual(1, result["public_models_allowlisted"])

    def test_public_repository_exception_rejects_non_model_artifact(self) -> None:
        payload = json.loads(self.lock.read_text(encoding="utf-8"))
        artifact = payload["artifacts"][0]
        artifact.update(
            {
                "public_repository_allowed": True,
                "provenance": "user_trained",
                "repository_storage": "git_lfs",
                "repository_path": (
                    "android_inference_benchmark/app/src/main/assets/"
                    "portable_models/model.onnx"
                ),
            }
        )
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.BoundaryPolicyError, "user-trained Git LFS models"
        ):
            self.scan(["private-artifacts.lock.json"])


    def test_gradle_stager_declares_external_root_input_before_execution(self) -> None:
        gradle = (
            ROOT / "android_inference_benchmark/app/build.gradle"
        ).read_text(encoding="utf-8")
        registration = gradle.index("def registerPrivateArtifactStaging")
        do_first = gradle.index("doFirst {", registration)
        declared_input = gradle.index("inputs.dir(file(privateArtifactRoot))", registration)
        self.assertLess(declared_input, do_first)
        self.assertIn("inputs.file(privateArtifactStager)", gradle[registration:do_first])

    def test_gradle_release_scan_does_not_consume_stale_debug_packages(self) -> None:
        gradle = (
            ROOT / "android_inference_benchmark/app/build.gradle"
        ).read_text(encoding="utf-8")
        self.assertIn("new File(outputsRoot, 'apk/release')", gradle)
        self.assertIn("new File(outputsRoot, 'bundle/release')", gradle)
        self.assertNotIn(
            "fileTree(outputsRoot) { include '**/*.apk', '**/*.aab' }",
            gradle,
        )
        self.assertIn("android.sourceSets.main.jniLibs.setSrcDirs([])", gradle)
        self.assertIn(
            "android.sourceSets.main.assets.exclude('qnn/**', 'portable_models/**')",
            gradle,
        )

    def test_invalid_lock_policy_is_rejected(self) -> None:
        payload = json.loads(self.lock.read_text())
        payload["policy"]["release_plaintext_allowed"] = True
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(self.module.BoundaryPolicyError):
            self.scan(["private-artifacts.lock.json"])

        payload["policy"]["release_plaintext_allowed"] = False
        payload["policy"]["source_root_environment"] = "OTHER_ROOT"
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            self.module.BoundaryPolicyError, "source_root_environment"
        ):
            self.scan(["private-artifacts.lock.json"])

    def test_explicit_owner_private_variant_preserves_source_boundary(self) -> None:
        payload = json.loads(self.lock.read_text(encoding="utf-8"))
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
        self.lock.write_text(json.dumps(payload), encoding="utf-8")
        self.write("src/manifest.json", b"metadata-only")

        result = self.scan(["src/manifest.json", "private-artifacts.lock.json"])

        self.assertTrue(result["ok"])
        self.assertEqual([], result["violations"])


if __name__ == "__main__":
    unittest.main()
