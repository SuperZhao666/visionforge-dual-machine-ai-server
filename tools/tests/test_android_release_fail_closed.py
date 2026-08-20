from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AndroidReleaseFailClosedContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_release_capabilities_remain_explicitly_false(self) -> None:
        formal = self.read(
            "android_inference_benchmark/app/formal-security-capability.properties"
        ).strip()
        model = self.read(
            "android_inference_benchmark/app/secure-model-delivery-capability.properties"
        ).strip()
        self.assertEqual("formalSecureDataPlaneImplemented=false", formal)
        self.assertEqual("secureEncryptedModelDeliveryImplemented=false", model)

    def test_gradle_release_graph_depends_on_secure_model_gate(self) -> None:
        loader = self.read(
            "android_inference_benchmark/app/secure-model-delivery-loader.gradle"
        )
        self.assertIn("verifySecureEncryptedModelDeliveryImplemented", loader)
        self.assertIn("'packageRelease', 'bundleRelease'", loader)
        self.assertIn("refusing release APK", loader)

        formal_loader = self.read(
            "android_inference_benchmark/app/formal-security-loader.gradle"
        )
        self.assertIn("'packageRelease', 'bundleRelease'", formal_loader)
        self.assertIn("verifyFormalSecureDataPlaneImplemented", formal_loader)

    def test_public_check_does_not_require_protected_release_materials(self) -> None:
        build = self.read("android_inference_benchmark/app/build.gradle")
        self.assertIn("tasks.register('verifyMobilePublicContracts')", build)
        self.assertIn("dependsOn(verifyMobilePublicContractsTask)", build)
        self.assertNotIn(
            "tasks.named('check').configure {\n"
            "    dependsOn(tasks.named('verifyMobileReleaseContracts'))",
            build,
        )

    def test_release_installer_refuses_false_capabilities_and_plaintext_assets(self) -> None:
        installer = self.read(
            "android_inference_benchmark/tools/install_mobile_release.ps1"
        )
        self.assertIn("Assert-FormalMobileReleaseCapabilities $projectRoot", installer)
        self.assertIn("formalSecureDataPlaneImplemented", installer)
        self.assertIn("secureEncryptedModelDeliveryImplemented", installer)
        self.assertIn("Assert-MobileApkContainsNoPlaintextPrivateArtifacts", installer)
        self.assertNotIn("Assert-MobileApkContainsMigrationModels", installer)


if __name__ == "__main__":
    unittest.main()
