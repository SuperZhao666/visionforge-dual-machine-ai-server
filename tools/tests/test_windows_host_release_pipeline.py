from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WindowsHostReleasePipelineContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_build_requires_external_signer_timestamp_and_pinned_certificate(self) -> None:
        script = self.read(
            "dual_machine_runtime/host/windows/build_host_application.bat"
        )
        self.assertIn("VFDUAL_REQUIRE_AUTHENTICODE=1", script)
        self.assertIn("VFDUAL_HOST_SIGN_SCRIPT", script)
        self.assertIn("VFDUAL_HOST_SIGNER_CERT_SHA256", script)
        self.assertIn("must be stored outside the repository workspace", script)
        self.assertIn("-ExpectedSignerCertificateSha256", script)
        self.assertIn("-RequireAuthenticode", script)
        self.assertIn("-RequireTimestamp", script)
        self.assertIn("-DVFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS=OFF", script)

    def test_verifier_keeps_evidence_out_of_public_directory(self) -> None:
        verifier = self.read(
            "dual_machine_runtime/host/windows/verify_host_release_artifact.ps1"
        )
        self.assertIn("Private Host verification evidence must not be written beside", verifier)
        self.assertIn("residual PDB/CodeView path", verifier)
        self.assertIn("absolute build path", verifier)
        self.assertIn("TimeStamperCertificate", verifier)
        self.assertIn("expected_signer_certificate_sha256", verifier)
        self.assertNotIn('$reportPath = "$resolvedExe.verify.json"', verifier)
        self.assertNotIn('$sha256Path = "$resolvedExe.sha256"', verifier)

    def test_release_compile_contract_disables_rtti_and_enables_mitigations(self) -> None:
        cmake = self.read("dual_machine_runtime/CMakeLists.txt")
        for switch in ["/GR-", "/GS", "/sdl", "/guard:cf", "/CETCOMPAT"]:
            self.assertIn(switch, cmake)


if __name__ == "__main__":
    unittest.main()
