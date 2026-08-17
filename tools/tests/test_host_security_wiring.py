from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HostSecurityWiringContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_host_runtime_has_no_unconditional_data_plane_permit(self) -> None:
        source = self.read(
            "dual_machine_runtime/host/windows/src/host_runtime_service.cpp"
        )
        compact = re.sub(r"\s+", " ", source)
        self.assertNotIn("[]() noexcept { return true; }", compact)
        self.assertGreaterEqual(
            source.count("authorization_gate->permits_data_plane()"), 2
        )
        self.assertIn("reason=host_authorization_closed", source)

    def test_video_idr_and_mouse_paths_share_fail_closed_permit(self) -> None:
        application = self.read(
            "dual_machine_runtime/host/windows/src/host_application.cpp"
        )
        self.assertGreaterEqual(application.count("config.video.data_plane_permit"), 2)

        idr = self.read(
            "dual_machine_runtime/host/windows/src/idr_request_listener.cpp"
        )
        self.assertIn("authorized &&", idr)
        self.assertIn("permit_source_ && permit_source_()", idr)

        mouse = self.read(
            "dual_machine_runtime/host/windows/src/host_mouse_button_publisher.cpp"
        )
        self.assertGreaterEqual(mouse.count("authorization_permits_send()"), 4)
        self.assertIn("socket.close();", mouse)

    def test_raw_ticket_text_cannot_enter_host_gate_api(self) -> None:
        header = self.read(
            "dual_machine_runtime/shared/include/vfdual/host_data_plane_authorization_gate.hpp"
        )
        self.assertIn("const VerifiedUsageLease& ticket", header)
        self.assertNotRegex(header, r"submit[^;]*std::string(?:_view)?")

    def test_formal_security_capability_remains_blocked(self) -> None:
        cmake = self.read("dual_machine_runtime/formal_security_capability.cmake")
        android = self.read(
            "android_inference_benchmark/app/formal-security-capability.properties"
        )
        self.assertIn("VFDUAL_FORMAL_SECURITY_IMPLEMENTED OFF", cmake)
        self.assertIn("formalSecureDataPlaneImplemented=false", android)


if __name__ == "__main__":
    unittest.main()
