from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArchitectureCheckSelfTest(unittest.TestCase):
    def test_current_tree_passes_architecture_gate(self) -> None:
        module = load("vf_arch", "tools/check_app_host_architecture.py")
        report = module.audit(ROOT)
        self.assertEqual("PASS", report["status"], report["failures"])

    def test_current_tree_passes_transport_gate(self) -> None:
        module = load("vf_transport", "tools/check_video_transport_contract.py")
        report = module.audit(ROOT)
        self.assertEqual("PASS", report["status"], report["failures"])


if __name__ == "__main__":
    unittest.main()
