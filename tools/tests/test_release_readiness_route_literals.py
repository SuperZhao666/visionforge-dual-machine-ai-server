from __future__ import annotations

import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


READINESS_GLOBALS = runpy.run_path(
    str(
        Path(__file__).resolve().parents[1]
        / "verify_dual_machine_release_readiness.py"
    )
)
PYTHON_AST_ROUTE_LITERALS = READINESS_GLOBALS["_python_ast_route_literals"]
PYTHON_ROUTE_LITERALS = READINESS_GLOBALS["_python_route_literals"]


class ReleaseReadinessRouteLiteralTests(unittest.TestCase):
    def test_runtime_dependency_failure_uses_literal_ast_routes(self) -> None:
        source = '''
from fastapi import APIRouter

router = APIRouter(prefix="/api/dual-machine/v1")

@router.post("/pair-generations/challenges")
def challenge():
    pass

@router.post("/pair-generations/credentials", status_code=201)
async def credential():
    pass
'''
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "routes.py"
            path.write_text(source, encoding="utf-8")
            failed_probe = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="missing dependency"
            )
            subprocess_module = PYTHON_ROUTE_LITERALS.__globals__["subprocess"]
            with mock.patch.object(
                subprocess_module, "run", return_value=failed_probe
            ):
                self.assertEqual(
                    PYTHON_ROUTE_LITERALS(path),
                    (
                        "/api/dual-machine/v1/pair-generations/challenges",
                        "/api/dual-machine/v1/pair-generations/credentials",
                    ),
                )

    def test_dynamic_prefix_or_route_is_not_accepted_as_evidence(self) -> None:
        sources = (
            '''
PREFIX = "/api/dual-machine/v1"
router = APIRouter(prefix=PREFIX)
@router.post("/pair-generations/challenges")
def challenge():
    pass
''',
            '''
router = APIRouter(prefix="/api/dual-machine/v1")
ROUTE = "/pair-generations/challenges"
@router.post(ROUTE)
def challenge():
    pass
''',
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            for index, source in enumerate(sources):
                with self.subTest(index=index):
                    path = Path(temporary_directory) / f"routes_{index}.py"
                    path.write_text(source, encoding="utf-8")
                    self.assertEqual(PYTHON_AST_ROUTE_LITERALS(path), ())

    def test_unrelated_decorators_and_malformed_source_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            unrelated = root / "unrelated.py"
            unrelated.write_text(
                '''
router = APIRouter(prefix="/api/dual-machine/v1")
@other_router.post("/pair-generations/challenges")
def challenge():
    pass
''',
                encoding="utf-8",
            )
            malformed = root / "malformed.py"
            malformed.write_text("def broken(:\n", encoding="utf-8")
            self.assertEqual(PYTHON_AST_ROUTE_LITERALS(unrelated), ())
            self.assertEqual(PYTHON_AST_ROUTE_LITERALS(malformed), ())


if __name__ == "__main__":
    unittest.main()
