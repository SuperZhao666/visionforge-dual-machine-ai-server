from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
READINESS_GLOBALS = runpy.run_path(
    str(ROOT / "tools" / "verify_dual_machine_release_readiness.py")
)
PYTHON_ROUTE_LITERALS = READINESS_GLOBALS["_python_route_literals"]


def test_fastapi_included_routers_are_runtime_route_evidence(monkeypatch) -> None:
    def reject_ast_fallback(_path: Path) -> tuple[str, ...]:
        raise AssertionError("runtime FastAPI route discovery used the AST fallback")

    monkeypatch.setitem(
        PYTHON_ROUTE_LITERALS.__globals__,
        "_python_ast_route_literals",
        reject_ast_fallback,
    )

    routes = set(
        PYTHON_ROUTE_LITERALS(
            ROOT
            / "server"
            / "visionforge-platform"
            / "dual_machine_service"
            / "routes.py"
        )
    )

    assert "/api/dual-machine/v1/pair-generations/challenges" in routes
    assert "/api/dual-machine/v1/pair-generations/credentials" in routes
    assert "/internal/dual-machine-admin/v1/products" in routes
    assert "/healthz" in routes
