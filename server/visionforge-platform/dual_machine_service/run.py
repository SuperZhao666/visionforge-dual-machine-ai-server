"""Loopback-only entrypoint for vf-dual-machine.service."""
from __future__ import annotations

import uvicorn

from .settings import DualMachineSettings


def main() -> None:
    settings = DualMachineSettings.from_environment()
    settings.validate_runtime()
    uvicorn.run(
        "dual_machine_service.main:create_app",
        factory=True,
        host=settings.bind_host,
        port=settings.bind_port,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
