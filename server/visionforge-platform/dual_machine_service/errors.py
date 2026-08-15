"""Public, bounded errors for the isolated dual-machine API."""
from __future__ import annotations


class DualMachineServiceError(RuntimeError):
    def __init__(self, code: str, status_code: int) -> None:
        super().__init__(code)
        self.code = str(code)
        self.status_code = int(status_code)
