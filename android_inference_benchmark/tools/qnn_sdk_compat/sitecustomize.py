"""Compatibility shim for QAIRT 2.37 on Windows hosts reporting an empty CPU name."""

from __future__ import annotations

import platform


if not platform.processor().strip():
    platform.processor = lambda: "AMD64"  # type: ignore[assignment]
