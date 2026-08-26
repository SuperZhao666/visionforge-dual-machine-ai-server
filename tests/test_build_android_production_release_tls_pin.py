from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.build_android_production_release import (  # noqa: E402
    verify_live_tls_pin_input,
)
from tools.prepare_dual_machine_release_materials import (  # noqa: E402
    tls_spki_pin_from_der_spki,
)


def _pin(seed: bytes) -> str:
    return tls_spki_pin_from_der_spki(seed.ljust(64, b"\0"))


def test_live_tls_pin_preflight_accepts_exact_current_pin_and_backup() -> None:
    current = _pin(b"current")
    backup = _pin(b"backup")

    report = verify_live_tls_pin_input(
        environ={"VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS": f"{current},{backup}"},
        fetcher=lambda *args, **kwargs: current,
    )

    assert report["ok"] is True
    assert report["configured_current_pin"] == current
    assert report["live_current_pin"] == current
    assert report["configured_pin_count"] == 2


def test_live_tls_pin_preflight_rejects_canonical_but_wrong_current_pin() -> None:
    configured = _pin(b"mistyped-current")
    live = _pin(b"live-current")
    backup = _pin(b"backup")

    report = verify_live_tls_pin_input(
        environ={"VISIONFORGE_DUAL_MACHINE_TLS_SPKI_PINS": f"{configured},{backup}"},
        fetcher=lambda *args, **kwargs: live,
    )

    assert report["ok"] is False
    assert report["errors"] == [
        "configured current TLS SPKI pin does not match the live leaf certificate"
    ]


def test_live_tls_pin_preflight_rejects_missing_rotation_set_without_network() -> None:
    calls = 0

    def unexpected_fetch(*_args: object, **_kwargs: object) -> str:
        nonlocal calls
        calls += 1
        raise AssertionError("network fetch must not run for structurally invalid inputs")

    report = verify_live_tls_pin_input(environ={}, fetcher=unexpected_fetch)

    assert report["ok"] is False
    assert calls == 0
    assert "2-4 distinct" in report["errors"][0]
