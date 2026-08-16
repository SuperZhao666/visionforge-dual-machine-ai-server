from __future__ import annotations

from dual_machine_service.release_manifest import (
    CURRENT_RELEASE_ID,
    CURRENT_RELEASE_VERSION,
)


def test_server_release_identity_comes_from_canonical_manifest():
    assert CURRENT_RELEASE_ID == "visionforge-dual-machine-1.0.8"
    assert CURRENT_RELEASE_VERSION == "1.0.8"
