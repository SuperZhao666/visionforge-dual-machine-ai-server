"""Read the repository release identity used by server-facing version APIs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RELEASE_MANIFEST_PATH = (
    Path(__file__).resolve().parents[3] / "release" / "release-manifest.json"
)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate release manifest key: {key}")
        result[key] = value
    return result


def load_release_manifest() -> dict[str, Any]:
    value = json.loads(
        RELEASE_MANIFEST_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
    )
    if not isinstance(value, dict):
        raise ValueError("release manifest root must be an object")
    if value.get("schema") != "visionforge-dual-machine-release-manifest-v1":
        raise ValueError("unsupported release manifest schema")
    publication = value.get("publication")
    if not isinstance(publication, dict) or publication.get("status") != "unpublished":
        raise ValueError("server source checkout requires an unpublished source manifest")
    components = value.get("components")
    if not isinstance(components, dict):
        raise ValueError("release manifest components are missing")
    version = components.get("server", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("release manifest server version is missing")
    return value


CURRENT_RELEASE_MANIFEST = load_release_manifest()
CURRENT_RELEASE_ID = str(CURRENT_RELEASE_MANIFEST["release_id"])
CURRENT_RELEASE_VERSION = str(
    CURRENT_RELEASE_MANIFEST["components"]["server"]["version"]
)
