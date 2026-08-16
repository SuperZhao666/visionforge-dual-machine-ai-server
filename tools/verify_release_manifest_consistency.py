"""Validate the single source of truth for dual-machine release identity."""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "release-manifest.json"
RELEASE_VERSION_FILE = ROOT / "dual_machine_runtime" / "release_version.txt"
ANDROID_BUILD_FILE = ROOT / "android_inference_benchmark" / "app" / "build.gradle"
RUNTIME_CMAKE_FILE = ROOT / "dual_machine_runtime" / "CMakeLists.txt"

SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER = re.compile(r"^\$\{[A-Z0-9_]+\}$")


class ManifestError(ValueError):
    """Raised when the manifest is malformed or disagrees with source files."""


def _strict_json(path: Path) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ManifestError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ManifestError(f"non-finite JSON value: {value}")
            ),
        )
    except OSError as exc:
        raise ManifestError(f"manifest cannot be read: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value


def _text(mapping: object, key: str, context: str) -> str:
    if not isinstance(mapping, dict):
        raise ManifestError(f"{context} must be an object")
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"{context}.{key} must be a non-empty string")
    return value.strip()


def _component(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    components = manifest.get("components")
    if not isinstance(components, dict) or not isinstance(components.get(name), dict):
        raise ManifestError(f"components.{name} must be an object")
    return components[name]


def _validate_signature(manifest: dict[str, Any], *, require_published: bool) -> None:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise ManifestError("signature must be an object")
    if signature.get("algorithm") != "Ed25519":
        raise ManifestError("signature.algorithm must be Ed25519")
    key_id = signature.get("key_id")
    signature_b64 = signature.get("signature_b64")
    if require_published:
        if not isinstance(key_id, str) or PLACEHOLDER.fullmatch(key_id or ""):
            raise ManifestError("published manifest requires a concrete signature key_id")
        if not isinstance(signature_b64, str) or not signature_b64:
            raise ManifestError("published manifest requires signature_b64")
        try:
            base64.b64decode(signature_b64, validate=True)
        except Exception as exc:  # pragma: no cover - exact decoder type is implementation-specific
            raise ManifestError("published manifest signature_b64 is not valid base64") from exc
    elif not (
        isinstance(key_id, str)
        and PLACEHOLDER.fullmatch(key_id)
        and isinstance(signature_b64, str)
        and PLACEHOLDER.fullmatch(signature_b64)
    ):
        raise ManifestError(
            "source manifest must keep signature fields as explicit publication placeholders"
        )


def _validate_artifacts(manifest: dict[str, Any], *, require_published: bool) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ManifestError("artifacts must be an object")
    expected = {
        "android_apk": ("/static/dual-machine-mobile/<sha256>.apk", "apk"),
        "host_exe": ("/static/dual-machine-host/<sha256>.exe", "exe"),
    }
    for name, (source_url, suffix) in expected.items():
        artifact = artifacts.get(name)
        if not isinstance(artifact, dict):
            raise ManifestError(f"artifacts.{name} must be an object")
        url = artifact.get("url")
        size = artifact.get("size")
        digest = artifact.get("sha256")
        if require_published:
            if not isinstance(url, str) or not re.fullmatch(
                rf"/static/[a-z0-9-]+/[0-9a-f]{{64}}\.{suffix}", url
            ):
                raise ManifestError(f"published artifacts.{name}.url must be content addressed")
            if not isinstance(size, int) or size <= 0:
                raise ManifestError(f"published artifacts.{name}.size must be positive")
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                raise ManifestError(f"published artifacts.{name}.sha256 must be lowercase SHA-256")
        else:
            if url != source_url or size is not None or digest is not None:
                raise ManifestError(
                    f"source artifacts.{name} must remain unbuilt placeholders"
                )


def validate_manifest(
    manifest_path: Path = DEFAULT_MANIFEST,
    *,
    require_published: bool = False,
) -> dict[str, Any]:
    manifest = _strict_json(manifest_path)
    if manifest.get("schema") != "visionforge-dual-machine-release-manifest-v1":
        raise ManifestError("unsupported release manifest schema")
    if not require_published and manifest.get("manifest_kind") != "source":
        raise ManifestError("source validation requires manifest_kind=source")

    release_version = RELEASE_VERSION_FILE.read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(release_version):
        raise ManifestError(f"release_version.txt is not stable SemVer: {release_version}")
    release_id = _text(manifest, "release_id", "manifest")
    if release_id != f"visionforge-dual-machine-{release_version}":
        raise ManifestError("release_id does not match release_version.txt")

    commit = _text(manifest, "commit", "manifest")
    if require_published:
        if not COMMIT.fullmatch(commit):
            raise ManifestError("published manifest commit must be a 40-character Git SHA")
    elif commit != "${GIT_COMMIT}":
        raise ManifestError("source manifest commit must be ${GIT_COMMIT}")

    client_protocol = _text(manifest, "client_protocol_version", "manifest")
    if client_protocol != "1.0.0":
        raise ManifestError("client_protocol_version must remain 1.0.0 for this contract")
    if manifest.get("wire_protocol_version") != 2:
        raise ManifestError("wire_protocol_version must be 2")

    for name in ("server", "host", "android"):
        component = _component(manifest, name)
        if _text(component, "version", f"components.{name}") != release_version:
            raise ManifestError(f"components.{name}.version disagrees with release_version.txt")
        minimum = _text(component, "minimum_supported_version", f"components.{name}")
        if not SEMVER.fullmatch(minimum):
            raise ManifestError(f"components.{name}.minimum_supported_version is invalid")

    android = _component(manifest, "android")
    version_code = android.get("version_code")
    previous_version_code = android.get("previous_version_code")
    if not isinstance(version_code, int) or isinstance(version_code, bool) or version_code <= 0:
        raise ManifestError("components.android.version_code must be a positive integer")
    if (
        not isinstance(previous_version_code, int)
        or isinstance(previous_version_code, bool)
        or previous_version_code < 0
        or previous_version_code >= version_code
    ):
        raise ManifestError(
            "components.android.previous_version_code must be less than version_code"
        )
    if _text(android, "package_name", "components.android") != "com.visionforge.mobile":
        raise ManifestError("components.android.package_name is not canonical")

    gradle = ANDROID_BUILD_FILE.read_text(encoding="utf-8")
    if "def dualMachineReleaseManifestFile = rootProject.file('../release/release-manifest.json')" not in gradle:
        raise ManifestError("Android Gradle must load the canonical release manifest")
    if "def productionVersionCode = (dualMachineAndroidRelease.version_code as Number).intValue()" not in gradle:
        raise ManifestError("Android Gradle versionCode must come from the release manifest")
    if "dualMachineAndroidRelease.previous_version_code as Number" not in gradle:
        raise ManifestError("Android Gradle previous versionCode must come from the release manifest")
    if "../release/release-manifest.json" not in gradle:
        raise ManifestError("Android Gradle must read the canonical release manifest")
    if "../dual_machine_runtime/release_version.txt" not in gradle:
        raise ManifestError("Android Gradle must retain the canonical runtime version check")
    cmake = RUNTIME_CMAKE_FILE.read_text(encoding="utf-8")
    if "release_version.txt" not in cmake:
        raise ManifestError("Host CMake must read the canonical runtime version file")

    _validate_artifacts(manifest, require_published=require_published)
    _validate_signature(manifest, require_published=require_published)
    publication = manifest.get("publication")
    if not isinstance(publication, dict) or publication.get("immutable") is not True:
        raise ManifestError("publication.immutable must be true")
    expected_status = "published" if require_published else "unpublished"
    if publication.get("status") != expected_status:
        raise ManifestError(f"publication.status must be {expected_status}")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--require-published", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = validate_manifest(
            args.manifest.resolve(), require_published=args.require_published
        )
    except (ManifestError, OSError) as exc:
        payload = {"ok": False, "error": str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(f"RELEASE_MANIFEST_RED: {exc}")
        return 1
    payload = {
        "ok": True,
        "mode": "published" if args.require_published else "source",
        "release_id": manifest["release_id"],
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "RELEASE_MANIFEST_GREEN: "
            f"mode={payload['mode']} release_id={payload['release_id']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
