"""Validated runtime catalog domain objects."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_CATALOG_BYTES = 2 * 1024 * 1024
TENSORRT_COMMON_REQUIRED_PATHS = frozenset({
    "bin/nvinfer_10.dll",
    "bin/nvonnxparser_10.dll",
    "bin/nvinfer_plugin_10.dll",
})
TENSORRT_BUILDER_RESOURCE_BY_COMPONENT_ID = {
    "tensorrt10-sm75": "bin/nvinfer_builder_resource_sm75_10.dll",
    "tensorrt10-sm80": "bin/nvinfer_builder_resource_sm80_10.dll",
    "tensorrt10-sm86": "bin/nvinfer_builder_resource_sm86_10.dll",
    "tensorrt10-sm89": "bin/nvinfer_builder_resource_sm89_10.dll",
    "tensorrt10-sm90": "bin/nvinfer_builder_resource_sm90_10.dll",
    "tensorrt10-sm100": "bin/nvinfer_builder_resource_sm100_10.dll",
    "tensorrt10-sm120": "bin/nvinfer_builder_resource_sm120_10.dll",
}
UNAPPROVED_NATIVE_TARGET_COMPONENT_IDS = frozenset({
    "cuda12-sm70",
    "tensorrt10-sm103",
    "tensorrt10-sm121",
})


@dataclass(frozen=True)
class CatalogComponent:
    component_id: str
    version: str
    dependencies: tuple[str, ...]
    object_key: str
    archive_sha256: str
    archive_size: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class SignedCatalog:
    catalog_version: str
    channel: str
    payload_bytes: bytes
    payload_sha256: str
    components: tuple[CatalogComponent, ...]


def parse_signed_payload(payload_b64: str, *, expected_channel: str) -> SignedCatalog:
    try:
        payload = base64.b64decode(payload_b64, validate=True)
    except Exception as exc:
        raise ValueError("invalid catalog payload encoding") from exc
    if not payload or len(payload) > MAX_CATALOG_BYTES:
        raise ValueError("runtime catalog payload size is invalid")
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ValueError("runtime catalog is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or int(data.get("schema_version") or 0) != 1:
        raise ValueError("unsupported runtime catalog schema")
    catalog_version = _catalog_version(data.get("catalog_version"))
    channel = _identifier(data.get("channel"), "channel")
    if channel != expected_channel:
        raise ValueError("catalog channel does not match publish channel")
    raw_components = data.get("components")
    if not isinstance(raw_components, list) or not raw_components or len(raw_components) > 100:
        raise ValueError("runtime catalog components are invalid")
    components = tuple(_component(item) for item in raw_components)
    component_ids = {item.component_id for item in components}
    if len(component_ids) != len(components):
        raise ValueError("runtime catalog must contain one version per component")
    _validate_dependency_graph(components)
    _validate_native_closure(components)
    return SignedCatalog(
        catalog_version=catalog_version,
        channel=channel,
        payload_bytes=payload,
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        components=components,
    )


def _component(value: Any) -> CatalogComponent:
    if not isinstance(value, dict):
        raise ValueError("runtime component must be an object")
    component_id = _identifier(value.get("component_id"), "component_id")
    version = _identifier(value.get("version"), "version")
    platform = str(value.get("platform") or "windows").strip().lower()
    architecture = str(value.get("architecture") or "x64").strip().lower()
    if platform != "windows" or architecture != "x64":
        raise ValueError("runtime component must target windows x64")
    _identifiers(value.get("gpu_families"), "gpu_families")
    dependencies = _identifiers(value.get("dependencies"), "dependencies")
    object_key = str(value.get("object_key") or "").replace("\\", "/").strip("/")
    path = PurePosixPath(object_key)
    if not object_key or path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid runtime component object key")
    digest = str(value.get("archive_sha256") or "").lower()
    if not SHA256.fullmatch(digest):
        raise ValueError("invalid runtime component SHA256")
    archive_size = int(value.get("archive_size") or 0)
    if archive_size <= 0 or archive_size > 2 * 1024**3:
        raise ValueError("invalid runtime component archive size")
    expanded_size = int(value.get("expanded_size") or 0)
    if expanded_size <= 0:
        raise ValueError("runtime component expanded_size must be positive")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("runtime component files must be a non-empty list")
    destinations: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("runtime component contains an invalid file entry")
        destination = _relative_path(item.get("path"))
        destination_key = destination.lower()
        if destination_key in destinations:
            raise ValueError("runtime component contains duplicate file paths")
        destinations.add(destination_key)
        if int(item.get("size") or 0) < 0:
            raise ValueError("runtime component file size must be non-negative")
        if not SHA256.fullmatch(str(item.get("sha256") or "").strip().lower()):
            raise ValueError("invalid runtime component file SHA256")
    licenses = value.get("licenses")
    if not isinstance(licenses, list) or not any(str(item).strip() for item in licenses):
        raise ValueError("runtime component licenses must be a non-empty list")
    return CatalogComponent(
        component_id,
        version,
        dependencies,
        object_key,
        digest,
        archive_size,
        value,
    )


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not IDENTIFIER.fullmatch(text):
        raise ValueError(f"invalid {label}")
    return text


def _catalog_version(value: Any) -> str:
    text = _identifier(value, "catalog_version")
    if not re.fullmatch(r"\d+(?:\.\d+)*", text):
        raise ValueError("runtime catalog version must be dotted numeric")
    return text


def _identifiers(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return tuple(_identifier(item, label) for item in value)


def _relative_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip("/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid runtime component file path")
    return path.as_posix()


def _validate_dependency_graph(components: tuple[CatalogComponent, ...]) -> None:
    latest: dict[str, CatalogComponent] = {}
    for component in components:
        current = latest.get(component.component_id)
        if current is None or _version_key(component.version) > _version_key(current.version):
            latest[component.component_id] = component
    for component in latest.values():
        missing = [dependency for dependency in component.dependencies if dependency not in latest]
        if missing:
            raise ValueError(f"missing runtime dependency: {missing[0]}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(component_id: str) -> None:
        if component_id in visited:
            return
        if component_id in visiting:
            raise ValueError("runtime component dependency cycle")
        visiting.add(component_id)
        for dependency in latest[component_id].dependencies:
            visit(dependency)
        visiting.remove(component_id)
        visited.add(component_id)

    for component_id in latest:
        visit(component_id)


def _validate_native_closure(components: tuple[CatalogComponent, ...]) -> None:
    by_id = {component.component_id: component for component in components}
    unapproved = sorted(UNAPPROVED_NATIVE_TARGET_COMPONENT_IDS & set(by_id))
    if unapproved:
        raise ValueError(f"native target is not approved for signed delivery: {unapproved[0]}")
    for component_id, builder_resource in TENSORRT_BUILDER_RESOURCE_BY_COMPONENT_ID.items():
        target = by_id.get(component_id)
        if target is None:
            continue
        closure_paths: set[str] = set()
        visited: set[str] = set()

        def visit(component: CatalogComponent) -> None:
            if component.component_id in visited:
                return
            visited.add(component.component_id)
            closure_paths.update(
                _relative_path(item.get("path")).lower()
                for item in component.raw["files"]
                if isinstance(item, dict)
            )
            for dependency_id in component.dependencies:
                visit(by_id[dependency_id])

        visit(target)
        _raise_missing(
            f"{component_id.removeprefix('tensorrt10-').upper()} TensorRT native closure",
            (
                TENSORRT_COMMON_REQUIRED_PATHS
                | {builder_resource}
            ) - closure_paths,
        )

    for component in components:
        paths = {
            _relative_path(item.get("path")).lower()
            for item in component.raw["files"]
            if isinstance(item, dict)
        }
        if component.component_id == "tensorrt10-common":
            _raise_missing(
                "TensorRT common native component",
                TENSORRT_COMMON_REQUIRED_PATHS - paths,
            )
        elif component.component_id in TENSORRT_BUILDER_RESOURCE_BY_COMPONENT_ID:
            _raise_missing(
                f"{component.component_id.removeprefix('tensorrt10-').upper()} TensorRT native component",
                {TENSORRT_BUILDER_RESOURCE_BY_COMPONENT_ID[component.component_id]} - paths,
            )


def _raise_missing(label: str, missing: set[str] | frozenset[str]) -> None:
    if missing:
        raise ValueError(f"{label} missing required file(s): {', '.join(sorted(missing))}")


def _version_key(value: str) -> tuple[int, ...]:
    parts = tuple(int(part) for part in re.findall(r"\d+", value))
    return parts or (0,)
