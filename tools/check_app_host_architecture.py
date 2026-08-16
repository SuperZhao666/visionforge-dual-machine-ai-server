#!/usr/bin/env python3
"""Enforce VisionForge Android App / Windows Host architectural boundaries.

The checker intentionally inspects production paths, not only sample modules.
It fails closed when a required boundary disappears or a historically dangerous
concrete type leaks back into UI/application headers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Iterable

JAVA_IMPORT = re.compile(r"^\s*import\s+([\w.]+)\s*;", re.MULTILINE)
CPP_INCLUDE = re.compile(r'^\s*#include\s+[<\"]([^>\"]+)[>\"]', re.MULTILINE)

REQUIRED_FILES = (
    "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/runtime/MobileRuntimeBinding.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/runtime/MobileRuntimeCommandProtocol.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/runtime/MobileRuntimeReadModel.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/MobileRuntimeCompositionRoot.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/VideoPreflightReassemblyWindow.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/video/VideoFragmentHeader.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/control/ExactCommandTicket.java",
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/control/PostAckVisibilityGate.java",
    "dual_machine_runtime/host/windows/include/vfdual/host/application/host_runtime_facade.hpp",
    "dual_machine_runtime/host/windows/include/vfdual/host/application/host_runtime_models.hpp",
    "dual_machine_runtime/host/windows/include/vfdual/host/domain/capture_region.hpp",
    "dual_machine_runtime/e2e_core/include/vf/host/interfaces/host_runtime_composition_root.hpp",
    "dual_machine_runtime/e2e_core/include/vf/host/application/host_streaming_orchestrator.hpp",
    "dual_machine_runtime/e2e_core/include/vf/host/domain/video_pipeline_status.hpp",
    "dual_machine_runtime/shared/include/vfdual/video_transport_contract.hpp",
)

COMPLEXITY_BUDGETS = {
    "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java": 6500,
    "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MainActivity.java": 1250,
    "android_inference_benchmark/app/src/main/cpp/DualMachineReceiver.cpp": 1450,
    "dual_machine_runtime/host/windows/src/streamer_desktop_app.cpp": 2150,
    "dual_machine_runtime/host/windows/src/host_runtime_service.cpp": 2180,
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/MobileRuntimeCompositionRoot.java": 500,
    "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/VideoPreflightReassemblyWindow.java": 450,
}


def _read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def _failure(failures: list[dict[str, str]], path: str, rule: str, detail: str = "") -> None:
    item = {"path": path, "rule": rule}
    if detail:
        item["detail"] = detail
    failures.append(item)


def _forbid_tokens(
    failures: list[dict[str, str]], root: Path, relative: str,
    tokens: Iterable[str], rule: str,
) -> None:
    path = root / relative
    if not path.is_file():
        _failure(failures, relative, "required file missing")
        return
    text = path.read_text(encoding="utf-8")
    for token in tokens:
        if token in text:
            _failure(failures, relative, rule, token)


def _audit_mobile_layers(root: Path, failures: list[dict[str, str]]) -> int:
    source_root = root / "android_inference_benchmark/app/src/main/java/com/visionforge/mobile"
    checked = 0
    if not source_root.is_dir():
        _failure(failures, source_root.relative_to(root).as_posix(), "mobile layered source root missing")
        return checked
    for path in sorted(source_root.rglob("*.java")):
        checked += 1
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        imports = JAVA_IMPORT.findall(text)
        parts = path.relative_to(source_root).parts
        layer = parts[0] if parts else ""
        if layer in {"domain", "ports", "core", "application"}:
            for imported in imports:
                if imported.startswith(("android.", "androidx.", "okhttp3.", "retrofit2.")):
                    _failure(failures, relative, "portable mobile layer depends on Android/network adapter", imported)
        for imported in imports:
            if not imported.startswith("com.visionforge.mobile."):
                continue
            target = imported.split(".")[3] if len(imported.split(".")) > 3 else ""
            if layer == "domain" and target in {"application", "core", "ports", "infrastructure", "interfaces"}:
                _failure(failures, relative, "mobile domain has reverse dependency", imported)
            elif layer == "ports" and target in {"application", "core", "infrastructure", "interfaces"}:
                _failure(failures, relative, "mobile port has reverse dependency", imported)
            elif layer == "application" and target in {"infrastructure", "interfaces"}:
                _failure(failures, relative, "mobile application depends on adapter/interface", imported)
    return checked


def _audit_video_package(root: Path, failures: list[dict[str, str]]) -> int:
    source_root = root / "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/video"
    checked = 0
    if not source_root.is_dir():
        _failure(failures, source_root.relative_to(root).as_posix(), "App video protocol package missing")
        return checked
    forbidden_import_prefixes = ("android.", "androidx.")
    forbidden_import_types = (
        "com.visionforge.inferencebenchmark.MobileRuntimeService",
        "com.visionforge.inferencebenchmark.MainActivity",
        "com.visionforge.inferencebenchmark.QnnHtpBridge",
    )
    for path in sorted(source_root.rglob("*.java")):
        checked += 1
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(root).as_posix()
        for imported in JAVA_IMPORT.findall(text):
            if imported.startswith(forbidden_import_prefixes) or imported in forbidden_import_types:
                _failure(failures, relative, "video protocol package depends on UI/service/device implementation", imported)
    return checked


def _audit_host_e2e_layers(root: Path, failures: list[dict[str, str]]) -> int:
    base = root / "dual_machine_runtime/e2e_core"
    checked = 0
    for source_root in (base / "include/vf/host", base / "src/host"):
        if not source_root.is_dir():
            _failure(failures, source_root.relative_to(root).as_posix(), "Host layered source root missing")
            continue
        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or path.suffix not in {".hpp", ".h", ".cpp", ".cc", ".cxx"}:
                continue
            checked += 1
            relative = path.relative_to(root).as_posix()
            rel_parts = path.relative_to(source_root).parts
            layer = rel_parts[0] if rel_parts else ""
            for include in CPP_INCLUDE.findall(path.read_text(encoding="utf-8")):
                match = re.match(r"vf/host/(domain|application|infrastructure|interfaces)/", include)
                target = match.group(1) if match else ""
                forbidden: set[str] = set()
                if layer == "domain":
                    forbidden = {"application", "infrastructure", "interfaces"}
                elif layer == "application":
                    forbidden = {"infrastructure", "interfaces"}
                elif layer == "infrastructure":
                    forbidden = {"application", "interfaces"}
                if target in forbidden:
                    _failure(failures, relative, f"Host {layer} layer has reverse dependency", include)
    return checked


def audit(root: Path) -> dict[str, Any]:
    root = root.resolve()
    failures: list[dict[str, str]] = []

    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            _failure(failures, relative, "required architecture file missing")

    _forbid_tokens(
        failures, root,
        "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MainActivity.java",
        ("MobileRuntimeService.LocalBinder", "MobileRuntimeService.Phase", "MobileRuntimeService.RuntimeStatus"),
        "Activity depends on Service private implementation",
    )
    _forbid_tokens(
        failures, root,
        "dual_machine_runtime/host/windows/include/vfdual/streamer_desktop_app.hpp",
        ("host_runtime_service.hpp", "cat6_session", "dxgi", "d3d", "nvenc", "winsock", "SOCKET"),
        "Host UI header exposes infrastructure implementation",
    )
    _forbid_tokens(
        failures, root,
        "dual_machine_runtime/host/windows/include/vfdual/host_ui_telemetry.hpp",
        ("host_runtime_service.hpp", "cat6_session", "dxgi", "d3d", "nvenc", "winsock", "SOCKET"),
        "Host telemetry header exposes infrastructure implementation",
    )
    for relative in (
        "dual_machine_runtime/host/windows/include/vfdual/host/application/host_runtime_facade.hpp",
        "dual_machine_runtime/host/windows/include/vfdual/host/application/host_runtime_models.hpp",
        "dual_machine_runtime/host/windows/include/vfdual/host/application/host_endpoint_discovery_facade.hpp",
    ):
        _forbid_tokens(
            failures, root, relative,
            ("windows.h", "dxgi.h", "d3d11.h", "nvEncodeAPI.h", "winsock2.h", "SOCKET", "HostRuntimeService", "Cat6SessionSnapshot"),
            "Host application boundary exposes platform type",
        )

    shared_protocol = _read(root, "dual_machine_runtime/shared/include/vfdual/protocol.hpp")
    for token in ("windows.h", "jni.h", "android/", "dxgi", "d3d", "winsock"):
        if token in shared_protocol.lower():
            _failure(failures, "dual_machine_runtime/shared/include/vfdual/protocol.hpp",
                     "shared protocol depends on platform implementation", token)

    complexity: dict[str, dict[str, int | str]] = {}
    for relative, budget in COMPLEXITY_BUDGETS.items():
        path = root / relative
        if not path.is_file():
            _failure(failures, relative, "complexity-budget file missing")
            continue
        lines = len(path.read_text(encoding="utf-8").splitlines())
        complexity[relative] = {"lines": lines, "budget": budget, "status": "PASS" if lines <= budget else "FAIL"}
        if lines > budget:
            _failure(failures, relative, "source exceeds hard line budget", f"{lines}>{budget}")

    mobile_checked = _audit_mobile_layers(root, failures)
    video_checked = _audit_video_package(root, failures)
    host_checked = _audit_host_e2e_layers(root, failures)

    report = {
        "schema_version": "visionforge.app-host-architecture-audit.v2",
        "status": "PASS" if not failures else "FAIL",
        "required_files_checked": len(REQUIRED_FILES),
        "mobile_layer_files_checked": mobile_checked,
        "app_video_files_checked": video_checked,
        "host_layer_files_checked": host_checked,
        "complexity_budgets": complexity,
        "dependency_direction": {
            "android": "UI -> stable ports/read model -> application -> domain/ports -> adapters",
            "host": "UI -> facade/DTO -> application -> domain/ports -> infrastructure",
        },
        "failures": failures,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.root)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
