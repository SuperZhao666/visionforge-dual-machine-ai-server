from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = (
    ROOT
    / "analysis_output"
    / "mobile_qnn_benchmark_20260727_ow2_rerun"
    / "OW2_MOBILE_QNN_RERUN_REPORT.md"
)
DEFAULT_CATALOG = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "src"
    / "main"
    / "java"
    / "com"
    / "visionforge"
    / "inferencebenchmark"
    / "MobileModelCatalog.java"
)
DEFAULT_QNN_LIBRARY = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "src"
    / "main"
    / "jniLibs"
    / "arm64-v8a"
    / "libow2_416_w8a16.so"
)
DEFAULT_SERVICE = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "src"
    / "main"
    / "java"
    / "com"
    / "visionforge"
    / "inferencebenchmark"
    / "MobileRuntimeService.java"
)
DEFAULT_INFERENCE_PROFILE = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "src"
    / "main"
    / "java"
    / "com"
    / "visionforge"
    / "inferencebenchmark"
    / "InferenceProfile.java"
)
DEFAULT_CONTROL_SCREEN = (
    ROOT
    / "android_inference_benchmark"
    / "app"
    / "src"
    / "main"
    / "java"
    / "com"
    / "visionforge"
    / "inferencebenchmark"
    / "ui"
    / "ControlScreen.java"
)

EXPECTED_TOKEN = "overwatch2-416-yolov5"
EXPECTED_LIBRARY = "libow2_416_w8a16.so"
EXPECTED_INPUT = (416, 416)
EXPECTED_ANCHORS = 3549
EXPECTED_CLASSES = 2
DEFAULT_MAX_P95_MS = 5.0
DEFAULT_MIN_FINGERPRINTS = 2
DEFAULT_MIN_RUNS = 300


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


def _pass(name: str, detail: str) -> CheckResult:
    return CheckResult(name=name, ok=True, detail=detail)


def _fail(name: str, detail: str) -> CheckResult:
    return CheckResult(name=name, ok=False, detail=detail)


def parse_benchmark_text(text: str) -> dict[str, Any]:
    model_match = re.search(
        r"model=(?P<token>\S+)\s+"
        r"qnn_library=(?P<library>\S+)\s+"
        r"input=(?P<width>\d+)x(?P<height>\d+)\s+"
        r"anchors=(?P<anchors>\d+)\s+classes=(?P<classes>\d+)",
        text,
    )
    run_match = re.search(
        r"Pure graphExecute\s*\("
        r"(?P<runs>\d+)\s+runs,\s+warmup\s+(?P<warmup>\d+)\)",
        text,
    )
    mean_match = _metric_match("Mean", text)
    median_match = _metric_match("Median", text)
    p95_match = _metric_match("P95", text)
    fingerprint_match = re.search(
        r"Output fingerprints across varying inputs:\s*"
        r"(?P<unique>\d+)/(?P<total>\d+)",
        text,
    )
    missing = [
        name
        for name, match in (
            ("model contract", model_match),
            ("run count", run_match),
            ("mean metric", mean_match),
            ("median metric", median_match),
            ("p95 metric", p95_match),
            ("output fingerprints", fingerprint_match),
        )
        if match is None
    ]
    if missing:
        raise ValueError("missing OW2 benchmark fields: " + ", ".join(missing))

    assert model_match is not None
    assert run_match is not None
    assert mean_match is not None
    assert median_match is not None
    assert p95_match is not None
    assert fingerprint_match is not None
    return {
        "token": model_match.group("token"),
        "library": model_match.group("library"),
        "input_width": int(model_match.group("width")),
        "input_height": int(model_match.group("height")),
        "anchors": int(model_match.group("anchors")),
        "classes": int(model_match.group("classes")),
        "runs": int(run_match.group("runs")),
        "warmup": int(run_match.group("warmup")),
        "mean_ms": float(mean_match.group("ms")),
        "mean_fps": float(mean_match.group("fps")),
        "median_ms": float(median_match.group("ms")),
        "median_fps": float(median_match.group("fps")),
        "p95_ms": float(p95_match.group("ms")),
        "p95_fps": float(p95_match.group("fps")),
        "fingerprint_unique": int(fingerprint_match.group("unique")),
        "fingerprint_total": int(fingerprint_match.group("total")),
        "qnn_htp": (
            "Backend: QNN HTP" in text
            or "backend=QNN HTP" in text
        ),
        "app_native_qnn": "App-native QNN evidence" in text,
        "precision_w8a16": "precision=W8A16" in text,
        "benchmark_ok": "MOBILE_QNN_BENCHMARK_OK" in text,
    }


def check_ow2_mobile_qnn_benchmark(
    *,
    report_path: Path = DEFAULT_REPORT,
    catalog_path: Path = DEFAULT_CATALOG,
    qnn_library_path: Path = DEFAULT_QNN_LIBRARY,
    service_path: Path = DEFAULT_SERVICE,
    inference_profile_path: Path = DEFAULT_INFERENCE_PROFILE,
    control_screen_path: Path = DEFAULT_CONTROL_SCREEN,
    max_p95_ms: float = DEFAULT_MAX_P95_MS,
    min_fingerprints: int = DEFAULT_MIN_FINGERPRINTS,
    min_runs: int = DEFAULT_MIN_RUNS,
) -> tuple[dict[str, Any], tuple[CheckResult, ...]]:
    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    catalog_text = catalog_path.read_text(encoding="utf-8", errors="replace")
    service_text = service_path.read_text(encoding="utf-8", errors="replace")
    inference_profile_text = inference_profile_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    control_screen_text = control_screen_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    summary = parse_benchmark_text(report_text)
    production_body = _production_selectable_body(catalog_text)
    checks = [
        _check_equal("token", summary["token"], EXPECTED_TOKEN),
        _check_equal("library", summary["library"], EXPECTED_LIBRARY),
        _check_equal(
            "input-shape",
            (summary["input_width"], summary["input_height"]),
            EXPECTED_INPUT,
        ),
        _check_equal("anchors", summary["anchors"], EXPECTED_ANCHORS),
        _check_equal("classes", summary["classes"], EXPECTED_CLASSES),
        _check_at_least("measured-runs", summary["runs"], min_runs),
        _check_at_most("p95-ms", summary["p95_ms"], max_p95_ms),
        _check_at_least(
            "output-fingerprints",
            summary["fingerprint_unique"],
            min_fingerprints,
        ),
        _check_true("qnn-htp-backend", bool(summary["qnn_htp"])),
        _check_true("app-native-qnn-evidence", bool(summary["app_native_qnn"])),
        _check_true("w8a16-precision", bool(summary["precision_w8a16"])),
        _check_true("benchmark-ok", bool(summary["benchmark_ok"])),
        _check_true(
            "catalog-token",
            f'"{EXPECTED_TOKEN}"' in catalog_text,
        ),
        _check_true(
            "catalog-library",
            f'"{EXPECTED_LIBRARY}"' in catalog_text,
        ),
        _check_true(
            "production-list-includes-ow2",
            "OVERWATCH_2" in production_body
            and "VALORANT" in production_body
            and "DELTA_FORCE" in production_body,
        ),
        _check_true(
            "service-production-token-gate",
            "forProductionToken(modelToken)" in service_text
            and "isProductionSelectable(selected)" in service_text,
        ),
        _check_true(
            "profile-production-token-restore",
            "forProductionToken(store.getString" in inference_profile_text
            and "isProductionSelectable(selected)" in inference_profile_text,
        ),
        _check_true(
            "control-screen-production-list",
            "MobileModelCatalog.PRODUCTION_SELECTABLE" in control_screen_text
            and "MobileModelCatalog.OVERWATCH_2" not in control_screen_text,
        ),
        _check_true(
            "packaged-library",
            qnn_library_path.is_file() and qnn_library_path.stat().st_size > 0,
        ),
    ]
    summary["report_path"] = str(report_path)
    summary["catalog_path"] = str(catalog_path)
    summary["qnn_library_path"] = str(qnn_library_path)
    summary["service_path"] = str(service_path)
    summary["inference_profile_path"] = str(inference_profile_path)
    summary["control_screen_path"] = str(control_screen_path)
    summary["ok"] = all(check.ok for check in checks)
    return summary, tuple(checks)


def _metric_match(label: str, text: str) -> re.Match[str] | None:
    return re.search(
        rf"{label}:\s*(?P<ms>\d+(?:\.\d+)?)\s*ms\s*/\s*"
        rf"(?P<fps>\d+(?:\.\d+)?)\s*FPS",
        text,
    )


def _production_selectable_body(catalog_text: str) -> str:
    match = re.search(
        r"PRODUCTION_SELECTABLE\s*=\s*\{(?P<body>[^}]+)\}",
        catalog_text,
        re.DOTALL,
    )
    return match.group("body") if match else ""


def _check_equal(name: str, actual: object, expected: object) -> CheckResult:
    if actual == expected:
        return _pass(name, f"{actual!r}")
    return _fail(name, f"expected {expected!r}, got {actual!r}")


def _check_at_least(name: str, actual: float, minimum: float) -> CheckResult:
    if actual >= minimum:
        return _pass(name, f"{actual} >= {minimum}")
    return _fail(name, f"expected >= {minimum}, got {actual}")


def _check_at_most(name: str, actual: float, maximum: float) -> CheckResult:
    if actual <= maximum:
        return _pass(name, f"{actual} <= {maximum}")
    return _fail(name, f"expected <= {maximum}, got {actual}")


def _check_true(name: str, actual: bool) -> CheckResult:
    if actual:
        return _pass(name, "present")
    return _fail(name, "missing")


def _text_report(
    summary: Mapping[str, Any],
    checks: Sequence[CheckResult],
) -> str:
    lines = [
        "VisionForge OW2 mobile QNN benchmark verification:",
        f"- status: {'PASS' if summary['ok'] else 'FAIL'}",
        f"- model: {summary['token']} / {summary['library']}",
        (
            f"- graphExecute: mean={summary['mean_ms']:.2f} ms, "
            f"median={summary['median_ms']:.2f} ms, "
            f"p95={summary['p95_ms']:.2f} ms"
        ),
        (
            f"- fingerprints: {summary['fingerprint_unique']}/"
            f"{summary['fingerprint_total']}"
        ),
    ]
    for check in checks:
        state = "PASS" if check.ok else "FAIL"
        lines.append(f"- [{state}] {check.name}: {check.detail}")
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the OW2 Android App-native QNN HTP benchmark evidence."
        ),
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--qnn-library", type=Path, default=DEFAULT_QNN_LIBRARY)
    parser.add_argument("--service", type=Path, default=DEFAULT_SERVICE)
    parser.add_argument(
        "--inference-profile",
        type=Path,
        default=DEFAULT_INFERENCE_PROFILE,
    )
    parser.add_argument(
        "--control-screen",
        type=Path,
        default=DEFAULT_CONTROL_SCREEN,
    )
    parser.add_argument("--max-p95-ms", type=float, default=DEFAULT_MAX_P95_MS)
    parser.add_argument(
        "--min-fingerprints",
        type=int,
        default=DEFAULT_MIN_FINGERPRINTS,
    )
    parser.add_argument("--min-runs", type=int, default=DEFAULT_MIN_RUNS)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        summary, checks = check_ow2_mobile_qnn_benchmark(
            report_path=args.report,
            catalog_path=args.catalog,
            qnn_library_path=args.qnn_library,
            service_path=args.service,
            inference_profile_path=args.inference_profile,
            control_screen_path=args.control_screen,
            max_p95_ms=args.max_p95_ms,
            min_fingerprints=args.min_fingerprints,
            min_runs=args.min_runs,
        )
    except Exception as exc:
        print(f"verify_ow2_mobile_qnn_benchmark.py: error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(_text_report(summary, checks))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
