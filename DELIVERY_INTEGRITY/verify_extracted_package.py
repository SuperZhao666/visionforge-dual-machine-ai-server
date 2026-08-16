#!/usr/bin/env python3
"""Verify an extracted VisionForge delivery against its internal manifest."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EXCLUDED = {"MANIFEST_SHA256.json", "SHA256SUMS.txt"}
FONT_SUFFIXES = {".ttf", ".otf", ".woff", ".woff2", ".eot"}
PRIVATE_MARKERS = tuple(
    b"-----BEGIN " + prefix + b"PRIVATE KEY-----"
    for prefix in (b"", b"RSA ", b"EC ", b"OPENSSH ", b"ENCRYPTED ")
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
    manifest_path = root / "MANIFEST_SHA256.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {item["path"]: item for item in manifest["files"]}

    actual: dict[str, Path] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SystemExit(f"FAIL: symbolic link is not allowed: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in EXCLUDED or "__pycache__/" in f"{rel}/" or rel.endswith(".pyc"):
            continue
        actual[rel] = path

    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    if missing or unexpected:
        raise SystemExit(f"FAIL: file-set mismatch missing={missing[:10]} unexpected={unexpected[:10]}")

    for rel, item in expected.items():
        path = actual[rel]
        if path.stat().st_size != item["size_bytes"]:
            raise SystemExit(f"FAIL: size mismatch: {rel}")
        if sha256_file(path) != item["sha256"]:
            raise SystemExit(f"FAIL: sha256 mismatch: {rel}")
        if path.suffix.lower() in FONT_SUFFIXES:
            raise SystemExit(f"FAIL: font binary present: {rel}")
        if path.stat().st_size <= 16 * 1024 * 1024:
            data = path.read_bytes()
            if any(marker in data for marker in PRIVATE_MARKERS):
                raise SystemExit(f"FAIL: private-key material present: {rel}")

    required = {
        "android_inference_benchmark/app/src/main/jniLibs": 100_000_000,
        "android_inference_benchmark/app/src/main/assets/qnn": 40_000_000,
        "security-defense/vendor": 5_000_000,
        "server/visionforge-platform/deploy/xianyu-fulfillment/upstream": 1_000_000,
    }
    for rel, minimum in required.items():
        directory = root / rel
        total = sum(p.stat().st_size for p in directory.rglob("*") if p.is_file())
        if total < minimum:
            raise SystemExit(f"FAIL: essential asset tree is incomplete: {rel} ({total} bytes)")

    bundle = root / "DELIVERY_INTEGRITY/VisionForge_MINGSIM_FULL_HISTORY.bundle"
    with tempfile.TemporaryDirectory(prefix="visionforge-bundle-verify-") as temp_dir:
        bare_repo = Path(temp_dir) / "repo.git"
        clone = subprocess.run(
            ["git", "clone", "--bare", str(bundle), str(bare_repo)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if clone.returncode != 0:
            raise SystemExit("FAIL: Git bundle cannot be cloned")
        fsck = subprocess.run(
            ["git", "-C", str(bare_repo), "fsck", "--strict"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if fsck.returncode != 0:
            raise SystemExit("FAIL: Git bundle object verification failed")

    print(json.dumps({
        "status": "PASS",
        "root": str(root),
        "verified_files": len(expected),
        "logical_bytes": sum(item["size_bytes"] for item in expected.values()),
        "manifest_sha256": sha256_file(manifest_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
