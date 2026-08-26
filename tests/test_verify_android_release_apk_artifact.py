from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import verify_android_release_apk_artifact as verifier  # noqa: E402
from tools.verify_formal_release_bundle import CheckResult  # noqa: E402


def test_android_release_apk_artifact_writes_success_report(tmp_path: Path) -> None:
    apk = tmp_path / "release.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "apk_preflight.json"

    report = verifier.verify_android_release_apk_artifact(
        apk_path=apk,
        output=output,
        allow_development_android_signing=False,
        verifier=lambda path, require: CheckResult(
            name="android_release_apk",
            ok=True,
            detail="ok",
            evidence={"apk": str(path), "require": require},
        ),
    )

    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema"] == verifier.SCHEMA
    assert persisted["ok"] is True
    assert persisted["require_production_signing"] is True
    assert persisted["check"]["evidence"]["require"] is True


def test_android_release_apk_artifact_rejects_debug_certificate(tmp_path: Path) -> None:
    apk = tmp_path / "debug.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "apk_preflight.json"

    report = verifier.verify_android_release_apk_artifact(
        apk_path=apk,
        output=output,
        allow_development_android_signing=False,
        verifier=lambda _path, _require: CheckResult(
            name="android_release_apk",
            ok=False,
            detail="APK is signed with Android Debug certificate",
            evidence={"errors": ["APK is signed with Android Debug certificate"]},
        ),
    )

    assert report["ok"] is False
    assert report["check"]["detail"] == "APK is signed with Android Debug certificate"
    assert "Android Debug" in output.read_text(encoding="utf-8")


def test_android_release_apk_artifact_allows_lab_development_signing(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "debug.apk"
    apk.write_bytes(b"apk")
    output = tmp_path / "apk_preflight.json"
    seen_require: list[bool] = []

    verifier.verify_android_release_apk_artifact(
        apk_path=apk,
        output=output,
        allow_development_android_signing=True,
        verifier=lambda _path, require: (
            seen_require.append(require)
            or CheckResult(
                name="android_release_apk",
                ok=True,
                detail="lab ok",
                evidence={},
            )
        ),
    )

    assert seen_require == [False]
    assert json.loads(output.read_text(encoding="utf-8"))["require_production_signing"] is False


def test_android_release_apk_artifact_main_writes_error_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk = tmp_path / "missing.apk"
    output = tmp_path / "apk_preflight.json"

    def fail(*, apk_path, output, allow_development_android_signing):  # noqa: ANN001
        raise RuntimeError("boom")

    monkeypatch.setattr(verifier, "verify_android_release_apk_artifact", fail)

    result = verifier.main(["--apk", str(apk), "--output", str(output)])

    report = json.loads(output.read_text(encoding="utf-8"))
    assert result == 1
    assert report["ok"] is False
    assert report["error"] == "boom"
