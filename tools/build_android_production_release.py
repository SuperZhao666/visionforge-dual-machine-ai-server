from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_android_production_signing_inputs import (  # noqa: E402
    verify_android_production_signing_inputs,
    write_report as write_signing_report,
)
from tools.verify_formal_release_bundle import (  # noqa: E402
    CheckResult,
    sha256_file,
    verify_android_release_apk,
)


SCHEMA = "visionforge-android-production-release-build-v1"
PRIVATE_SYMBOLS_SCHEMA = "visionforge-android-private-r8-symbols-v1"
ANDROID_PROJECT_ROOT = ROOT / "android_inference_benchmark"
DEFAULT_APK = (
    ANDROID_PROJECT_ROOT
    / "app"
    / "build"
    / "outputs"
    / "apk"
    / "release"
    / "app-release.apk"
)
DEFAULT_R8_MAPPING = (
    ANDROID_PROJECT_ROOT
    / "app"
    / "build"
    / "outputs"
    / "mapping"
    / "release"
    / "mapping.txt"
)


def _default_private_symbols_dir() -> Path:
    local_app_data = str(os.environ.get("LOCALAPPDATA") or "").strip()
    owner_root = Path(local_app_data) if local_app_data else Path.home() / ".visionforge"
    return owner_root / "VisionForge" / "private-release-symbols" / "android"


DEFAULT_PRIVATE_SYMBOLS_DIR = _default_private_symbols_dir()


@dataclass(frozen=True, slots=True)
class CommandResult:
    cmd: tuple[str, ...]
    cwd: str
    returncode: int
    stdout: str
    stderr: str


class ApkVerifier(Protocol):
    def __call__(self, apk_path: Path, *, require_production_signing: bool) -> CheckResult:
        ...


CommandRunner = Callable[[Sequence[str], Path, int], CommandResult]
SigningChecker = Callable[[Path], Mapping[str, Any]]


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _tail(text: str, limit: int = 12000) -> str:
    return text[-limit:]


def run_command(
    command: Sequence[str],
    cwd: Path,
    timeout_sec: int,
) -> CommandResult:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return CommandResult(
        cmd=tuple(str(part) for part in command),
        cwd=str(cwd),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_signing_preflight(output: Path) -> Mapping[str, Any]:
    report = verify_android_production_signing_inputs()
    write_signing_report(report, output)
    return report


def gradle_release_command() -> list[str]:
    return [
        "cmd",
        "/c",
        "gradlew.bat",
        "-PvisionforgeFormalSecureDataPlaneOnly=true",
        ":app:verifyMobileRuntimeSnapshot",
        ":app:assembleRelease",
        "--offline",
    ]


def _command_json(result: CommandResult | None) -> Mapping[str, Any] | None:
    if result is None:
        return None
    return {
        "cmd": list(result.cmd),
        "cwd": result.cwd,
        "returncode": result.returncode,
        "stdout_tail": _tail(result.stdout),
        "stderr_tail": _tail(result.stderr),
    }


def _check_json(result: CheckResult | None) -> Mapping[str, Any] | None:
    if result is None:
        return None
    return asdict(result)


def _signing_errors(signing_report: Mapping[str, Any] | None) -> list[str]:
    if signing_report is None:
        return []
    errors = signing_report.get("errors")
    if not isinstance(errors, Sequence) or isinstance(errors, (str, bytes)):
        return []
    return [str(error) for error in errors if str(error).strip()]


def _signing_required_env(signing_report: Mapping[str, Any] | None) -> list[str]:
    if signing_report is None:
        return [
            "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
            "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
            "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
            "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
        ]
    env_names = signing_report.get("env_names")
    if not isinstance(env_names, Mapping):
        return [
            "VISIONFORGE_ANDROID_RELEASE_STORE_FILE",
            "VISIONFORGE_ANDROID_RELEASE_STORE_PASSWORD",
            "VISIONFORGE_ANDROID_RELEASE_KEY_ALIAS",
            "VISIONFORGE_ANDROID_RELEASE_KEY_PASSWORD",
        ]
    required: list[str] = []
    for key in ("store_file", "store_password", "key_alias", "key_password"):
        value = str(env_names.get(key) or "").strip()
        if value:
            required.append(value)
    return required


def _build_next_actions(
    *,
    stage: str,
    signing_report: Mapping[str, Any] | None,
) -> list[Mapping[str, object]]:
    if stage != "android_signing_preflight":
        return []
    return [
        {
            "stage": stage,
            "action": (
                "Set production Android release signing environment variables "
                "before building the release APK."
            ),
            "required_env": _signing_required_env(signing_report),
            "command": (
                "python tools\\create_android_release_keystore.py "
                "--output-dir C:\\secure\\visionforge-android-release"
            ),
        }
    ]


def _safe_version(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("._-") or "unknown"


def _artifact_name(apk_result: CheckResult, timestamp: str) -> str:
    badging = apk_result.evidence.get("badging", {})
    version = "unknown"
    if isinstance(badging, Mapping):
        version = str(badging.get("version_name") or "unknown")
    return f"VFMobile_{_safe_version(version)}_{timestamp}.apk"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _certificate_sha256(signing_report: Mapping[str, Any]) -> str:
    signing = signing_report.get("signing")
    if not isinstance(signing, Mapping):
        return ""
    digest = str(signing.get("certificate_sha256") or "").strip().lower()
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else ""


def _apk_signer_sha256(apk_result: CheckResult) -> str:
    signing = apk_result.evidence.get("signing")
    if not isinstance(signing, Mapping):
        return ""
    signers = signing.get("signer_sha256")
    if not isinstance(signers, Sequence) or isinstance(signers, (str, bytes)):
        return ""
    normalized = [str(value).strip().lower() for value in signers]
    if len(normalized) != 1 or not re.fullmatch(r"[0-9a-f]{64}", normalized[0]):
        return ""
    return normalized[0]


def write_private_symbols_report(
    *,
    output: Path,
    apk_path: Path,
    apk_sha256: str,
    mapping_path: Path,
    mapping_sha256_path: Path,
    mapping_sha256: str,
) -> None:
    report = {
        "schema": PRIVATE_SYMBOLS_SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "apk_name": apk_path.name,
        "apk_sha256": apk_sha256,
        "mapping": str(mapping_path),
        "mapping_sha256_file": str(mapping_sha256_path),
        "mapping_sha256": mapping_sha256,
        "mapping_size": mapping_path.stat().st_size,
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def write_build_report(
    *,
    output: Path,
    ok: bool,
    stage: str,
    signing_report_path: Path,
    signing_report: Mapping[str, Any] | None,
    gradle: CommandResult | None,
    apk_result: CheckResult | None,
    artifact: Mapping[str, Any] | None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": ok,
        "stage": stage,
        "signing_report_path": str(signing_report_path),
        "signing_report_ok": (
            bool(signing_report.get("ok")) if signing_report is not None else None
        ),
        "signing_errors": _signing_errors(signing_report),
        "next_actions": _build_next_actions(
            stage=stage,
            signing_report=signing_report,
        ),
        "gradle": _command_json(gradle),
        "apk_verification": _check_json(apk_result),
        "artifact": artifact,
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def build_android_production_release(
    *,
    output_dir: Path,
    apk_path: Path = DEFAULT_APK,
    r8_mapping_path: Path = DEFAULT_R8_MAPPING,
    private_symbols_dir: Path = DEFAULT_PRIVATE_SYMBOLS_DIR,
    report_path: Path | None = None,
    gradle_timeout_sec: int = 1200,
    signing_checker: SigningChecker = run_signing_preflight,
    runner: CommandRunner = run_command,
    apk_verifier: ApkVerifier = verify_android_release_apk,
    test_only_allow_noncanonical_inputs: bool = False,
) -> int:
    output_dir = output_dir.resolve()
    apk_path = apk_path.resolve()
    r8_mapping_path = r8_mapping_path.resolve()
    private_symbols_dir = private_symbols_dir.resolve()
    if _is_relative_to(private_symbols_dir, output_dir):
        raise ValueError(
            "private R8 symbols directory must not be inside the distributable output directory"
        )
    if _is_relative_to(private_symbols_dir, ROOT.resolve()):
        raise ValueError("private R8 symbols directory must be outside the repository")
    if not test_only_allow_noncanonical_inputs:
        if apk_path != DEFAULT_APK.resolve() or r8_mapping_path != DEFAULT_R8_MAPPING.resolve():
            raise ValueError(
                "production build must consume the canonical release APK and R8 mapping outputs"
            )
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    report = report_path or output_dir / "android_production_release_build.json"
    signing_report_path = output_dir / "android_production_signing_inputs.json"

    signing_report = signing_checker(signing_report_path)
    if not signing_report.get("ok"):
        write_build_report(
            output=report,
            ok=False,
            stage="android_signing_preflight",
            signing_report_path=signing_report_path,
            signing_report=signing_report,
            gradle=None,
            apk_result=None,
            artifact=None,
        )
        print(f"[ERROR] Android production signing preflight failed; report={report}", flush=True)
        return 2

    if not test_only_allow_noncanonical_inputs:
        # Remove only the two exact generated outputs. Their reappearance binds
        # the verified APK and mapping to this Gradle invocation instead of a
        # stale or caller-supplied artifact.
        apk_path.unlink(missing_ok=True)
        r8_mapping_path.unlink(missing_ok=True)
    gradle = runner(gradle_release_command(), ANDROID_PROJECT_ROOT, gradle_timeout_sec)
    if gradle.returncode != 0:
        write_build_report(
            output=report,
            ok=False,
            stage="gradle_release_build",
            signing_report_path=signing_report_path,
            signing_report=signing_report,
            gradle=gradle,
            apk_result=None,
            artifact=None,
        )
        print(f"[ERROR] Android release Gradle build failed; report={report}", flush=True)
        return 3

    if not r8_mapping_path.is_file() or r8_mapping_path.stat().st_size == 0:
        write_build_report(
            output=report,
            ok=False,
            stage="r8_mapping_verification",
            signing_report_path=signing_report_path,
            signing_report=signing_report,
            gradle=gradle,
            apk_result=None,
            artifact={
                "r8_mapping_source": str(r8_mapping_path),
                "error": "R8 mapping.txt is missing or empty",
            },
        )
        print(f"[ERROR] R8 mapping.txt is missing; report={report}", flush=True)
        return 4

    apk_result = apk_verifier(apk_path, require_production_signing=True)
    if not apk_result.ok:
        write_build_report(
            output=report,
            ok=False,
            stage="android_apk_static_verification",
            signing_report_path=signing_report_path,
            signing_report=signing_report,
            gradle=gradle,
            apk_result=apk_result,
            artifact=None,
        )
        print(f"[ERROR] Android APK static release verification failed; report={report}", flush=True)
        return 5

    expected_signer = _certificate_sha256(signing_report)
    actual_signer = _apk_signer_sha256(apk_result)
    if not expected_signer or actual_signer != expected_signer:
        write_build_report(
            output=report,
            ok=False,
            stage="android_signer_provenance",
            signing_report_path=signing_report_path,
            signing_report=signing_report,
            gradle=gradle,
            apk_result=apk_result,
            artifact=None,
        )
        print(
            f"[ERROR] Android APK signer does not match signing preflight; report={report}",
            flush=True,
        )
        return 6

    artifact_path = output_dir / _artifact_name(apk_result, timestamp)
    shutil.copy2(apk_path, artifact_path)
    digest = sha256_file(artifact_path)
    sha_path = artifact_path.with_suffix(artifact_path.suffix + ".sha256")
    sha_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")

    private_symbols_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        private_symbols_dir.chmod(0o700)
    mapping_artifact = private_symbols_dir / f"{artifact_path.stem}.mapping.txt"
    shutil.copy2(r8_mapping_path, mapping_artifact)
    mapping_digest = sha256_file(mapping_artifact)
    mapping_sha_path = mapping_artifact.with_suffix(mapping_artifact.suffix + ".sha256")
    mapping_sha_path.write_text(
        f"{mapping_digest}  {mapping_artifact.name}\n",
        encoding="utf-8",
    )
    private_symbols_report = private_symbols_dir / f"{artifact_path.stem}.symbols.json"
    write_private_symbols_report(
        output=private_symbols_report,
        apk_path=artifact_path,
        apk_sha256=digest,
        mapping_path=mapping_artifact,
        mapping_sha256_path=mapping_sha_path,
        mapping_sha256=mapping_digest,
    )
    if os.name != "nt":
        for private_file in (mapping_artifact, mapping_sha_path, private_symbols_report):
            private_file.chmod(0o600)
    artifact = {
        "apk": str(artifact_path),
        "sha256_file": str(sha_path),
        "sha256": digest,
        "size": artifact_path.stat().st_size,
        "source_apk": str(apk_path),
    }
    write_build_report(
        output=report,
        ok=True,
        stage="complete",
        signing_report_path=signing_report_path,
        signing_report=signing_report,
        gradle=gradle,
        apk_result=apk_result,
        artifact=artifact,
    )
    print(f"[OK] Android production release APK built; report={report}", flush=True)
    print(f"[OK] apk={artifact_path}", flush=True)
    print(f"[OK] sha256={digest}", flush=True)
    print("[OK] private R8 symbols archived outside the release directory", flush=True)
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "releases" / "android",
    )
    parser.add_argument(
        "--private-symbols-dir",
        type=Path,
        default=DEFAULT_PRIVATE_SYMBOLS_DIR,
    )
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--gradle-timeout-sec", type=int, default=1200)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    return build_android_production_release(
        output_dir=args.output_dir.resolve(),
        private_symbols_dir=args.private_symbols_dir,
        report_path=args.report.resolve() if args.report else None,
        gradle_timeout_sec=args.gradle_timeout_sec,
    )


if __name__ == "__main__":
    _configure_utf8_stdio()
    raise SystemExit(main())
