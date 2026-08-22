from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


ANDROID_DEBUG_CERT_SHA256 = (
    "179faf0492d0b49d66bdefcc66bc51541602525a25b8af8c4e42345a770c7155"
)
EXPECTED_ANDROID_PACKAGE = "com.visionforge.mobile"
EXPECTED_ANDROID_MODELS = (
    "lib/arm64-v8a/libvalorant_416_v11s_no_flash_w8a16.so",
    "lib/arm64-v8a/libow2_416_w8a16.so",
    "lib/arm64-v8a/libdelta_416_v8s_w8a16.so",
    "lib/arm64-v8a/libcs2_vombit_416_v8s_w8a16.so",
)
EXPECTED_QNN_HTP_RUNTIME = (
    "lib/arm64-v8a/libvisionforge_qnn_htp.so",
    "lib/arm64-v8a/libQnnHtp.so",
    "lib/arm64-v8a/libQnnHtpPrepare.so",
    "lib/arm64-v8a/libQnnHtpV68Stub.so",
    "lib/arm64-v8a/libQnnHtpV69Stub.so",
    "lib/arm64-v8a/libQnnHtpV73Stub.so",
    "lib/arm64-v8a/libQnnHtpV75Stub.so",
    "lib/arm64-v8a/libQnnHtpV79Stub.so",
    "assets/qnn/libQnnHtp.so",
    "assets/qnn/libQnnHtpV68Skel.so",
    "assets/qnn/libQnnHtpV69Skel.so",
    "assets/qnn/libQnnHtpV73Skel.so",
    "assets/qnn/libQnnHtpV75Skel.so",
    "assets/qnn/libQnnHtpV79Skel.so",
)
CS2_DEX_MARKERS = (
    "counter-strike-2-vombit-416-v8s",
    "libcs2_vombit_416_v8s_w8a16.so",
    "vf.game_model.",
    "ct_body",
    "ct_head",
    "t_body",
    "t_head",
)
CS2_NATIVE_MARKERS = (
    "counter-strike-2-vombit-416-v8s",
    "libcs2_vombit_416_v8s_w8a16.so",
    "ct_body",
    "ct_head",
    "t_body",
    "t_head",
)
FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS = (
    "forTestPrivateScalar",
    "sec1ForTestScalar",
    "finishedKeyForTest",
    "channelBindingExporterForTest",
    "AuthenticatedPeerHandshakeV1SelfTest",
    "AuthenticatedControlBootstrapRecordV1SelfTest",
    "PairGenerationProposalV1SelfTest",
    "AndroidBoundPeerHandshakeSessionSelfTest",
    "AuthenticatedPeerHandshakeV1InstrumentationProbe",
    "ANDROID_AUTHENTICATED_PEER_HANDSHAKE_V1_INSTRUMENTATION_OK",
    "AndroidBoundPeerHandshakeSessionInstrumentationProbe",
    "ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK",
    "RejectingPrivateKey",
    "fixedAgreement",
)


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    evidence: Mapping[str, Any]


def _pass(name: str, detail: str, evidence: Mapping[str, Any] | None = None) -> CheckResult:
    return CheckResult(name, True, detail, evidence or {})


def _fail(name: str, detail: str, evidence: Mapping[str, Any] | None = None) -> CheckResult:
    return CheckResult(name, False, detail, evidence or {})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_apk_zip(apk_path: Path) -> Mapping[str, Any]:
    with zipfile.ZipFile(apk_path) as archive:
        names = set(archive.namelist())
        dex_names = sorted(
            name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", name)
        )
        dex_contents = b"".join(archive.read(name) for name in dex_names)
        native_name = "lib/arm64-v8a/libvisionforge_qnn_htp.so"
        native_contents = archive.read(native_name) if native_name in names else b""
        resource_contents = archive.read("resources.arsc") if "resources.arsc" in names else b""

    required = (*EXPECTED_ANDROID_MODELS, *EXPECTED_QNN_HTP_RUNTIME)
    return {
        "entry_count": len(names),
        "required_entries": list(required),
        "missing_required_entries": [name for name in required if name not in names],
        "dex_entries": dex_names,
        "missing_cs2_dex_markers": [
            marker for marker in CS2_DEX_MARKERS if marker.encode("ascii") not in dex_contents
        ],
        "missing_cs2_native_markers": [
            marker for marker in CS2_NATIVE_MARKERS if marker.encode("ascii") not in native_contents
        ],
        "forbidden_test_seam_markers": [
            marker
            for marker in FORBIDDEN_ANDROID_RELEASE_TEST_SEAM_MARKERS
            if marker.encode("ascii") in dex_contents
        ],
        "cs2_string_resource_name_present": b"game_counter_strike_2" in resource_contents,
    }


def aapt_values_include_cs2_display_name(text: str) -> bool:
    return (
        "com.visionforge.mobile:string/game_counter_strike_2" in text
        and '(string8) "反恐精英2"' in text
    )


def parse_aapt_badging_output(text: str) -> Mapping[str, Any]:
    package_match = re.search(
        r"package: name='(?P<package>[^']+)'(?:[^\n]*versionCode='(?P<code>[^']+)')?"
        r"(?:[^\n]*versionName='(?P<name>[^']+)')?",
        text,
    )
    return {
        "package": package_match.group("package") if package_match else "",
        "version_code": package_match.group("code") if package_match else "",
        "version_name": package_match.group("name") if package_match else "",
        "debuggable": "application-debuggable" in text,
    }


def parse_apksigner_output(text: str) -> Mapping[str, Any]:
    signer_dns = re.findall(r"Signer #\d+ certificate DN: (.+)", text)
    signer_sha256 = [
        value.lower()
        for value in re.findall(
            r"Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)", text
        )
    ]
    return {
        "v1_verified": bool(re.search(r"Verified using v1 scheme \(JAR signing\): true", text)),
        "v2_verified": bool(re.search(r"Verified using v2 scheme \(APK Signature Scheme v2\): true", text)),
        "v3_verified": bool(re.search(r"Verified using v3 scheme \(APK Signature Scheme v3\): true", text)),
        "android_debug_certificate": any("CN=Android Debug" in value for value in signer_dns)
        or ANDROID_DEBUG_CERT_SHA256 in signer_sha256,
        "signer_dns": signer_dns,
        "signer_sha256": signer_sha256,
    }


def resolve_android_tool(name: str) -> Path | str:
    candidate = ROOT / ".android-sdk" / "build-tools" / "35.0.0" / name
    if candidate.exists():
        return candidate
    command = shutil.which(name) or (shutil.which(name[:-4]) if name.endswith(".bat") else None)
    if command:
        return command
    raise FileNotFoundError(f"{name} not found")


def run_text_command(command: Sequence[str | Path]) -> Mapping[str, Any]:
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    return {
        "cmd": [str(part) for part in command],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def verify_android_release_apk(
    apk_path: Path,
    *,
    require_production_signing: bool,
) -> CheckResult:
    if not apk_path.exists() or apk_path.stat().st_size <= 0:
        return _fail("android_release_apk", "Android APK is missing or empty", {"apk": str(apk_path)})
    evidence: dict[str, Any] = {
        "apk": str(apk_path),
        "size": apk_path.stat().st_size,
        "sha256": sha256_file(apk_path),
    }
    errors: list[str] = []
    try:
        zip_report = inspect_apk_zip(apk_path)
        evidence["zip"] = zip_report
        if zip_report["missing_required_entries"]:
            errors.append("APK is missing required model or QNN HTP entries")
        if zip_report["missing_cs2_dex_markers"]:
            errors.append("APK DEX is missing CS2 model, UI or target markers")
        if zip_report["missing_cs2_native_markers"]:
            errors.append("APK native bridge is missing the CS2 runtime contract")
        if zip_report["forbidden_test_seam_markers"]:
            errors.append("APK DEX contains authenticated-handshake test-only crypto seams")
        if not zip_report["cs2_string_resource_name_present"]:
            errors.append("APK resource table is missing the CS2 display entry")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"APK zip inspection failed: {exc}")

    try:
        aapt = resolve_android_tool("aapt.exe")
        aapt_result = run_text_command([aapt, "dump", "badging", apk_path])
        evidence["aapt"] = {
            "returncode": aapt_result["returncode"],
            "stderr_tail": str(aapt_result["stderr"])[-2000:],
        }
        if aapt_result["returncode"] != 0:
            errors.append("aapt badging check failed")
        else:
            badging = parse_aapt_badging_output(str(aapt_result["stdout"]))
            evidence["badging"] = badging
            if badging["package"] != EXPECTED_ANDROID_PACKAGE:
                errors.append("APK package name is not com.visionforge.mobile")
            if badging["debuggable"]:
                errors.append("APK manifest is debuggable")
        values_result = run_text_command([aapt, "dump", "--values", "resources", apk_path])
        evidence["aapt_values"] = {
            "returncode": values_result["returncode"],
            "stderr_tail": str(values_result["stderr"])[-2000:],
        }
        if values_result["returncode"] != 0:
            errors.append("aapt resource values check failed")
        elif not aapt_values_include_cs2_display_name(str(values_result["stdout"])):
            errors.append("APK does not expose the CS2 Chinese display name")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"aapt badging check could not run: {exc}")

    try:
        apksigner = resolve_android_tool("apksigner.bat")
        signer_result = run_text_command([apksigner, "verify", "--verbose", "--print-certs", apk_path])
        evidence["apksigner"] = {
            "returncode": signer_result["returncode"],
            "stderr_tail": str(signer_result["stderr"])[-2000:],
        }
        if signer_result["returncode"] != 0:
            errors.append("apksigner verification failed")
        else:
            signing = parse_apksigner_output(str(signer_result["stdout"]))
            evidence["signing"] = signing
            if not signing["v2_verified"] and not signing["v3_verified"]:
                errors.append("APK is not verified with Signature Scheme v2 or v3")
            if require_production_signing:
                if signing["v1_verified"]:
                    errors.append("production APK unexpectedly enables legacy JAR signing")
                if not signing["v3_verified"]:
                    errors.append("production APK is not verified with Signature Scheme v3")
                if len(signing["signer_sha256"]) != 1:
                    errors.append("production APK must contain exactly one current signer")
                if signing["android_debug_certificate"]:
                    errors.append("APK is signed with Android Debug certificate")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"apksigner check could not run: {exc}")

    if errors:
        evidence["errors"] = errors
        return _fail("android_release_apk", "; ".join(errors), evidence)
    return _pass("android_release_apk", "Android release APK passed static release checks", evidence)
