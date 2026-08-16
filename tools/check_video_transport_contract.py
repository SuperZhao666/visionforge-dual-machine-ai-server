#!/usr/bin/env python3
"""Fail closed when Host/App video identity, publication, or recovery semantics drift."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

PATHS = {
    "cpp_header": "dual_machine_runtime/shared/include/vfdual/protocol.hpp",
    "cpp_codec": "dual_machine_runtime/shared/src/protocol.cpp",
    "cpp_reassembler_h": "dual_machine_runtime/shared/include/vfdual/access_unit_reassembler.hpp",
    "cpp_reassembler": "dual_machine_runtime/shared/src/access_unit_reassembler.cpp",
    "epoch_session": "dual_machine_runtime/shared/include/vfdual/receiver_epoch_session.hpp",
    "epoch_contract_h": "dual_machine_runtime/shared/include/vfdual/video_transport_contract.hpp",
    "publisher_h": "dual_machine_runtime/host/windows/include/vfdual/udp_video_publisher.hpp",
    "desktop_agent": "dual_machine_runtime/host/windows/src/desktop_video_agent.cpp",
    "hybrid_pipeline": "dual_machine_runtime/host/windows/src/hybrid_gpu_video_pipeline.cpp",
    "host_runtime": "dual_machine_runtime/host/windows/src/host_runtime_service.cpp",
    "epoch_store_h": "dual_machine_runtime/e2e_core/include/vf/host/infrastructure/file_epoch_reservation_store.hpp",
    "epoch_store_cpp": "dual_machine_runtime/e2e_core/src/host/infrastructure/file_epoch_reservation_store.cpp",
    "receiver": "android_inference_benchmark/app/src/main/cpp/DualMachineReceiver.cpp",
    "java_header": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/video/VideoFragmentHeader.java",
    "java_kind": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/video/VideoPacketKind.java",
    "java_wrapper": "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/video/VideoWireProtocol.java",
    "probe": "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/HostVideoPresenceProbe.java",
    "preflight_verifier": "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/video/HostVideoPreflightVerifier.java",
    "reassembly_result": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/VideoReassemblyResult.java",
    "restart": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/core/DecoderRestartCoordinator.java",
    "preflight": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/VideoPreflightReassemblyWindow.java",
    "makcu_gate": "android_inference_benchmark/app/src/main/cpp/MakcuOutputGate.hpp",
    "makcu_bridge": "android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp",
}


def require(failures: list[dict[str, str]], path: str, text: str, pattern: str, rule: str) -> None:
    if re.search(pattern, text, flags=re.MULTILINE | re.DOTALL) is None:
        failures.append({"path": path, "rule": rule, "pattern": pattern})


def audit(root: Path) -> dict[str, Any]:
    root = root.resolve()
    failures: list[dict[str, str]] = []
    text: dict[str, str] = {}
    for key, relative in PATHS.items():
        path = root / relative
        if not path.is_file():
            failures.append({"path": relative, "rule": "required transport file missing"})
            text[key] = ""
        else:
            text[key] = path.read_text(encoding="utf-8")

    require(failures, PATHS["cpp_header"], text["cpp_header"], r"kVideoPacketHeaderBytes\s*=\s*20U", "C++ header must remain 20 bytes")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"0x56463247U", "C++ DATA magic must be VF2G")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"0x56463252U", "C++ REPEAT magic must be VF2R")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"kVideoStreamEpochMax\s*=\s*0x7fff'ffff'ffff'ffffULL", "C++ epoch must fit Java signed long")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"advance_video_frame_sequence[\s\S]*?UINT32_MAX[\s\S]*?return false", "C++ sequence exhaustion must force epoch rotation")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"struct\s+VideoFragmentView", "C++ hot path must expose a non-owning fragment view")
    require(failures, PATHS["cpp_header"], text["cpp_header"], r"decode_video_packet_view", "C++ hot path view decoder is required")
    for offset, function, field in ((0, "store_u32", "magic"), (4, "store_u64", "stream_epoch"), (12, "store_u32", "frame_sequence"), (16, "store_u16", "fragment_index"), (18, "store_u16", "fragment_count")):
        token = "repeated_content" if field == "magic" else ("identity.stream_epoch" if field == "stream_epoch" else "identity.frame_sequence" if field == "frame_sequence" else field)
        require(failures, PATHS["cpp_codec"], text["cpp_codec"], rf"{function}\(destination,\s*{offset}U,[\s\S]*?{re.escape(token)}", f"C++ write offset for {field} must be {offset}")
    for offset, function, field in ((4, "get_u64", "stream_epoch"), (12, "get_u32", "frame_sequence"), (16, "get_u16", "index"), (18, "get_u16", "count")):
        require(failures, PATHS["cpp_codec"], text["cpp_codec"], rf"{function}\(datagram,\s*{offset}U\)", f"C++ read offset for {field} must be {offset}")

    require(failures, PATHS["java_header"], text["java_header"], r"BYTE_LENGTH\s*=\s*20", "Java canonical header must remain 20 bytes")
    require(failures, PATHS["java_header"], text["java_header"], r"ByteOrder\.BIG_ENDIAN", "Java canonical codec must use network byte order")
    require(failures, PATHS["java_header"], text["java_header"], r"putLong\(streamEpoch\)[\s\S]*?putInt\(\(int\) frameSequence\)[\s\S]*?putShort\(\(short\) fragmentIndex\)[\s\S]*?putShort\(\(short\) fragmentCount\)", "Java write order must match C++")
    require(failures, PATHS["java_kind"], text["java_kind"], r"DATA\(0x5646_?3247\)", "Java DATA magic must be VF2G")
    require(failures, PATHS["java_kind"], text["java_kind"], r"REPEAT\(0x5646_?3252\)", "Java REPEAT magic must be VF2R")
    require(failures, PATHS["java_header"], text["java_header"], r"putInt\(kind\.magicCode\(\)\)", "Java wire encode must avoid temporary magic arrays")
    require(failures, PATHS["java_header"], text["java_header"], r"fromMagicCode\(buffer\.getInt\(\)\)", "Java wire decode must avoid temporary magic arrays")
    require(failures, PATHS["java_wrapper"], text["java_wrapper"], r"VideoFragmentHeader\.decode", "App wrapper must delegate to canonical Java codec")
    if "ByteBuffer" in text["java_wrapper"] or "readPositiveLong" in text["java_wrapper"] or "writeLong(" in text["java_wrapper"]:
        failures.append({"path": PATHS["java_wrapper"], "rule": "App wrapper duplicates canonical wire codec"})

    if "VFRG" in text["probe"] or "VFRR" in text["probe"] or re.search(r"HEADER_BYTES\s*=\s*12", text["probe"]):
        failures.append({"path": PATHS["probe"], "rule": "video presence probe contains retired 12-byte protocol"})
    require(failures, PATHS["probe"], text["probe"], r"HostVideoPreflightVerifier", "socket probe must delegate complete-frame proof to the bounded verifier")
    require(failures, PATHS["probe"], text["probe"], r"verifier\.offer", "socket probe must feed complete datagrams into the verifier")
    require(failures, PATHS["preflight_verifier"], text["preflight_verifier"], r"VideoPreflightReassemblyWindow", "preflight verifier must use the canonical bounded reassembler")
    require(failures, PATHS["preflight_verifier"], text["preflight_verifier"], r"H264AccessUnitClassifier", "preflight verifier must validate complete H.264 Access Units")
    require(failures, PATHS["preflight_verifier"], text["preflight_verifier"], r"confirmedCompleteAccessUnits", "preflight verifier must require complete IDR plus fresh content")
    require(failures, PATHS["reassembly_result"], text["reassembly_result"], r"takeAccessUnit\(\)", "completed Access Units must support a one-shot ownership transfer")

    require(failures, PATHS["publisher_h"], text["publisher_h"], r"completely_published\(\)", "publisher result must expose full-AU completion")
    require(failures, PATHS["desktop_agent"], text["desktop_agent"], r"published\.completely_published\(\)\s*&&\s*encoded_keyframe", "Host must acknowledge IDR only after full publication")
    require(failures, PATHS["hybrid_pipeline"], text["hybrid_pipeline"], r"completely_published\(\)", "asynchronous Host path must use full-publication result")
    require(failures, PATHS["host_runtime"], text["host_runtime"], r"FileEpochReservationStore", "production Host must use persistent cross-process epoch reservation")
    if len(re.findall(r"stream_epoch_store->reserve_next\(\)", text["host_runtime"])) < 2:
        failures.append({
            "path": PATHS["host_runtime"],
            "rule": "production Host must durably reserve both initial and recovery epochs",
        })
    if "derive_video_stream_epoch" in text["host_runtime"]:
        failures.append({"path": PATHS["host_runtime"], "rule": "production Host must not derive random/non-monotonic stream epochs"})
    for token in ("LockFileEx", "flock", "persist_atomically"):
        if token not in text["epoch_store_cpp"]:
            failures.append({"path": PATHS["epoch_store_cpp"], "rule": f"crash-safe epoch store missing {token}"})

    for key in ("cpp_reassembler_h", "cpp_reassembler", "preflight"):
        require(failures, PATHS[key], text[key], r"max|MAX", "reassembly must declare resource bounds")
    require(failures, PATHS["cpp_reassembler"], text["cpp_reassembler"], r"conflict|conflicting", "native reassembly must reject conflicting repeats")
    require(failures, PATHS["cpp_reassembler"], text["cpp_reassembler"], r"retired", "native reassembly/session must reject retired epochs")
    for key in ("cpp_reassembler_h", "epoch_session", "epoch_contract_h"):
        require(failures, PATHS[key], text[key], r"retired_through_", "native epoch retirement must use a permanent monotonic watermark")
        if re.search(r"std::deque\s*<\s*std::uint64_t\s*>\s+retired", text[key]):
            failures.append({"path": PATHS[key], "rule": "bounded retired-epoch rings are forbidden in production"})
    require(failures, PATHS["preflight"], text["preflight"], r"RESOURCE_LIMIT|resource", "Java preflight must fail closed on resource limits")
    require(failures, PATHS["preflight"], text["preflight"], r"CANDIDATE_REJECTED|candidate", "Java preflight must preserve active epoch while candidate fails")

    require(failures, PATHS["restart"], text["restart"], r"pending|queued|nextEpoch", "decoder restarts must coalesce newer epochs")
    require(failures, PATHS["receiver"], text["receiver"], r"pending_candidate_idr", "native receiver must retain only a complete candidate IDR")
    require(failures, PATHS["receiver"], text["receiver"], r"ReceiverEpochSession", "native receiver must track active/candidate/retired epochs")
    require(failures, PATHS["receiver"], text["receiver"], r"decode_video_packet_view", "Android native receiver must parse without an eager payload copy")
    require(failures, PATHS["makcu_gate"], text["makcu_gate"], r"MakcuFrameIdentity", "control visibility must compare full stream identity")
    require(failures, PATHS["makcu_gate"], text["makcu_gate"], r"source_generation", "control ticket/visibility state must retain stream generation")
    require(failures, PATHS["makcu_bridge"], text["makcu_bridge"], r"begin\(now_us,\s*stream_generation,\s*frame_sequence\)", "control ticket must bind stream generation and sequence")
    require(failures, PATHS["makcu_bridge"], text["makcu_bridge"], r"\{stream_generation,\s*frame_sequence\}", "post-ACK visibility must evaluate full stream identity")

    # Exactly one Java class owns a ByteBuffer codec for the video wire header.
    video_roots = [
        root / "android_inference_benchmark/app/src/main/java/com/visionforge/mobile",
        root / "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/video",
    ]
    owners: list[str] = []
    for source_root in video_roots:
        for path in sorted(source_root.rglob("*.java")) if source_root.is_dir() else []:
            if "ByteBuffer" in path.read_text(encoding="utf-8"):
                owners.append(path.relative_to(root).as_posix())
    expected_owner = PATHS["java_header"]
    if owners != [expected_owner]:
        failures.append({"path": "android Java video packages", "rule": "video wire codec must have one ByteBuffer owner", "detail": json.dumps(owners)})

    return {
        "schema_version": "visionforge.video-transport-contract-audit.v3",
        "status": "PASS" if not failures else "FAIL",
        "contract": {
            "header_bytes": 20,
            "data_magic": "VF2G",
            "repeat_magic": "VF2R",
            "identity": "(stream_epoch:uint63-positive, frame_sequence:uint32)",
            "byte_order": "big-endian/network order",
            "publication": "IDR success requires every fragment",
            "epoch_change": "candidate two-phase commit; monotonic retired high-water prevents reactivation",
            "prebilling_proof": "complete real IDR plus a complete forward non-REPEAT access unit",
            "receive_copy_policy": "header decode is zero-copy; bounded reassembly copies each accepted fragment once; completed AU ownership transfers once",
            "host_epoch_allocation": "durably reserve before initial start and recovery; volatile PID/uptime derivation is forbidden",
        },
        "java_video_codec_owners": owners,
        "failures": failures,
    }


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
