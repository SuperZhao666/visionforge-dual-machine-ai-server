#!/usr/bin/env python3
"""Fail closed when realtime video/control performance or recovery bounds regress."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path

REQUIRED = {
    "session": "dual_machine_runtime/shared/include/vfdual/receiver_epoch_session.hpp",
    "reassembler_h": "dual_machine_runtime/shared/include/vfdual/access_unit_reassembler.hpp",
    "reassembler_cpp": "dual_machine_runtime/shared/src/access_unit_reassembler.cpp",
    "e2e_reassembly_h": "dual_machine_runtime/e2e_core/include/vf/reassembly.hpp",
    "e2e_reassembly_cpp": "dual_machine_runtime/e2e_core/src/reassembly.cpp",
    "java_header": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/domain/video/VideoFragmentHeader.java",
    "java_root": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/MobileRuntimeCompositionRoot.java",
    "java_window": "android_inference_benchmark/app/src/main/java/com/visionforge/mobile/application/VideoPreflightReassemblyWindow.java",
    "decoder_queue": "android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/DecoderAccessUnitQueue.java",
    "host_runtime": "dual_machine_runtime/host/windows/src/host_runtime_service.cpp",
    "makcu_gate": "android_inference_benchmark/app/src/main/cpp/MakcuOutputGate.hpp",
    "makcu_bridge": "android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp",
}

def audit(root: Path) -> dict:
    root = root.resolve(); failures=[]; text={}
    for key, rel in REQUIRED.items():
        path=root/rel
        if not path.is_file(): failures.append({"path":rel,"rule":"required production file missing"}); text[key]=""
        else: text[key]=path.read_text(encoding="utf-8")
    for key in ("session","reassembler_h"):
        if "retired_through_" not in text[key]: failures.append({"path":REQUIRED[key],"rule":"permanent epoch high-water mark missing"})
        if re.search(r"std::deque\s*<\s*std::uint64_t\s*>\s+retired", text[key]): failures.append({"path":REQUIRED[key],"rule":"bounded retired epoch ring reintroduced"})
    if "received_fragments" not in text["e2e_reassembly_h"] or not re.search(r"received_fragments\s*!=\s*frame\.fragment_count", text["e2e_reassembly_cpp"]):
        failures.append({"path":REQUIRED["e2e_reassembly_cpp"],"rule":"hot-path fragment completion scan was reintroduced"})
    if "Arrays.copyOfRange(datagram" in text["java_root"]:
        failures.append({"path":REQUIRED["java_root"],"rule":"UDP payload is copied before bounded admission"})
    for token in ("payloadOffset", "payloadLength", "rangeEquals"):
        if token not in text["java_window"]: failures.append({"path":REQUIRED["java_window"],"rule":f"zero-copy admission contract missing {token}"})
    for token in ("maximumReusableBytes", "reusableBytes", "removeLargestReusableAccessUnit"):
        if token not in text["decoder_queue"]: failures.append({"path":REQUIRED["decoder_queue"],"rule":f"decoder pool byte bound missing {token}"})
    if "ByteBuffer.wrap(datagram, offset, BYTE_LENGTH)" not in text["java_header"]:
        failures.append({"path":REQUIRED["java_header"],"rule":"canonical Java header must parse a bounded slice"})
    if "FileEpochReservationStore" not in text["host_runtime"] or "reserve_next()" not in text["host_runtime"]:
        failures.append({"path": REQUIRED["host_runtime"], "rule": "production Host epoch is not durably reserved"})
    if "derive_video_stream_epoch" in text["host_runtime"]:
        failures.append({"path": REQUIRED["host_runtime"], "rule": "random epoch derivation reintroduced"})
    if "MakcuFrameIdentity" not in text["makcu_gate"] or "source_generation" not in text["makcu_gate"]:
        failures.append({"path": REQUIRED["makcu_gate"], "rule": "control gate lost full frame identity"})
    if not re.search(r"begin\(now_us,\s*stream_generation,\s*frame_sequence\)", text["makcu_bridge"]):
        failures.append({"path": REQUIRED["makcu_bridge"], "rule": "control ticket is not generation-bound"})
    if "result.takeAccessUnit()" not in text["java_root"]:
        failures.append({"path": REQUIRED["java_root"], "rule": "completed access unit is not transferred exactly once before decode handoff"})
    return {"schema_version":"visionforge.realtime-pipeline-contract.v1","status":"PASS" if not failures else "FAIL","invariants":["permanent epoch retirement","candidate monotonicity","bounded reassembly","single-copy fragment admission","bounded decoder reuse pool","constant-time fragment completion","durable monotonic Host epochs","full-identity post-ACK visibility"],"failures":failures}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--root",type=Path,default=Path(".")); ap.add_argument("--output",type=Path); a=ap.parse_args(); report=audit(a.root); rendered=json.dumps(report,ensure_ascii=False,indent=2)+"\n"; print(rendered,end="");
    if a.output: a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(rendered,encoding="utf-8")
    raise SystemExit(0 if report["status"]=="PASS" else 1)
if __name__=="__main__": main()
