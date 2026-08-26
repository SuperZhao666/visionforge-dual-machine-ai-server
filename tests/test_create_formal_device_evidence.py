from __future__ import annotations

import json
import sys
import zipfile
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import create_formal_device_evidence as creator  # noqa: E402
from tools import physical_output_route_evidence as route_evidence  # noqa: E402
from tools import verify_formal_release_bundle as verifier  # noqa: E402
from tests._final_safe_idle_fixture import (  # noqa: E402
    valid_final_safe_idle_events,
    valid_final_safe_idle_payload,
)


def _write_exe(path: Path) -> None:
    path.write_bytes(b"MZformal")


def _write_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")


def _write_ui_evidence(root: Path, package_name: str = "com.visionforge.mobile") -> None:
    control = """
<hierarchy>
  <node package="{package_name}" content-desc="vf.control_output_toggle" enabled="false" />
  <node package="{package_name}" content-desc="vf.output_route.makcu_usb" enabled="true" />
  <node package="{package_name}" content-desc="vf.game_model.valorant-yellow-416-v11s-no-flash" text="无畏契约" />
  <node package="{package_name}" content-desc="vf.game_model.overwatch2-416-yolov5" text="守望先锋" />
  <node package="{package_name}" content-desc="vf.game_model.delta-force-416-v8s" text="三角洲行动" />
  <node package="{package_name}" content-desc="vf.game_model.counter-strike-2-vombit-416-v8s" text="反恐精英2" />
  <node package="{package_name}" content-desc="vf.aim_target.body" />
  <node package="{package_name}" content-desc="vf.aim_target.head" />
</hierarchy>
""".format(package_name=package_name)
    cs2 = """
<hierarchy>
  <node package="{package_name}" content-desc="vf.game_model.counter-strike-2-vombit-416-v8s" />
  <node package="{package_name}" content-desc="vf.aim_target.ct_body" />
  <node package="{package_name}" content-desc="vf.aim_target.ct_head" />
  <node package="{package_name}" content-desc="vf.aim_target.t_body" />
  <node package="{package_name}" content-desc="vf.aim_target.t_head" />
</hierarchy>
""".format(package_name=package_name)
    ow2 = """
<hierarchy>
  <node package="{package_name}" content-desc="vf.game_model.overwatch2-416-yolov5" />
  <node package="{package_name}" content-desc="vf.aim_target.body" />
  <node package="{package_name}" content-desc="vf.aim_target.head" />
</hierarchy>
""".format(package_name=package_name)
    (root / "03-control.xml").write_text(control, encoding="utf-8")
    (root / "03-control-ow2-targets.xml").write_text(ow2, encoding="utf-8")
    (root / "03-control-cs2-targets.xml").write_text(cs2, encoding="utf-8")


def _health_detail(
    *,
    route: str,
    candidate_moves: int,
    java_acceptances: int,
    bluetooth_acceptances: int = 0,
    device_acknowledgements: int = 0,
) -> str:
    makcu_ready = route == route_evidence.MAKCU_USB_ROUTE
    return (
        "phase=running "
        "video={ethernet_network_bound=1 completed_access_units=40} "
        "decoder={qnn_executions=40 qnn_failures=0 consecutive_qnn_failures=0 "
        "last_detection_count=2 makcu_bridge{"
        f"candidate_moves={candidate_moves} "
        f"java_offer_acceptances={java_acceptances} "
        "java_offer_rejections=0 java_dispatch_failures=0 "
        "native_move_completion_pending=0 native_move_completion_timeouts=0 "
        f"native_device_ack_completions={device_acknowledgements} "
        "native_device_ack_failures=0 stale_device_feedback=0 "
        f"native_bluetooth_hid_api_acceptances={bluetooth_acceptances} "
        "stale_bluetooth_hid_api_acceptances=0 output_requested=1 output_enabled=1}} "
        "qnn={backend=QNN HTP} "
        f"makcu={{serial_open={int(makcu_ready)} "
        f"adapter_identity_verified={int(makcu_ready)} "
        f"protocol_identity_verified={int(makcu_ready)} "
        f"selected_baud={4000000 if makcu_ready else 0} "
        f"device_move_acknowledgements={device_acknowledgements} "
        "device_acknowledgement_failures=0 unexpected_device_responses=0 "
        "response_parser_overflows=0 delivery_failures=0 "
        "consecutive_delivery_failures=0 delivery_circuit_open=0 "
        "delivery_circuit_trips=0}"
    )


def test_cs2_full_chain_requires_model_attributed_success_metrics() -> None:
    cs2_metrics = json.dumps(
        {
            "event": "mobile_pipeline_metrics",
            "detail": (
                "model=counter-strike-2-vombit-416-v8s "
                "aim_target=ct_head native_applied=true "
                "rendered_frames=21 qnn_executions=20 qnn_failures=0 "
                "qnn_fps=140.5 preprocess_p50=1.20 qnn_p50=3.40 "
                "inference_total_p50=3.70 decode_queue_p50=6.50 "
                "target_switches=2 motion_plans=5 direction_flips=3,4"
            ),
        }
    )

    observation = creator._counter_strike_2_qnn_observation(cs2_metrics)

    assert observation is not None
    assert observation["event"] == "mobile_pipeline_metrics"
    assert observation["model"] == "counter-strike-2-vombit-416-v8s"
    assert observation["aim_target"] == "ct_head"
    assert observation["rendered_frames"] == 21
    assert observation["qnn_executions"] == 20
    assert observation["qnn_failures"] == 0
    assert observation["qnn_fps"] == 140.5
    assert observation["preprocess_p50_ms"] == 1.2
    assert observation["qnn_p50_ms"] == 3.4
    assert observation["inference_total_p50_ms"] == 3.7
    assert observation["decode_queue_p50_ms"] == 6.5
    assert observation["target_switches"] == 2
    assert observation["motion_plans"] == 5
    assert observation["direction_flips_xy"] == [3, 4]
    assert len(observation["detail_sha256"]) == 64


def test_cs2_full_chain_rejects_other_model_and_failed_qnn() -> None:
    delta_metrics = json.dumps(
        {
            "event": "mobile_pipeline_metrics",
                "detail": (
                    "model=delta-force-416-v8s aim_target=head native_applied=true "
                    "rendered_frames=21 qnn_executions=20 qnn_failures=0 "
                    "qnn_fps=140.5 preprocess_p50=1.20 qnn_p50=3.40 "
                    "inference_total_p50=3.70 decode_queue_p50=6.50"
                ),
        }
    )
    failed_cs2_metrics = json.dumps(
        {
            "event": "mobile_pipeline_metrics",
                "detail": (
                    "model=counter-strike-2-vombit-416-v8s "
                    "aim_target=t_head native_applied=true "
                    "rendered_frames=21 qnn_executions=20 qnn_failures=1 "
                    "qnn_fps=140.5 preprocess_p50=1.20 qnn_p50=3.40 "
                    "inference_total_p50=3.70 decode_queue_p50=6.50"
                ),
        }
    )

    assert not creator._counter_strike_2_qnn_full_chain(delta_metrics)
    assert not creator._counter_strike_2_qnn_full_chain(failed_cs2_metrics)


def test_cs2_full_chain_decodes_logcat_json_and_selects_latest_sample() -> None:
    def metric_event(timestamp_unix_ms: int, executions: int, qnn_fps: float) -> str:
        payload = json.dumps(
            {
                "timestamp_unix_ms": timestamp_unix_ms,
                "event": "mobile_pipeline_metrics",
                "detail": (
                    "model=counter-strike-2-vombit-416-v8s "
                    "aim_target=t_head native_applied=true "
                    f"rendered_frames={executions + 2} "
                    f"qnn_executions={executions} qnn_failures=0 "
                    f"qnn_fps={qnn_fps} preprocess_p50=0.95 "
                    "qnn_p50=3.40 inference_total_p50=3.50 "
                    "decode_queue_p50=5.20"
                ),
            }
        )
        return (
            f"{timestamp_unix_ms / 1000:.3f} 6358 6358 "
            f"I VisionForgeMobile: {payload}"
        )

    observation = creator._counter_strike_2_qnn_observation(
        metric_event(1_785_655_018_227, 2_252, 128.3)
        + "\n"
        + metric_event(1_785_655_023_319, 2_951, 137.2)
    )

    assert observation is not None
    assert observation["event"] == "mobile_pipeline_metrics"
    assert observation["timestamp_unix_ms"] == 1_785_655_023_319
    assert observation["qnn_executions"] == 2_951
    assert observation["qnn_fps"] == 137.2


def _write_physical_route_sources(
    root: Path,
    *,
    route: str,
    apk: Path,
    device_serial: str,
    start_unix_ms: int,
) -> tuple[Path, Path]:
    mobile_log = root / f"{route}-mobile-events.jsonl"
    cursor_csv = root / f"{route}-cursor.csv"
    first_health = _health_detail(
        route=route,
        candidate_moves=1,
        java_acceptances=1,
    )
    second_health = _health_detail(
        route=route,
        candidate_moves=4,
        java_acceptances=4,
        bluetooth_acceptances=3 if route == route_evidence.BLUETOOTH_HID_ROUTE else 0,
        device_acknowledgements=3 if route == route_evidence.MAKCU_USB_ROUTE else 0,
    )
    events = [
        {
            "timestamp_unix_ms": start_unix_ms + 500,
            "event": "mobile_control_output_route_selected",
            "detail": f"route={route} fail_closed=false",
        },
        {
            "timestamp_unix_ms": start_unix_ms + 1_000,
            "event": "mobile_runtime_health",
            "detail": first_health,
        },
        {
            "timestamp_unix_ms": start_unix_ms + 2_000,
            "event": "mobile_pipeline_metrics",
            "detail": (
                "model=counter-strike-2-vombit-416-v8s "
                "aim_target=t_head confidence=0.25 iou=0.45 "
                "native_applied=true rendered_frames=40 "
                "qnn_executions=40 qnn_failures=0 qnn_fps=140.0 "
                "preprocess_p50=1.20 qnn_p50=3.40 "
                "inference_total_p50=3.70 decode_queue_p50=6.50 "
                "target_switches=2 motion_plans=5 direction_flips=3,4"
            ),
        },
    ]
    if route == route_evidence.BLUETOOTH_HID_ROUTE:
        events.append(
            {
                "timestamp_unix_ms": start_unix_ms + 3_000,
                "event": "bluetooth_hid_send_report",
                "detail": "accepted=true reason=api_return accepted_total=1",
            }
        )
    events.append(
        {
            "timestamp_unix_ms": start_unix_ms + 6_000,
            "event": "mobile_runtime_health",
            "detail": second_health,
        }
    )
    mobile_log.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    with cursor_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("Index", "UnixMs", "X", "Y", "Valid"))
        writer.writeheader()
        for index in range(8):
            moved = index >= 3
            writer.writerow(
                {
                    "Index": index,
                    "UnixMs": start_unix_ms + (index * 1_000),
                    "X": 120 if moved else 100,
                    "Y": 100,
                    "Valid": "true",
                }
            )
    payload = route_evidence.create_route_evidence(
        route=route,
        android_apk=apk,
        device_serial=device_serial,
        mobile_logs=[mobile_log],
        cursor_samples_path=cursor_csv,
    )
    evidence_path = root / f"{route}-physical-evidence.json"
    evidence_path.write_text(json.dumps(payload), encoding="utf-8")
    assert route_evidence.route_evidence_errors(payload) == []
    return mobile_log, evidence_path


def test_build_device_evidence_sets_all_checks_from_real_artifacts_and_logs(tmp_path: Path) -> None:
    windows = tmp_path / "VisionForge_Protected.exe"
    host = tmp_path / "VFHost.exe"
    apk = tmp_path / "app-release.apk"
    output = tmp_path / "formal_device_evidence.json"
    ui = tmp_path / "ui"
    ui.mkdir()
    _write_exe(windows)
    _write_exe(host)
    _write_apk(apk)
    _write_ui_evidence(ui)
    device_serial = "adb-test._adb-tls-connect._tcp"
    bluetooth_log, bluetooth_evidence = _write_physical_route_sources(
        tmp_path,
        route=route_evidence.BLUETOOTH_HID_ROUTE,
        apk=apk,
        device_serial=device_serial,
        start_unix_ms=1_800_000_000_000,
    )
    makcu_log, makcu_evidence = _write_physical_route_sources(
        tmp_path,
        route=route_evidence.MAKCU_USB_ROUTE,
        apk=apk,
        device_serial=device_serial,
        start_unix_ms=1_800_000_020_000,
    )
    physical_routes = {
        route: {
            "evidence_sha256": route_evidence.canonical_sha256(payload),
            "evidence": payload,
        }
        for route, payload in (
            (
                route_evidence.BLUETOOTH_HID_ROUTE,
                json.loads(bluetooth_evidence.read_text(encoding="utf-8")),
            ),
            (
                route_evidence.MAKCU_USB_ROUTE,
                json.loads(makcu_evidence.read_text(encoding="utf-8")),
            ),
        )
    }
    acceptance_end = max(
        int(entry["evidence"]["metrics"]["capture_end_unix_ms"])
        for entry in physical_routes.values()
    )
    final_log = tmp_path / "mobile-events-final.jsonl"
    final_log.write_text(
        "".join(
            json.dumps(event) + "\n"
            for event in valid_final_safe_idle_events(acceptance_end)
        ),
        encoding="utf-8",
    )
    control_xml_path = ui / "03-control.xml"
    control_xml = control_xml_path.read_text(encoding="utf-8")
    safe_idle_payload = valid_final_safe_idle_payload(
        android_apk_sha256=route_evidence.sha256_file(apk),
        device_serial=device_serial,
        mobile_log_sha256=route_evidence.sha256_file(final_log),
        ui_xml_sha256=route_evidence.sha256_file(control_xml_path),
        ui_xml=control_xml,
        physical_output_routes=physical_routes,
    )
    safe_idle_evidence = tmp_path / "final-safe-idle-evidence.json"
    safe_idle_evidence.write_text(json.dumps(safe_idle_payload), encoding="utf-8")

    evidence = creator.build_device_evidence(
        android_apk=apk,
        windows_exe=windows,
        host_exe=host,
        ui_evidence_dir=ui,
        mobile_logs=[bluetooth_log, makcu_log, final_log],
        host_logs=[],
        output=output,
        apk_installed=True,
        device_serial=device_serial,
        installed_package_version="1.0.0-rc1",
        physical_route_evidence_paths={
            route_evidence.BLUETOOTH_HID_ROUTE: bluetooth_evidence,
            route_evidence.MAKCU_USB_ROUTE: makcu_evidence,
        },
        final_safe_idle_evidence_path=safe_idle_evidence,
    )

    assert output.exists()
    assert evidence["installed_package_name"] == "com.visionforge.mobile"
    assert evidence["checks"]["ui_evidence_package_scope"] is True
    assert all(evidence["checks"][key] is True for key in verifier.REQUIRED_DEVICE_EVIDENCE_FLAGS)
    assert evidence["schema"] == verifier.DEVICE_EVIDENCE_SCHEMA
    assert evidence["observations"]["legacy_generic_move_signal_is_release_proof"] is False
    cs2_observation = evidence["observations"]["counter_strike_2_qnn_full_chain"]
    assert cs2_observation["model"] == "counter-strike-2-vombit-416-v8s"
    assert cs2_observation["aim_target"] == "t_head"
    assert cs2_observation["rendered_frames"] == 40
    assert cs2_observation["qnn_executions"] == 40
    assert cs2_observation["qnn_failures"] == 0
    assert cs2_observation["qnn_fps"] == 140.0
    assert len(cs2_observation["source_mobile_log_sha256"]) == 64
    assert evidence["game_display_names"] == verifier.EXPECTED_GAME_DISPLAY_NAMES
    ow2_contract = evidence["model_target_contracts"]["overwatch2-416-yolov5"]
    assert ow2_contract["game_display_name"] == "守望先锋"
    assert ow2_contract["lock_class_id"] == 0
    assert ow2_contract["lock_class_name"] == "enemy_body"
    assert ow2_contract["ignored_class_ids"] == [1]
    assert ow2_contract["ignored_class_names"] == ["non_enemy_body"]
    assert ow2_contract["head_target_source"] == "geometric_body_box"
    cs2_contract = evidence["model_target_contracts"][
        "counter-strike-2-vombit-416-v8s"
    ]
    assert cs2_contract["game_display_name"] == "反恐精英2"
    assert cs2_contract["ct_body_class_id"] == 0
    assert cs2_contract["ct_head_class_id"] == 1
    assert cs2_contract["t_body_class_id"] == 2
    assert cs2_contract["t_head_class_id"] == 3
    assert cs2_contract["cross_faction_pairing_allowed"] is False
    verification = verifier.verify_device_evidence(
        output,
        required=True,
        expected_hashes={
            "windows_exe_sha256": evidence["windows_exe_sha256"],
            "android_apk_sha256": evidence["android_apk_sha256"],
            "host_exe_sha256": evidence["host_exe_sha256"],
        },
    )
    assert verification.ok


def test_verify_host_release_requires_vfhost_filename(tmp_path: Path) -> None:
    canonical = tmp_path / "VFHost.exe"
    legacy = tmp_path / "VisionForgeHost.exe"
    _write_exe(canonical)
    _write_exe(legacy)

    assert verifier.verify_host_release(
        canonical,
        require_authenticode=False,
    ).ok
    legacy_result = verifier.verify_host_release(
        legacy,
        require_authenticode=False,
    )
    assert not legacy_result.ok
    assert "must be named VFHost.exe" in legacy_result.detail


def test_main_reports_incomplete_when_runtime_logs_are_missing(tmp_path: Path, capsys) -> None:
    apk = tmp_path / "app-release.apk"
    ui = tmp_path / "ui"
    output = tmp_path / "formal_device_evidence.json"
    ui.mkdir()
    _write_apk(apk)
    _write_ui_evidence(ui)

    result = creator.main(
        [
            "--android-apk",
            str(apk),
            "--ui-evidence-dir",
            str(ui),
            "--apk-installed",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr().out
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert "complete=False" in captured
    assert payload["checks"]["qnn_htp_graph_execute"] is False
    assert payload["checks"]["game_models_available"] is True
    assert payload["checks"]["game_model_display_names_visible"] is True


def test_main_reports_incomplete_when_ui_nodes_belong_to_other_package(
    tmp_path: Path,
    capsys,
) -> None:
    apk = tmp_path / "app-release.apk"
    ui = tmp_path / "ui"
    output = tmp_path / "formal_device_evidence.json"
    ui.mkdir()
    _write_apk(apk)
    _write_ui_evidence(ui, package_name="com.fake.overlay")

    result = creator.main(
        [
            "--android-apk",
            str(apk),
            "--ui-evidence-dir",
            str(ui),
            "--apk-installed",
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr().out
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert "complete=False" in captured
    assert payload["checks"]["game_models_available"] is True
    assert payload["checks"]["game_model_display_names_visible"] is True
    assert payload["checks"]["ui_evidence_package_scope"] is False


def test_main_require_complete_fails_when_device_metadata_is_missing(
    tmp_path: Path,
    capsys,
) -> None:
    windows = tmp_path / "VisionForge_Protected.exe"
    host = tmp_path / "VFHost.exe"
    apk = tmp_path / "app-release.apk"
    output = tmp_path / "formal_device_evidence.json"
    log = tmp_path / "mobile-logcat.txt"
    ui = tmp_path / "ui"
    ui.mkdir()
    _write_exe(windows)
    _write_exe(host)
    _write_apk(apk)
    _write_ui_evidence(ui)
    log.write_text(
        "\n".join(
            (
                "backend=QNN HTP; graph=1",
                "ethernet_network_bound=true",
                "completed_access_units=42",
                "control_output_usb_write_completed count=1",
            )
        ),
        encoding="utf-8",
    )

    result = creator.main(
        [
            "--android-apk",
            str(apk),
            "--windows-exe",
            str(windows),
            "--host-exe",
            str(host),
            "--ui-evidence-dir",
            str(ui),
            "--mobile-log",
            str(log),
            "--apk-installed",
            "--output",
            str(output),
            "--require-complete",
        ]
    )

    captured = capsys.readouterr().out
    assert result == 2
    assert "complete=False" in captured
    assert "device_serial" in captured
    assert "installed_package_version" in captured
