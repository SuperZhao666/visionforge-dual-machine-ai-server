"""Verify the approved OW2 static-decode ONNX and phone HTP raw outputs."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import onnx
import onnxruntime as ort


SCHEMA = "visionforge-ow2-qnn-numeric-contract-v1"
INPUT_SIZE = 416
ANCHORS = 3549
CLASSES = 2
CONTROL_CLASS = 0
CONFIDENCE_THRESHOLD = 0.20
NMS_IOU_THRESHOLD = 0.45
TOP_K = 20


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _difference(actual: np.ndarray, expected: np.ndarray) -> dict[str, float]:
    absolute = np.abs(actual - expected).reshape(-1)
    return {
        "mean_abs": float(absolute.mean()),
        "p95_abs": float(np.quantile(absolute, 0.95)),
        "max_abs": float(absolute.max()),
    }


def _xywh_to_xyxy(boxes: np.ndarray) -> np.ndarray:
    result = boxes.copy()
    result[:, 0] = boxes[:, 0] - boxes[:, 2] * 0.5
    result[:, 1] = boxes[:, 1] - boxes[:, 3] * 0.5
    result[:, 2] = boxes[:, 0] + boxes[:, 2] * 0.5
    result[:, 3] = boxes[:, 1] + boxes[:, 3] * 0.5
    return result


def _nms_indices(
    coordinates: np.ndarray,
    scores: np.ndarray,
) -> list[int]:
    candidates = np.flatnonzero(scores >= CONFIDENCE_THRESHOLD)
    if candidates.size == 0:
        return []
    boxes = _xywh_to_xyxy(coordinates[:, candidates].T)
    order = np.argsort(scores[candidates])[::-1]
    keep: list[int] = []
    while order.size:
        selected_position = int(order[0])
        keep.append(int(candidates[selected_position]))
        if order.size == 1:
            break
        remaining = order[1:]
        selected = boxes[selected_position]
        others = boxes[remaining]
        left = np.maximum(selected[:2], others[:, :2])
        right = np.minimum(selected[2:], others[:, 2:])
        intersection = np.prod(np.maximum(0.0, right - left), axis=1)
        selected_area = max(0.0, float(np.prod(selected[2:] - selected[:2])))
        other_areas = np.prod(np.maximum(0.0, others[:, 2:] - others[:, :2]), axis=1)
        union = np.maximum(selected_area + other_areas - intersection, 1e-12)
        order = remaining[(intersection / union) <= NMS_IOU_THRESHOLD]
    return keep


def _box_iou(left_xywh: np.ndarray, right_xywh: np.ndarray) -> float:
    boxes = _xywh_to_xyxy(np.stack((left_xywh, right_xywh)))
    intersection_left = np.maximum(boxes[0, :2], boxes[1, :2])
    intersection_right = np.minimum(boxes[0, 2:], boxes[1, 2:])
    intersection = float(
        np.prod(np.maximum(0.0, intersection_right - intersection_left))
    )
    areas = np.prod(np.maximum(0.0, boxes[:, 2:] - boxes[:, :2]), axis=1)
    return intersection / max(float(areas.sum()) - intersection, 1e-12)


def _match_nms_targets(
    reference_coordinates: np.ndarray,
    qnn_coordinates: np.ndarray,
    reference_indices: list[int],
    qnn_indices: list[int],
) -> dict[str, Any]:
    if len(reference_indices) != len(qnn_indices) or not reference_indices:
        return {"matched": False, "pairs": [], "minimum_iou": 0.0, "maximum_center_error": None}
    remaining = set(qnn_indices)
    pairs: list[dict[str, float | int]] = []
    for reference_index in reference_indices:
        best_index = max(
            remaining,
            key=lambda candidate: _box_iou(
                reference_coordinates[:, reference_index],
                qnn_coordinates[:, candidate],
            ),
        )
        iou = _box_iou(
            reference_coordinates[:, reference_index],
            qnn_coordinates[:, best_index],
        )
        center_error = float(
            np.linalg.norm(
                reference_coordinates[:2, reference_index]
                - qnn_coordinates[:2, best_index]
            )
        )
        pairs.append(
            {
                "reference_anchor": reference_index,
                "qnn_anchor": best_index,
                "iou": iou,
                "center_error_pixels": center_error,
            }
        )
        remaining.remove(best_index)
    return {
        "matched": True,
        "pairs": pairs,
        "minimum_iou": min(float(pair["iou"]) for pair in pairs),
        "maximum_center_error": max(
            float(pair["center_error_pixels"]) for pair in pairs
        ),
    }


def _load_reference(
    source: Path,
    rewritten: Path,
    input_path: Path,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    raw = np.fromfile(input_path, dtype=np.uint16)
    expected_elements = INPUT_SIZE * INPUT_SIZE * 3
    if raw.size != expected_elements:
        raise ValueError(
            f"Expected {expected_elements} U16 NHWC input values, got {raw.size}"
        )
    input_tensor = (
        raw.reshape(1, INPUT_SIZE, INPUT_SIZE, 3)
        .astype(np.float32)
        .transpose(0, 3, 1, 2)
        / 65535.0
    )
    source_session = ort.InferenceSession(
        str(source),
        providers=["CPUExecutionProvider"],
    )
    source_input = source_session.get_inputs()[0].name
    rows = source_session.run(None, {source_input: input_tensor})[0]
    if rows.shape != (1, ANCHORS, 5 + CLASSES):
        raise ValueError(f"Unexpected source output shape: {rows.shape}")
    reference_coordinates = rows[:, :, :4].transpose(0, 2, 1)
    reference_confidences = (
        rows[:, :, 4:5] * rows[:, :, 5 : 5 + CLASSES]
    ).transpose(0, 2, 1)

    rewritten_session = ort.InferenceSession(
        str(rewritten),
        providers=["CPUExecutionProvider"],
    )
    rewritten_input = rewritten_session.get_inputs()[0].name
    outputs = dict(
        zip(
            [output.name for output in rewritten_session.get_outputs()],
            rewritten_session.run(None, {rewritten_input: input_tensor}),
            strict=True,
        )
    )
    split_coordinates = outputs.get("output_coordinates")
    split_confidences = outputs.get("output_confidences")
    if split_coordinates is None or split_confidences is None:
        raise ValueError("Rewritten model is missing the mobile split outputs")
    op_types = {node.op_type for node in onnx.load(rewritten).graph.node}
    forbidden = sorted(op_types & {"Range", "ScatterND"})
    static_metrics = {
        "coordinates": _difference(split_coordinates, reference_coordinates),
        "confidences": _difference(split_confidences, reference_confidences),
        "node_count": len(onnx.load(rewritten).graph.node),
        "forbidden_dynamic_decode_ops": forbidden,
    }
    return reference_coordinates, reference_confidences, static_metrics


def verify_numeric_contract(
    *,
    source: Path,
    rewritten: Path,
    input_path: Path,
    qnn_coordinates_path: Path,
    qnn_confidences_path: Path,
    qnn_library_path: Path,
) -> dict[str, Any]:
    reference_coordinates, reference_confidences, static_metrics = _load_reference(
        source,
        rewritten,
        input_path,
    )
    qnn_coordinates = np.fromfile(qnn_coordinates_path, dtype=np.float32)
    qnn_confidences = np.fromfile(qnn_confidences_path, dtype=np.float32)
    if qnn_coordinates.size != 4 * ANCHORS:
        raise ValueError(f"Unexpected QNN coordinate value count: {qnn_coordinates.size}")
    if qnn_confidences.size != CLASSES * ANCHORS:
        raise ValueError(f"Unexpected QNN confidence value count: {qnn_confidences.size}")
    qnn_coordinates = qnn_coordinates.reshape(1, 4, ANCHORS)
    qnn_confidences = qnn_confidences.reshape(1, CLASSES, ANCHORS)
    if not np.isfinite(qnn_coordinates).all() or not np.isfinite(qnn_confidences).all():
        raise ValueError("QNN outputs contain non-finite values")

    reference_control = reference_confidences[0, CONTROL_CLASS]
    qnn_control = qnn_confidences[0, CONTROL_CLASS]
    reference_top = np.argsort(reference_control)[::-1][:TOP_K]
    qnn_top = np.argsort(qnn_control)[::-1][:TOP_K]
    top_overlap = len(set(reference_top) & set(qnn_top)) / TOP_K
    candidate_mask = np.maximum(reference_control, qnn_control) >= CONFIDENCE_THRESHOLD
    candidate_coordinate_metrics = _difference(
        qnn_coordinates[0, :, candidate_mask],
        reference_coordinates[0, :, candidate_mask],
    )
    control_confidence_metrics = _difference(qnn_control, reference_control)
    reference_nms = _nms_indices(reference_coordinates[0], reference_control)
    qnn_nms = _nms_indices(qnn_coordinates[0], qnn_control)
    nms_match = _match_nms_targets(
        reference_coordinates[0],
        qnn_coordinates[0],
        reference_nms,
        qnn_nms,
    )
    unique_confidences = int(np.unique(qnn_confidences).size)
    control_unique_confidences = int(np.unique(qnn_control).size)
    reference_candidates = set(
        np.flatnonzero(reference_control >= CONFIDENCE_THRESHOLD).tolist()
    )
    qnn_candidates = set(
        np.flatnonzero(qnn_control >= CONFIDENCE_THRESHOLD).tolist()
    )
    candidate_union = reference_candidates | qnn_candidates
    candidate_jaccard = (
        len(reference_candidates & qnn_candidates) / len(candidate_union)
        if candidate_union
        else 1.0
    )

    checks = {
        "static_coordinates_exact": static_metrics["coordinates"]["max_abs"] <= 1e-5,
        "static_confidences_exact": static_metrics["confidences"]["max_abs"] <= 1e-7,
        "static_dynamic_decode_removed": not static_metrics["forbidden_dynamic_decode_ops"],
        "qnn_control_confidences_not_saturated": control_unique_confidences >= 20,
        "control_top20_overlap": top_overlap >= 0.95,
        "control_candidate_count_matches": len(qnn_candidates)
        == len(reference_candidates),
        "control_candidate_set_overlap": candidate_jaccard >= 0.95,
        "control_confidence_error": control_confidence_metrics["max_abs"] <= 0.06,
        "control_candidate_coordinate_mean": candidate_coordinate_metrics["mean_abs"] <= 0.30,
        "control_candidate_coordinate_p95": candidate_coordinate_metrics["p95_abs"] <= 0.75,
        "control_candidate_coordinate_max": candidate_coordinate_metrics["max_abs"] <= 1.0,
        "control_nms_target_count_matches": len(reference_nms) >= 2
        and len(reference_nms) == len(qnn_nms),
        "control_nms_target_iou": bool(nms_match["matched"])
        and float(nms_match["minimum_iou"]) >= 0.90,
        "control_nms_target_center": bool(nms_match["matched"])
        and float(nms_match["maximum_center_error"]) <= 1.0,
    }
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "ok": all(checks.values()),
        "contract": {
            "input": [1, 3, INPUT_SIZE, INPUT_SIZE],
            "anchors": ANCHORS,
            "classes": CLASSES,
            "control_class": CONTROL_CLASS,
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "nms_iou_threshold": NMS_IOU_THRESHOLD,
        },
        "artifacts": {
            "source_onnx": {"path": str(source.resolve()), "sha256": _sha256(source)},
            "rewritten_onnx": {
                "path": str(rewritten.resolve()),
                "sha256": _sha256(rewritten),
            },
            "input_u16_nhwc": {
                "path": str(input_path.resolve()),
                "sha256": _sha256(input_path),
            },
            "qnn_coordinates": {
                "path": str(qnn_coordinates_path.resolve()),
                "sha256": _sha256(qnn_coordinates_path),
            },
            "qnn_confidences": {
                "path": str(qnn_confidences_path.resolve()),
                "sha256": _sha256(qnn_confidences_path),
            },
            "qnn_android_model_library": {
                "path": str(qnn_library_path.resolve()),
                "sha256": _sha256(qnn_library_path),
            },
        },
        "static_onnx": static_metrics,
        "phone_htp": {
            "confidence_min": float(qnn_confidences.min()),
            "confidence_max": float(qnn_confidences.max()),
            "confidence_unique_values": unique_confidences,
            "control_confidence_unique_values": control_unique_confidences,
            "control_top20_overlap": top_overlap,
            "control_candidate_jaccard": candidate_jaccard,
            "control_reference_candidates": int(
                (reference_control >= CONFIDENCE_THRESHOLD).sum()
            ),
            "control_qnn_candidates": int(
                (qnn_control >= CONFIDENCE_THRESHOLD).sum()
            ),
            "control_reference_top_confidence": float(reference_control.max()),
            "control_qnn_top_confidence": float(qnn_control.max()),
            "control_confidence_error": control_confidence_metrics,
            "control_candidate_coordinate_error_pixels": candidate_coordinate_metrics,
            "control_reference_nms_indices": reference_nms,
            "control_qnn_nms_indices": qnn_nms,
            "control_nms_match": nms_match,
        },
        "checks": checks,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rewritten", type=Path, required=True)
    parser.add_argument("--input-u16-nhwc", type=Path, required=True)
    parser.add_argument("--qnn-coordinates", type=Path, required=True)
    parser.add_argument("--qnn-confidences", type=Path, required=True)
    parser.add_argument("--qnn-library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    report = verify_numeric_contract(
        source=arguments.source,
        rewritten=arguments.rewritten,
        input_path=arguments.input_u16_nhwc,
        qnn_coordinates_path=arguments.qnn_coordinates,
        qnn_confidences_path=arguments.qnn_confidences,
        qnn_library_path=arguments.qnn_library,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if report["ok"]:
        print(f"OW2_QNN_NUMERIC_CONTRACT_OK report={arguments.output.resolve()}")
        return 0
    failed = [name for name, ok in report["checks"].items() if not ok]
    print(
        "OW2_QNN_NUMERIC_CONTRACT_FAILED "
        f"checks={','.join(failed)} report={arguments.output.resolve()}"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
