"""Verify CS2 Vombit ONNX equivalence and exact-library phone HTP outputs."""

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


SCHEMA = "visionforge-cs2-qnn-numeric-contract-v1"
BUILD_SCHEMA = "visionforge-cs2-vombit-w8a16-build-v1"
EXECUTION_SCHEMA = "visionforge-cs2-phone-htp-execution-v1"
MODEL_TOKEN = "counter-strike-2-vombit-416-v8s"
INPUT_SIZE = 416
ANCHORS = 3549
CLASSES = 4
CONFIDENCE_THRESHOLD = 0.25
NMS_IOU_THRESHOLD = 0.45
MINIMUM_CLASS_UNIQUE_VALUES = 8
MAXIMUM_CANDIDATE_COORDINATE_ERROR_PIXELS = 2.0
MAXIMUM_CONFIDENCE_ERROR = 0.08
MINIMUM_CANDIDATE_JACCARD = 0.95
MINIMUM_NMS_IOU = 0.84
MAXIMUM_NMS_CENTER_ERROR_PIXELS = 1.0
KNOWN_POSITIVE_SHA256 = (
    "B16F47756FC4DDB445524744947779D7372EED00DDD8172D05148273237B0E53"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _difference(actual: np.ndarray, expected: np.ndarray) -> dict[str, float]:
    absolute = np.abs(actual - expected).reshape(-1)
    return {
        "mean_abs": float(absolute.mean()) if absolute.size else 0.0,
        "p95_abs": float(np.quantile(absolute, 0.95)) if absolute.size else 0.0,
        "max_abs": float(absolute.max()) if absolute.size else 0.0,
    }


def _xywh_to_xyxy(boxes: np.ndarray) -> np.ndarray:
    result = boxes.copy()
    result[:, 0] = boxes[:, 0] - boxes[:, 2] * 0.5
    result[:, 1] = boxes[:, 1] - boxes[:, 3] * 0.5
    result[:, 2] = boxes[:, 0] + boxes[:, 2] * 0.5
    result[:, 3] = boxes[:, 1] + boxes[:, 3] * 0.5
    return result


def _box_iou(left_xywh: np.ndarray, right_xywh: np.ndarray) -> float:
    boxes = _xywh_to_xyxy(np.stack((left_xywh, right_xywh)))
    intersection_left = np.maximum(boxes[0, :2], boxes[1, :2])
    intersection_right = np.minimum(boxes[0, 2:], boxes[1, 2:])
    intersection = float(
        np.prod(np.maximum(0.0, intersection_right - intersection_left))
    )
    areas = np.prod(np.maximum(0.0, boxes[:, 2:] - boxes[:, :2]), axis=1)
    return intersection / max(float(areas.sum()) - intersection, 1e-12)


def _nms_indices(coordinates: np.ndarray, scores: np.ndarray) -> list[int]:
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
        other_areas = np.prod(
            np.maximum(0.0, others[:, 2:] - others[:, :2]), axis=1
        )
        union = np.maximum(selected_area + other_areas - intersection, 1e-12)
        order = remaining[(intersection / union) <= NMS_IOU_THRESHOLD]
    return keep


def _match_nms_targets(
    reference_coordinates: np.ndarray,
    qnn_coordinates: np.ndarray,
    reference_indices: list[int],
    qnn_indices: list[int],
) -> dict[str, Any]:
    if len(reference_indices) != len(qnn_indices):
        return {
            "matched": False,
            "pairs": [],
            "minimum_iou": 0.0,
            "maximum_center_error_pixels": None,
        }
    if not reference_indices:
        return {
            "matched": True,
            "pairs": [],
            "minimum_iou": None,
            "maximum_center_error_pixels": None,
        }
    remaining = set(qnn_indices)
    pairs: list[dict[str, float | int]] = []
    for reference_index in reference_indices:
        qnn_index = max(
            remaining,
            key=lambda candidate: _box_iou(
                reference_coordinates[:, reference_index],
                qnn_coordinates[:, candidate],
            ),
        )
        iou = _box_iou(
            reference_coordinates[:, reference_index],
            qnn_coordinates[:, qnn_index],
        )
        center_error = float(
            np.linalg.norm(
                reference_coordinates[:2, reference_index]
                - qnn_coordinates[:2, qnn_index]
            )
        )
        pairs.append(
            {
                "reference_anchor": reference_index,
                "qnn_anchor": qnn_index,
                "iou": iou,
                "center_error_pixels": center_error,
            }
        )
        remaining.remove(qnn_index)
    return {
        "matched": True,
        "pairs": pairs,
        "minimum_iou": min(float(pair["iou"]) for pair in pairs),
        "maximum_center_error_pixels": max(
            float(pair["center_error_pixels"]) for pair in pairs
        ),
    }


def _load_input(path: Path) -> np.ndarray:
    raw = np.fromfile(path, dtype="<u2")
    expected_elements = INPUT_SIZE * INPUT_SIZE * 3
    if raw.size != expected_elements:
        raise ValueError(
            f"Expected {expected_elements} U16 NHWC values, got {raw.size}: {path}"
        )
    return (
        raw.reshape(1, INPUT_SIZE, INPUT_SIZE, 3)
        .astype(np.float32)
        .transpose(0, 3, 1, 2)
        / 65535.0
    )


def _artifact(path: Path) -> dict[str, str | int]:
    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def verify_numeric_contract(
    *,
    canonical_directory: Path,
    execution_manifest_path: Path,
    known_positive_index: int,
) -> dict[str, Any]:
    canonical_directory = canonical_directory.resolve()
    build_manifest_path = canonical_directory / "build_manifest.json"
    build_manifest = json.loads(build_manifest_path.read_text(encoding="utf-8"))
    execution_manifest = json.loads(
        execution_manifest_path.read_text(encoding="utf-8")
    )
    source = canonical_directory / "source" / "CS2_Vombit_v8s_416.onnx"
    rewritten = canonical_directory / "model" / "cs2_vombit_416_split.onnx"
    library = (
        canonical_directory
        / "android_model_lib"
        / "build"
        / "libcs2_vombit_416_v8s_w8a16.so"
    )
    artifacts = {
        "source_onnx": _artifact(source),
        "rewritten_onnx": _artifact(rewritten),
        "qnn_android_model_library": _artifact(library),
        "build_manifest": _artifact(build_manifest_path),
        "phone_execution_manifest": _artifact(execution_manifest_path),
    }
    artifact_hash_closure = (
        build_manifest.get("schema") == BUILD_SCHEMA
        and build_manifest.get("build_complete") is True
        and build_manifest.get("model", {}).get("token") == MODEL_TOKEN
        and build_manifest["artifacts"]["source_onnx"]["sha256"]
        == artifacts["source_onnx"]["sha256"]
        and build_manifest["artifacts"]["split_onnx"]["sha256"]
        == artifacts["rewritten_onnx"]["sha256"]
        and build_manifest["artifacts"]["android_library"]["sha256"]
        == artifacts["qnn_android_model_library"]["sha256"]
        and execution_manifest.get("schema") == EXECUTION_SCHEMA
        and execution_manifest.get("backend") == "libQnnHtp.so"
        and execution_manifest.get("android_library_sha256")
        == artifacts["qnn_android_model_library"]["sha256"]
        and execution_manifest.get("source_onnx_sha256")
        == artifacts["source_onnx"]["sha256"]
        and execution_manifest.get("split_onnx_sha256")
        == artifacts["rewritten_onnx"]["sha256"]
    )

    source_session = ort.InferenceSession(
        str(source), providers=["CPUExecutionProvider"]
    )
    rewritten_session = ort.InferenceSession(
        str(rewritten), providers=["CPUExecutionProvider"]
    )
    source_input = source_session.get_inputs()[0].name
    rewritten_input = rewritten_session.get_inputs()[0].name
    results = execution_manifest.get("results", [])
    if len(results) != execution_manifest.get("inferences_completed"):
        raise ValueError("Phone execution result count is inconsistent")
    if known_positive_index < 0 or known_positive_index >= len(results):
        raise ValueError("Known-positive result index is out of range")

    result_metrics: list[dict[str, Any]] = []
    combined_qnn_confidences: list[list[np.ndarray]] = [
        [] for _ in range(CLASSES)
    ]
    all_finite = True
    all_static_exact = True
    all_candidate_counts_match = True
    all_candidate_sets_match = True
    all_nms_counts_match = True
    all_nms_boxes_match = True
    maximum_candidate_coordinate_error = 0.0
    maximum_candidate_confidence_error = 0.0
    minimum_matched_nms_iou = 1.0
    maximum_matched_center_error = 0.0

    for result in results:
        input_path = Path(result["input_path"]).resolve()
        coordinates_path = Path(result["coordinates_path"]).resolve()
        confidences_path = Path(result["confidences_path"]).resolve()
        if (
            _sha256(input_path) != result["input_sha256"]
            or _sha256(coordinates_path) != result["coordinates_sha256"]
            or _sha256(confidences_path) != result["confidences_sha256"]
        ):
            artifact_hash_closure = False
        input_tensor = _load_input(input_path)
        mixed = source_session.run(None, {source_input: input_tensor})[0]
        if mixed.shape != (1, 4 + CLASSES, ANCHORS):
            raise ValueError(f"Unexpected source output shape: {mixed.shape}")
        reference_coordinates = mixed[:, :4, :]
        reference_confidences = mixed[:, 4:, :]
        rewritten_outputs = dict(
            zip(
                [output.name for output in rewritten_session.get_outputs()],
                rewritten_session.run(None, {rewritten_input: input_tensor}),
                strict=True,
            )
        )
        split_coordinates = rewritten_outputs["output_coordinates"]
        split_confidences = rewritten_outputs["output_confidences"]
        static_coordinates = _difference(
            split_coordinates, reference_coordinates
        )
        static_confidences = _difference(
            split_confidences, reference_confidences
        )
        static_exact = (
            static_coordinates["max_abs"] == 0.0
            and static_confidences["max_abs"] == 0.0
        )
        all_static_exact = all_static_exact and static_exact

        qnn_coordinates = np.fromfile(coordinates_path, dtype="<f4")
        qnn_confidences = np.fromfile(confidences_path, dtype="<f4")
        if qnn_coordinates.size != 4 * ANCHORS:
            raise ValueError("Unexpected QNN coordinate output size")
        if qnn_confidences.size != CLASSES * ANCHORS:
            raise ValueError("Unexpected QNN confidence output size")
        qnn_coordinates = qnn_coordinates.reshape(1, 4, ANCHORS)
        qnn_confidences = qnn_confidences.reshape(1, CLASSES, ANCHORS)
        finite = bool(
            np.isfinite(qnn_coordinates).all()
            and np.isfinite(qnn_confidences).all()
        )
        all_finite = all_finite and finite
        class_metrics: list[dict[str, Any]] = []
        for class_id in range(CLASSES):
            reference_scores = reference_confidences[0, class_id]
            qnn_scores = qnn_confidences[0, class_id]
            combined_qnn_confidences[class_id].append(qnn_scores)
            reference_candidates = set(
                np.flatnonzero(reference_scores >= CONFIDENCE_THRESHOLD).tolist()
            )
            qnn_candidates = set(
                np.flatnonzero(qnn_scores >= CONFIDENCE_THRESHOLD).tolist()
            )
            candidate_union = reference_candidates | qnn_candidates
            candidate_intersection = reference_candidates & qnn_candidates
            candidate_jaccard = (
                1.0
                if not candidate_union
                else len(candidate_intersection) / len(candidate_union)
            )
            candidate_counts_match = len(reference_candidates) == len(qnn_candidates)
            candidate_sets_match = candidate_jaccard >= MINIMUM_CANDIDATE_JACCARD
            all_candidate_counts_match = (
                all_candidate_counts_match and candidate_counts_match
            )
            all_candidate_sets_match = all_candidate_sets_match and candidate_sets_match
            candidate_indices = np.array(sorted(candidate_union), dtype=np.int64)
            if candidate_indices.size:
                coordinate_error = _difference(
                    qnn_coordinates[0, :, candidate_indices],
                    reference_coordinates[0, :, candidate_indices],
                )
                confidence_error = _difference(
                    qnn_scores[candidate_indices],
                    reference_scores[candidate_indices],
                )
            else:
                coordinate_error = _difference(
                    np.empty(0, dtype=np.float32),
                    np.empty(0, dtype=np.float32),
                )
                confidence_error = coordinate_error.copy()
            maximum_candidate_coordinate_error = max(
                maximum_candidate_coordinate_error,
                coordinate_error["max_abs"],
            )
            maximum_candidate_confidence_error = max(
                maximum_candidate_confidence_error,
                confidence_error["max_abs"],
            )

            reference_nms = _nms_indices(
                reference_coordinates[0], reference_scores
            )
            qnn_nms = _nms_indices(qnn_coordinates[0], qnn_scores)
            nms_match = _match_nms_targets(
                reference_coordinates[0],
                qnn_coordinates[0],
                reference_nms,
                qnn_nms,
            )
            nms_counts_match = len(reference_nms) == len(qnn_nms)
            all_nms_counts_match = all_nms_counts_match and nms_counts_match
            if nms_match["minimum_iou"] is not None:
                minimum_matched_nms_iou = min(
                    minimum_matched_nms_iou,
                    float(nms_match["minimum_iou"]),
                )
                maximum_matched_center_error = max(
                    maximum_matched_center_error,
                    float(nms_match["maximum_center_error_pixels"]),
                )
            nms_boxes_match = (
                nms_match["matched"]
                and (
                    nms_match["minimum_iou"] is None
                    or nms_match["minimum_iou"] >= MINIMUM_NMS_IOU
                )
                and (
                    nms_match["maximum_center_error_pixels"] is None
                    or nms_match["maximum_center_error_pixels"]
                    <= MAXIMUM_NMS_CENTER_ERROR_PIXELS
                )
            )
            all_nms_boxes_match = all_nms_boxes_match and nms_boxes_match
            class_metrics.append(
                {
                    "class_id": class_id,
                    "reference_candidate_count": len(reference_candidates),
                    "qnn_candidate_count": len(qnn_candidates),
                    "candidate_jaccard": candidate_jaccard,
                    "candidate_coordinate_error": coordinate_error,
                    "candidate_confidence_error": confidence_error,
                    "reference_nms_count": len(reference_nms),
                    "qnn_nms_count": len(qnn_nms),
                    "nms_match": nms_match,
                    "qnn_unique_values": int(np.unique(qnn_scores).size),
                    "reference_maximum_confidence": float(reference_scores.max()),
                    "qnn_maximum_confidence": float(qnn_scores.max()),
                }
            )
        result_metrics.append(
            {
                "index": int(result["index"]),
                "input_sha256": result["input_sha256"],
                "static_exact": static_exact,
                "static_coordinates": static_coordinates,
                "static_confidences": static_confidences,
                "qnn_coordinates_all_anchors": _difference(
                    qnn_coordinates, reference_coordinates
                ),
                "qnn_confidences_all_anchors": _difference(
                    qnn_confidences, reference_confidences
                ),
                "finite": finite,
                "classes": class_metrics,
            }
        )

    known_positive = result_metrics[known_positive_index]
    known_positive_all_classes_present = (
        results[known_positive_index]["input_sha256"] == KNOWN_POSITIVE_SHA256
        and all(
            class_metric["reference_nms_count"] > 0
            and class_metric["qnn_nms_count"] > 0
            for class_metric in known_positive["classes"]
        )
    )
    combined_unique_values = [
        int(np.unique(np.concatenate(class_scores)).size)
        for class_scores in combined_qnn_confidences
    ]
    rewritten_model = onnx.load(rewritten)
    rewritten_outputs = [output.name for output in rewritten_model.graph.output]
    source_mixed_output = onnx.load(source).graph.output[0].name
    operation_types = {node.op_type for node in rewritten_model.graph.node}
    split_mixed_domain_output_removed = (
        rewritten_outputs == ["output_coordinates", "output_confidences"]
        and all(
            source_mixed_output not in node.output
            for node in rewritten_model.graph.node
        )
        and not operation_types.intersection({"Range", "ScatterND"})
    )
    checks = {
        "artifact_hash_closure": artifact_hash_closure,
        "source_split_outputs_exact": all_static_exact,
        "split_mixed_domain_output_removed": split_mixed_domain_output_removed,
        "phone_htp_outputs_finite": all_finite,
        "qnn_confidences_not_saturated_per_class": all(
            count >= MINIMUM_CLASS_UNIQUE_VALUES
            for count in combined_unique_values
        ),
        "candidate_counts_match": all_candidate_counts_match,
        "candidate_sets_match": all_candidate_sets_match,
        "candidate_coordinate_error_bounded": (
            maximum_candidate_coordinate_error
            <= MAXIMUM_CANDIDATE_COORDINATE_ERROR_PIXELS
        ),
        "candidate_confidence_error_bounded": (
            maximum_candidate_confidence_error <= MAXIMUM_CONFIDENCE_ERROR
        ),
        "nms_entity_counts_match": all_nms_counts_match,
        "nms_boxes_match": all_nms_boxes_match,
        "known_positive_all_four_classes_present": known_positive_all_classes_present,
        "phone_htp_execution_count_bound": (
            execution_manifest.get("inferences_completed") == len(results)
            and len(results) >= 6
        ),
    }
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "ok": all(checks.values()),
        "model": {
            "token": MODEL_TOKEN,
            "input": [1, 3, INPUT_SIZE, INPUT_SIZE],
            "anchors": ANCHORS,
            "classes": CLASSES,
            "class_names": ["ct_body", "ct_head", "t_body", "t_head"],
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "nms_iou_threshold": NMS_IOU_THRESHOLD,
        },
        "artifacts": artifacts,
        "execution": {
            "backend": execution_manifest.get("backend"),
            "inferences_completed": execution_manifest.get("inferences_completed"),
            "device_identity_path": str(
                (execution_manifest_path.parent / "device_identity.json").resolve()
            ),
            "known_positive_index": known_positive_index,
        },
        "limits": {
            "minimum_class_unique_values": MINIMUM_CLASS_UNIQUE_VALUES,
            "maximum_candidate_coordinate_error_pixels": (
                MAXIMUM_CANDIDATE_COORDINATE_ERROR_PIXELS
            ),
            "maximum_confidence_error": MAXIMUM_CONFIDENCE_ERROR,
            "minimum_candidate_jaccard": MINIMUM_CANDIDATE_JACCARD,
            "minimum_nms_iou": MINIMUM_NMS_IOU,
            "maximum_nms_center_error_pixels": (
                MAXIMUM_NMS_CENTER_ERROR_PIXELS
            ),
        },
        "summary": {
            "combined_qnn_unique_values_per_class": combined_unique_values,
            "maximum_candidate_coordinate_error_pixels": (
                maximum_candidate_coordinate_error
            ),
            "maximum_candidate_confidence_error": (
                maximum_candidate_confidence_error
            ),
            "minimum_matched_nms_iou": minimum_matched_nms_iou,
            "maximum_matched_nms_center_error_pixels": (
                maximum_matched_center_error
            ),
        },
        "checks": checks,
        "results": result_metrics,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical-directory", type=Path, required=True)
    parser.add_argument("--execution-manifest", type=Path, required=True)
    parser.add_argument("--known-positive-index", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    report = verify_numeric_contract(
        canonical_directory=arguments.canonical_directory,
        execution_manifest_path=arguments.execution_manifest.resolve(),
        known_positive_index=arguments.known_positive_index,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "CS2_QNN_NUMERIC_CONTRACT_OK "
        f"ok={str(report['ok']).lower()} "
        f"library_sha256={report['artifacts']['qnn_android_model_library']['sha256']} "
        f"report={arguments.output.resolve()}"
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
