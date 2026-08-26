from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


MAP_THRESHOLDS = tuple(round(value / 100.0, 2) for value in range(50, 100, 5))
TRACE_CSV_HEADER = ("frame_id", "class_id", "confidence", "x1", "y1", "x2", "y2")


@dataclass(frozen=True, slots=True)
class Box:
    sample_id: str
    class_id: int
    confidence: float
    x1: float
    y1: float
    x2: float
    y2: float


@dataclass(frozen=True, slots=True)
class EvaluationInputs:
    ground_truth: Mapping[str, tuple[Box, ...]]
    predictions: tuple[Box, ...]
    seen_prediction_samples: frozenset[str]


def read_yolo_labels(labels_dir: Path, model_input_size: float) -> dict[str, tuple[Box, ...]]:
    if not labels_dir.is_dir():
        raise ValueError(f"labels directory is missing: {labels_dir}")
    label_paths = sorted(labels_dir.glob("*.txt"), key=lambda path: _sample_sort_key(path.stem))
    if not label_paths:
        raise ValueError(f"no YOLO label files found under: {labels_dir}")

    samples: dict[str, tuple[Box, ...]] = {}
    for label_path in label_paths:
        boxes: list[Box] = []
        for line_number, raw_line in enumerate(
            label_path.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 5:
                raise ValueError(f"invalid YOLO row {label_path}:{line_number}")
            class_id = _parse_class_id(fields[0], label_path, line_number)
            center_x, center_y, width, height = (
                _parse_finite_float(value, label_path, line_number)
                for value in fields[1:5]
            )
            boxes.append(
                Box(
                    sample_id=label_path.stem,
                    class_id=class_id,
                    confidence=1.0,
                    x1=(center_x - width * 0.5) * model_input_size,
                    y1=(center_y - height * 0.5) * model_input_size,
                    x2=(center_x + width * 0.5) * model_input_size,
                    y2=(center_y + height * 0.5) * model_input_size,
                )
            )
        samples[label_path.stem] = tuple(box for box in boxes if _is_valid_box(box))
    return samples


def read_predictions(
    predictions_path: Path,
    model_input_size: float,
) -> tuple[tuple[Box, ...], frozenset[str]]:
    if not predictions_path.is_file():
        raise ValueError(f"predictions file is missing: {predictions_path}")
    text = predictions_path.read_text(encoding="utf-8", errors="replace")
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    if predictions_path.suffix.lower() == ".csv" or first_line == ",".join(TRACE_CSV_HEADER):
        return _read_trace_csv(predictions_path)
    return _read_prediction_json(text, model_input_size)


def evaluate_detection_accuracy(
    *,
    labels_dir: Path,
    predictions_path: Path,
    model_input_size: float = 416.0,
    class_names: Sequence[str] = (),
    minimum_confidence: float = 0.25,
    match_iou: float = 0.50,
    require_complete: bool = False,
    min_map50: float | None = None,
    min_map50_95: float | None = None,
    min_precision: float | None = None,
    min_recall: float | None = None,
) -> dict[str, Any]:
    _validate_options(model_input_size, minimum_confidence, match_iou)
    ground_truth = read_yolo_labels(labels_dir, model_input_size)
    predictions, seen_samples = read_predictions(predictions_path, model_input_size)
    inputs = EvaluationInputs(
        ground_truth=ground_truth,
        predictions=tuple(predictions),
        seen_prediction_samples=frozenset(seen_samples),
    )
    return evaluate_inputs(
        inputs,
        class_names=class_names,
        minimum_confidence=minimum_confidence,
        match_iou=match_iou,
        require_complete=require_complete,
        min_map50=min_map50,
        min_map50_95=min_map50_95,
        min_precision=min_precision,
        min_recall=min_recall,
    )


def evaluate_inputs(
    inputs: EvaluationInputs,
    *,
    class_names: Sequence[str] = (),
    minimum_confidence: float = 0.25,
    match_iou: float = 0.50,
    require_complete: bool = False,
    min_map50: float | None = None,
    min_map50_95: float | None = None,
    min_precision: float | None = None,
    min_recall: float | None = None,
) -> dict[str, Any]:
    expected_samples = frozenset(inputs.ground_truth)
    missing_samples = sorted(
        expected_samples - inputs.seen_prediction_samples,
        key=_sample_sort_key,
    )
    unknown_samples = sorted(
        inputs.seen_prediction_samples - expected_samples,
        key=_sample_sort_key,
    )
    predictions = tuple(
        prediction
        for prediction in inputs.predictions
        if prediction.confidence >= minimum_confidence
    )
    classes = _collect_class_ids(inputs.ground_truth, inputs.predictions)
    overall = _score_at_threshold(
        predictions,
        inputs.ground_truth,
        class_id=None,
        iou_threshold=match_iou,
    )
    per_class: dict[str, dict[str, Any]] = {}
    ap50_values: list[float] = []
    map50_95_values: list[float] = []
    for class_id in classes:
        class_key = str(class_id)
        class_score = _score_at_threshold(
            predictions,
            inputs.ground_truth,
            class_id=class_id,
            iou_threshold=match_iou,
        )
        ap50 = _average_precision(
            inputs.predictions,
            inputs.ground_truth,
            class_id=class_id,
            iou_threshold=0.50,
        )
        threshold_aps = [
            value
            for value in (
                _average_precision(
                    inputs.predictions,
                    inputs.ground_truth,
                    class_id=class_id,
                    iou_threshold=threshold,
                )
                for threshold in MAP_THRESHOLDS
            )
            if value is not None
        ]
        class_map50_95 = _mean(threshold_aps)
        if ap50 is not None:
            ap50_values.append(ap50)
        if class_map50_95 is not None:
            map50_95_values.append(class_map50_95)
        per_class[class_key] = {
            "name": class_names[class_id] if 0 <= class_id < len(class_names) else class_key,
            "ground_truth": _count_ground_truth(inputs.ground_truth, class_id),
            "predictions_at_threshold": sum(
                1 for prediction in predictions if prediction.class_id == class_id
            ),
            **class_score,
            "ap50": _round_optional(ap50),
            "map50_95": _round_optional(class_map50_95),
        }

    map50 = _mean(ap50_values)
    map50_95 = _mean(map50_95_values)
    issues = _collect_issues(
        require_complete=require_complete,
        missing_samples=missing_samples,
        unknown_samples=unknown_samples,
        ground_truth_boxes=sum(len(boxes) for boxes in inputs.ground_truth.values()),
        metrics=overall,
        map50=map50,
        map50_95=map50_95,
        min_map50=min_map50,
        min_map50_95=min_map50_95,
        min_precision=min_precision,
        min_recall=min_recall,
    )
    return {
        "ok": not issues,
        "issues": issues,
        "sample_count": len(inputs.ground_truth),
        "prediction_sample_count": len(inputs.seen_prediction_samples),
        "missing_prediction_samples": missing_samples,
        "unknown_prediction_samples": unknown_samples,
        "minimum_confidence": minimum_confidence,
        "match_iou": match_iou,
        "map_thresholds": list(MAP_THRESHOLDS),
        "metrics": overall,
        "map50": _round_optional(map50),
        "map50_95": _round_optional(map50_95),
        "per_class": per_class,
    }


def write_reports(
    summary: Mapping[str, Any],
    *,
    output_json: Path | None,
    output_markdown: Path | None,
) -> None:
    if output_json is not None:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if output_markdown is not None:
        output_markdown.parent.mkdir(parents=True, exist_ok=True)
        output_markdown.write_text(render_markdown(summary), encoding="utf-8")


def render_markdown(summary: Mapping[str, Any]) -> str:
    status = "PASS" if summary["ok"] else "FAIL"
    metrics = summary["metrics"]
    lines = [
        "# YOLO detection accuracy evaluation",
        "",
        f"- Status: {status}",
        f"- Samples: {summary['sample_count']}",
        f"- Prediction samples: {summary['prediction_sample_count']}",
        f"- Confidence threshold: {summary['minimum_confidence']}",
        f"- Match IoU: {summary['match_iou']}",
        f"- Precision / Recall / F1: {metrics['precision']:.6f} / "
        f"{metrics['recall']:.6f} / {metrics['f1']:.6f}",
        f"- mAP@0.50: {_format_optional(summary['map50'])}",
        f"- mAP50-95: {_format_optional(summary['map50_95'])}",
        "",
        "| Class | GT | Pred | TP | FP | FN | AP50 | mAP50-95 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for class_id, row in summary["per_class"].items():
        lines.append(
            f"| {row['name']} (`{class_id}`) | {row['ground_truth']} | "
            f"{row['predictions_at_threshold']} | {row['tp']} | {row['fp']} | "
            f"{row['fn']} | {_format_optional(row['ap50'])} | "
            f"{_format_optional(row['map50_95'])} |"
        )
    if summary["issues"]:
        lines.extend(["", "## Issues"])
        lines.extend(f"- {issue}" for issue in summary["issues"])
    return "\n".join(lines) + "\n"


def _read_trace_csv(path: Path) -> tuple[tuple[Box, ...], frozenset[str]]:
    predictions: list[Box] = []
    seen_samples: set[str] = set()
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != TRACE_CSV_HEADER:
            raise ValueError("trace CSV header must be frame_id,class_id,confidence,x1,y1,x2,y2")
        for row_number, row in enumerate(reader, start=2):
            sample_id = str(row["frame_id"]).strip()
            if not sample_id:
                raise ValueError(f"missing frame_id at {path}:{row_number}")
            seen_samples.add(sample_id)
            class_token = str(row["class_id"]).strip()
            if class_token == "-1":
                continue
            box = Box(
                sample_id=sample_id,
                class_id=int(class_token),
                confidence=_parse_confidence(row["confidence"], path, row_number),
                x1=_parse_finite_float(row["x1"], path, row_number),
                y1=_parse_finite_float(row["y1"], path, row_number),
                x2=_parse_finite_float(row["x2"], path, row_number),
                y2=_parse_finite_float(row["y2"], path, row_number),
            )
            if _is_valid_box(box):
                predictions.append(box)
    return tuple(predictions), frozenset(seen_samples)


def _read_prediction_json(
    text: str,
    model_input_size: float,
) -> tuple[tuple[Box, ...], frozenset[str]]:
    entries = _load_prediction_entries(text)
    predictions: list[Box] = []
    seen_samples: set[str] = set()
    for index, entry in enumerate(entries, start=1):
        sample_id = _entry_sample_id(entry)
        seen_samples.add(sample_id)
        detections = entry.get("detections")
        raw_detections = detections if isinstance(detections, list) else [entry]
        for raw_detection in raw_detections:
            if not isinstance(raw_detection, Mapping):
                raise ValueError(f"invalid detection object in JSON entry {index}")
            if "class_id" not in raw_detection and "class" not in raw_detection:
                continue
            box = _json_detection_box(sample_id, raw_detection, model_input_size, index)
            if _is_valid_box(box):
                predictions.append(box)
    return tuple(predictions), frozenset(seen_samples)


def _load_prediction_entries(text: str) -> list[Mapping[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped[0] in "[{":
        payload = json.loads(stripped)
        if isinstance(payload, Mapping):
            raw_entries = payload.get("samples", [payload])
        else:
            raw_entries = payload
        if not isinstance(raw_entries, list):
            raise ValueError("prediction JSON must be an object or list")
        return [_require_mapping(entry) for entry in raw_entries]
    entries: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(stripped.splitlines(), start=1):
        try:
            entries.append(_require_mapping(json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL row {line_number}: {exc}") from exc
    return entries


def _json_detection_box(
    sample_id: str,
    detection: Mapping[str, Any],
    model_input_size: float,
    entry_index: int,
) -> Box:
    class_id = int(detection.get("class_id", detection.get("class")))
    confidence = float(detection.get("confidence", detection.get("score", 0.0)))
    if not math.isfinite(confidence) or confidence < 0.0 or confidence > 1.0:
        raise ValueError(f"invalid confidence in JSON entry {entry_index}")
    if "xyxyn" in detection:
        x1, y1, x2, y2 = _scaled_tuple(detection["xyxyn"], model_input_size)
    elif "xywhn" in detection:
        center_x, center_y, width, height = _scaled_tuple(
            detection["xywhn"],
            model_input_size,
        )
        x1, y1, x2, y2 = (
            center_x - width * 0.5,
            center_y - height * 0.5,
            center_x + width * 0.5,
            center_y + height * 0.5,
        )
    elif "xyxy" in detection:
        x1, y1, x2, y2 = _number_tuple(detection["xyxy"], expected=4)
    elif "xywh" in detection:
        center_x, center_y, width, height = _number_tuple(detection["xywh"], expected=4)
        x1, y1, x2, y2 = (
            center_x - width * 0.5,
            center_y - height * 0.5,
            center_x + width * 0.5,
            center_y + height * 0.5,
        )
    else:
        x1, y1, x2, y2 = (
            float(detection["x1"]),
            float(detection["y1"]),
            float(detection["x2"]),
            float(detection["y2"]),
        )
    return Box(sample_id, class_id, confidence, x1, y1, x2, y2)


def _score_at_threshold(
    predictions: Sequence[Box],
    ground_truth: Mapping[str, tuple[Box, ...]],
    *,
    class_id: int | None,
    iou_threshold: float,
) -> dict[str, Any]:
    matched: dict[str, list[bool]] = {}
    for sample_id, boxes in ground_truth.items():
        filtered_boxes = _filter_class(boxes, class_id)
        matched[sample_id] = [False] * len(filtered_boxes)
    sorted_predictions = sorted(
        (box for box in predictions if class_id is None or box.class_id == class_id),
        key=lambda box: box.confidence,
        reverse=True,
    )
    true_positive = 0
    false_positive = 0
    matched_iou_sum = 0.0
    filtered_ground_truth = {
        sample_id: _filter_class(boxes, class_id)
        for sample_id, boxes in ground_truth.items()
    }
    for prediction in sorted_predictions:
        boxes = filtered_ground_truth.get(prediction.sample_id, ())
        best_index = -1
        best_iou = 0.0
        for index, truth in enumerate(boxes):
            if matched[prediction.sample_id][index]:
                continue
            if prediction.class_id != truth.class_id:
                continue
            iou = intersection_over_union(prediction, truth)
            if iou > best_iou:
                best_iou = iou
                best_index = index
        if best_index >= 0 and best_iou >= iou_threshold:
            matched[prediction.sample_id][best_index] = True
            true_positive += 1
            matched_iou_sum += best_iou
        else:
            false_positive += 1
    false_negative = sum(
        1
        for sample_id, boxes in filtered_ground_truth.items()
        for index in range(len(boxes))
        if not matched[sample_id][index]
    )
    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    f1 = _safe_ratio(2.0 * precision * recall, precision + recall)
    return {
        "tp": true_positive,
        "fp": false_positive,
        "fn": false_negative,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "matched_mean_iou": round(
            _safe_ratio(matched_iou_sum, true_positive),
            6,
        ),
    }


def _average_precision(
    predictions: Sequence[Box],
    ground_truth: Mapping[str, tuple[Box, ...]],
    *,
    class_id: int,
    iou_threshold: float,
) -> float | None:
    ground_truth_by_sample = {
        sample_id: tuple(box for box in boxes if box.class_id == class_id)
        for sample_id, boxes in ground_truth.items()
    }
    ground_truth_count = sum(len(boxes) for boxes in ground_truth_by_sample.values())
    if ground_truth_count == 0:
        return None
    matched = {
        sample_id: [False] * len(boxes)
        for sample_id, boxes in ground_truth_by_sample.items()
    }
    true_positive = 0
    false_positive = 0
    points: list[tuple[float, float]] = []
    for prediction in sorted(
        (box for box in predictions if box.class_id == class_id),
        key=lambda box: box.confidence,
        reverse=True,
    ):
        boxes = ground_truth_by_sample.get(prediction.sample_id, ())
        best_index = -1
        best_iou = 0.0
        for index, truth in enumerate(boxes):
            if matched[prediction.sample_id][index]:
                continue
            iou = intersection_over_union(prediction, truth)
            if iou > best_iou:
                best_iou = iou
                best_index = index
        if best_index >= 0 and best_iou >= iou_threshold:
            matched[prediction.sample_id][best_index] = True
            true_positive += 1
        else:
            false_positive += 1
        precision = true_positive / (true_positive + false_positive)
        recall = true_positive / ground_truth_count
        points.append((recall, precision))
    return round(
        sum(
            max(
                (precision for recall, precision in points if recall >= threshold / 100.0),
                default=0.0,
            )
            for threshold in range(101)
        )
        / 101.0,
        6,
    )


def intersection_over_union(left: Box, right: Box) -> float:
    x1 = max(left.x1, right.x1)
    y1 = max(left.y1, right.y1)
    x2 = min(left.x2, right.x2)
    y2 = min(left.y2, right.y2)
    intersection = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    left_area = max(0.0, left.x2 - left.x1) * max(0.0, left.y2 - left.y1)
    right_area = max(0.0, right.x2 - right.x1) * max(0.0, right.y2 - right.y1)
    union = left_area + right_area - intersection
    return intersection / union if union > 0.0 else 0.0


def _collect_issues(
    *,
    require_complete: bool,
    missing_samples: Sequence[str],
    unknown_samples: Sequence[str],
    ground_truth_boxes: int,
    metrics: Mapping[str, Any],
    map50: float | None,
    map50_95: float | None,
    min_map50: float | None,
    min_map50_95: float | None,
    min_precision: float | None,
    min_recall: float | None,
) -> list[str]:
    issues: list[str] = []
    if ground_truth_boxes <= 0:
        issues.append("no ground-truth boxes; accuracy conclusion is invalid")
    if require_complete and missing_samples:
        issues.append(f"incomplete prediction coverage: missing {len(missing_samples)} samples")
    if require_complete and unknown_samples:
        issues.append(f"prediction file contains {len(unknown_samples)} unknown samples")
    _append_minimum_issue(issues, "precision", metrics["precision"], min_precision)
    _append_minimum_issue(issues, "recall", metrics["recall"], min_recall)
    _append_minimum_issue(issues, "mAP@0.50", map50, min_map50)
    _append_minimum_issue(issues, "mAP50-95", map50_95, min_map50_95)
    return issues


def _append_minimum_issue(
    issues: list[str],
    name: str,
    actual: float | None,
    minimum: float | None,
) -> None:
    if minimum is None:
        return
    if actual is None or actual < minimum:
        issues.append(f"{name} below release threshold: {actual} < {minimum}")


def _validate_options(
    model_input_size: float,
    minimum_confidence: float,
    match_iou: float,
) -> None:
    if not math.isfinite(model_input_size) or model_input_size <= 0.0:
        raise ValueError("--model-input-size must be positive")
    if not math.isfinite(minimum_confidence) or not 0.0 <= minimum_confidence <= 1.0:
        raise ValueError("--minimum-confidence must be within [0, 1]")
    if not math.isfinite(match_iou) or not 0.0 < match_iou <= 1.0:
        raise ValueError("--match-iou must be within (0, 1]")


def _parse_class_id(value: str, path: Path, line_number: int) -> int:
    try:
        class_id = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid class id at {path}:{line_number}") from exc
    if class_id < 0:
        raise ValueError(f"negative class id at {path}:{line_number}")
    return class_id


def _parse_confidence(value: str, path: Path, line_number: int) -> float:
    confidence = _parse_finite_float(value, path, line_number)
    if confidence < 0.0 or confidence > 1.0:
        raise ValueError(f"confidence outside [0, 1] at {path}:{line_number}")
    return confidence


def _parse_finite_float(value: object, path: Path, line_number: int) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid number at {path}:{line_number}") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite number at {path}:{line_number}")
    return parsed


def _entry_sample_id(entry: Mapping[str, Any]) -> str:
    for key in ("sample", "stem", "frame_id", "image"):
        value = entry.get(key)
        if value is not None:
            return Path(str(value)).stem
    raise ValueError("prediction entry is missing sample/stem/frame_id/image")


def _number_tuple(value: object, *, expected: int) -> tuple[float, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("box coordinates must be a numeric sequence")
    numbers = tuple(float(item) for item in value)
    if len(numbers) != expected or any(not math.isfinite(item) for item in numbers):
        raise ValueError("box coordinates have invalid length or value")
    return numbers


def _scaled_tuple(value: object, scale: float) -> tuple[float, ...]:
    return tuple(item * scale for item in _number_tuple(value, expected=4))


def _require_mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("prediction entry must be a JSON object")
    return value


def _is_valid_box(box: Box) -> bool:
    return (
        box.class_id >= 0
        and math.isfinite(box.confidence)
        and all(math.isfinite(value) for value in (box.x1, box.y1, box.x2, box.y2))
        and box.x2 > box.x1
        and box.y2 > box.y1
    )


def _filter_class(boxes: Iterable[Box], class_id: int | None) -> tuple[Box, ...]:
    if class_id is None:
        return tuple(boxes)
    return tuple(box for box in boxes if box.class_id == class_id)


def _count_ground_truth(ground_truth: Mapping[str, tuple[Box, ...]], class_id: int) -> int:
    return sum(1 for boxes in ground_truth.values() for box in boxes if box.class_id == class_id)


def _collect_class_ids(
    ground_truth: Mapping[str, tuple[Box, ...]],
    predictions: Sequence[Box],
) -> tuple[int, ...]:
    class_ids = {
        box.class_id
        for boxes in ground_truth.values()
        for box in boxes
    }
    class_ids.update(box.class_id for box in predictions)
    return tuple(sorted(class_ids))


def _mean(values: Sequence[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 6)


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _round_optional(value: float | None) -> float | None:
    return None if value is None else round(value, 6)


def _format_optional(value: object) -> str:
    if value is None:
        return "--"
    return f"{float(value):.6f}"


def _sample_sort_key(value: str) -> tuple[int, int | str]:
    return (0, int(value)) if value.isdigit() else (1, value)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate YOLO detection accuracy from normalized label txt files "
            "and VisionForge mobile trace CSV or prediction JSON/JSONL."
        ),
    )
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--model-input-size", type=float, default=416.0)
    parser.add_argument("--class-names", default="")
    parser.add_argument("--minimum-confidence", type=float, default=0.25)
    parser.add_argument("--match-iou", type=float, default=0.50)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--min-map50", type=float)
    parser.add_argument("--min-map50-95", type=float)
    parser.add_argument("--min-precision", type=float)
    parser.add_argument("--min-recall", type=float)
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-md", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = evaluate_detection_accuracy(
        labels_dir=args.labels,
        predictions_path=args.predictions,
        model_input_size=args.model_input_size,
        class_names=tuple(name.strip() for name in args.class_names.split(",") if name.strip()),
        minimum_confidence=args.minimum_confidence,
        match_iou=args.match_iou,
        require_complete=args.require_complete,
        min_map50=args.min_map50,
        min_map50_95=args.min_map50_95,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
    )
    write_reports(summary, output_json=args.output_json, output_markdown=args.output_md)
    print(
        "OW2_MOBILE_ACCURACY_EVALUATION_OK"
        if summary["ok"]
        else "OW2_MOBILE_ACCURACY_EVALUATION_FAILED"
    )
    print(render_markdown(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
