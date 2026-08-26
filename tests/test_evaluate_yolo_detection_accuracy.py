from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evaluate_yolo_detection_accuracy import (  # noqa: E402
    evaluate_detection_accuracy,
    render_markdown,
)


def test_yolo_detection_accuracy_scores_multiclass_trace_csv(tmp_path: Path) -> None:
    labels = tmp_path / "labels"
    labels.mkdir()
    (labels / "1.txt").write_text(
        "0 0.50 0.50 0.20 0.20\n1 0.25 0.25 0.10 0.10\n",
        encoding="utf-8",
    )
    (labels / "2.txt").write_text("0 0.50 0.50 0.20 0.20\n", encoding="utf-8")
    trace = tmp_path / "trace.csv"
    trace.write_text(
        "\n".join(
            [
                "frame_id,class_id,confidence,x1,y1,x2,y2",
                "1,0,0.90,40,40,60,60",
                "1,1,0.80,20,20,30,30",
                "2,0,0.70,40,40,60,60",
                "2,0,0.60,0,0,10,10",
                "",
            ]
        ),
        encoding="utf-8",
    )

    summary = evaluate_detection_accuracy(
        labels_dir=labels,
        predictions_path=trace,
        model_input_size=100,
        class_names=("body", "head"),
        minimum_confidence=0.50,
        require_complete=True,
        min_map50=0.99,
        min_recall=0.99,
    )

    assert summary["ok"] is True
    assert summary["metrics"]["tp"] == 3
    assert summary["metrics"]["fp"] == 1
    assert summary["metrics"]["fn"] == 0
    assert summary["metrics"]["precision"] == 0.75
    assert summary["metrics"]["recall"] == 1.0
    assert summary["map50"] == 1.0
    assert summary["per_class"]["0"]["name"] == "body"
    assert summary["per_class"]["1"]["name"] == "head"


def test_yolo_detection_accuracy_high_confidence_false_positive_reduces_ap(
    tmp_path: Path,
) -> None:
    labels = tmp_path / "labels"
    labels.mkdir()
    (labels / "sample-a.txt").write_text("0 0.50 0.50 0.20 0.20\n", encoding="utf-8")
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text(
        json.dumps(
            {
                "sample": "sample-a",
                "detections": [
                    {"class_id": 0, "confidence": 0.90, "xywhn": [0.10, 0.10, 0.10, 0.10]},
                    {"class_id": 0, "confidence": 0.80, "xywhn": [0.50, 0.50, 0.20, 0.20]},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    summary = evaluate_detection_accuracy(
        labels_dir=labels,
        predictions_path=predictions,
        model_input_size=100,
        minimum_confidence=0.25,
        min_map50=0.75,
    )

    assert summary["ok"] is False
    assert summary["metrics"]["tp"] == 1
    assert summary["metrics"]["fp"] == 1
    assert summary["metrics"]["fn"] == 0
    assert summary["per_class"]["0"]["ap50"] == 0.5
    assert any("mAP@0.50 below release threshold" in issue for issue in summary["issues"])


def test_yolo_detection_accuracy_requires_complete_prediction_coverage(
    tmp_path: Path,
) -> None:
    labels = tmp_path / "labels"
    labels.mkdir()
    (labels / "1.txt").write_text("0 0.50 0.50 0.20 0.20\n", encoding="utf-8")
    (labels / "2.txt").write_text("0 0.50 0.50 0.20 0.20\n", encoding="utf-8")
    trace = tmp_path / "trace.csv"
    trace.write_text(
        "\n".join(
            [
                "frame_id,class_id,confidence,x1,y1,x2,y2",
                "1,0,0.90,40,40,60,60",
                "",
            ]
        ),
        encoding="utf-8",
    )

    summary = evaluate_detection_accuracy(
        labels_dir=labels,
        predictions_path=trace,
        model_input_size=100,
        require_complete=True,
    )

    assert summary["ok"] is False
    assert summary["missing_prediction_samples"] == ["2"]
    assert any("incomplete prediction coverage" in issue for issue in summary["issues"])


def test_yolo_detection_accuracy_writes_reader_friendly_markdown(tmp_path: Path) -> None:
    labels = tmp_path / "labels"
    labels.mkdir()
    (labels / "1.txt").write_text("0 0.50 0.50 0.20 0.20\n", encoding="utf-8")
    trace = tmp_path / "trace.csv"
    trace.write_text(
        "\n".join(
            [
                "frame_id,class_id,confidence,x1,y1,x2,y2",
                "1,0,0.90,40,40,60,60",
                "",
            ]
        ),
        encoding="utf-8",
    )

    summary = evaluate_detection_accuracy(
        labels_dir=labels,
        predictions_path=trace,
        model_input_size=100,
        require_complete=True,
    )
    markdown = render_markdown(summary)

    assert "# YOLO detection accuracy evaluation" in markdown
    assert "mAP50-95" in markdown
    assert "| Class | GT | Pred | TP | FP | FN | AP50 | mAP50-95 |" in markdown
