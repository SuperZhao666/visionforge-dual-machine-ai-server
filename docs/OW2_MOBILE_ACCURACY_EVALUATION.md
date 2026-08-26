# OW2 手机模型精度评测门禁

OW2 的手机 QNN 性能已经可以单独验收，但性能不等于可发布。`overwatch2-416-yolov5` 在进入正式生产模型列表前，必须在有标注数据集上跑完整精度评测。

当前项目使用轻量评估器：

```powershell
python tools\evaluate_yolo_detection_accuracy.py `
  --labels D:\datasets\ow2\labels `
  --predictions .\qnn-detection-trace.csv `
  --model-input-size 416 `
  --class-names class_0,class_1 `
  --minimum-confidence 0.25 `
  --require-complete `
  --output-json analysis_output\ow2_accuracy\metrics.json `
  --output-md analysis_output\ow2_accuracy\metrics.md
```

## 输入契约

- `--labels` 指向 YOLO txt 标签目录，文件名 stem 必须与预测样本一致，例如 `1.txt` 对应手机 trace 的 `frame_id=1`。
- 标签行格式为 `class_id x_center y_center width height`，坐标为归一化 YOLO 坐标。
- `--predictions` 可直接使用手机导出的检测追踪 CSV，表头必须是 `frame_id,class_id,confidence,x1,y1,x2,y2`。
- 预测框坐标与 `--model-input-size` 同坐标系；OW2 当前模型输入为 `416`。
- 也可使用 JSON / JSONL 预测记录；每条记录包含 `sample` / `stem` / `frame_id` / `image` 与 `detections`，检测框支持 `xyxyn`、`xywhn`、`xyxy` 或 `xywh`。

## 输出指标

评估器会输出：

- 全局 TP、FP、FN、Precision、Recall、F1、匹配框平均 IoU。
- 每个 class 的 AP50 与 mAP50-95。
- 全局 mAP@0.50 与 mAP50-95。
- 缺失预测样本与未知预测样本；开启 `--require-complete` 后这些问题会让命令 fail-close。

## 发布规则

- 不允许仅凭 QNN FPS、graphExecute 耗时或输出 fingerprint 判断 OW2 可以发布。
- 未通过 `--require-complete` 的 OW2 标注数据集评测前，OW2 必须保留为实验/评测模型，不允许进入正式生产模型列表。
- 正式发布时应额外带上项目当期阈值，例如 `--min-map50`、`--min-map50-95`、`--min-precision`、`--min-recall`；阈值由实际业务验收口径决定，不能在无标注数据时硬编造。
