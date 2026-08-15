# 手机 QNN 数据集回放与精度审计

> Current migration note (2026-08-01): this document is a historical 320x320 dataset replay record. The active four-model mobile runtime now uses 416x416 model contracts.

这是一条离线诊断链路，目的是测量手机上实际 **MediaCodec → 预处理 → QNN HTP → C++ 后处理** 的检测结果。它不连接 MAKCU 输出，也不改变控制输出开关。

## 输入契约

- 图像与标签目录：`D:\software\新建文件夹\images\images1`
- 已生成的确定性输入：`dual_machine_runtime\out\dataset_images1_320.h264`
- 图像、JSON 和 H.264 当前均为 484 帧/项；帧 `N` 对应 `labels\N.txt`。
- 评估目标为标签 class `0` 的人框，输入和模型尺寸均为 `320×320`；IoU 阈值固定为 `0.50`。

## 运行顺序

1. 停止正常桌面推流，避免实时画面与回放帧混入同一 UDP :5000 接收器。
2. 手机启动“本地链路”，但不要启用控制输出。
3. 通过 USB 调试开启有界追踪，例如 100 帧：

```powershell
$adb = 'F:\ADB\platform-tools\adb.exe'
& $adb shell am start -n com.visionforge.mobile/com.visionforge.inferencebenchmark.MainActivity `
  --es com.visionforge.mobile.diagnostic.action begin_detection_trace `
  --ei com.visionforge.mobile.diagnostic.trace_frame_count 100
```

4. 使用 C++ 回放器以不会淹没手机解码队列的速率发送。`frame_id=1..N` 是标签映射证据：

```powershell
dual_machine_runtime\out\VisionForgeDatasetReplay.exe `
  --input dual_machine_runtime\out\dataset_images1_320.h264 `
  --host PHONE_IP --fps 10 --max-frames 100
```

5. 等待最后一帧完成后导出手机端原始追踪，再拉回电脑：

```powershell
& $adb shell am start -n com.visionforge.mobile/com.visionforge.inferencebenchmark.MainActivity `
  --es com.visionforge.mobile.diagnostic.action export_detection_trace
& $adb pull /sdcard/Android/data/com.visionforge.mobile/files/diagnostics/qnn-detection-trace.csv .\qnn-detection-trace.csv
```

6. 用 C++ 评估器输出固定后处理阈值的 Precision、Recall、F1、匹配框平均 IoU，
   以及按置信度排序的 `AP50`、`mAP50-95`（当前标签只有 class 0，故两项以
   `class0` 标示）。必须使用 `--require-complete`；缺帧时命令失败，不能发布精度结论：

```powershell
dual_machine_runtime\out\VisionForgeDatasetEvaluate.exe `
  --labels D:\software\新建文件夹\images\images1\labels `
  --trace .\qnn-detection-trace.csv --max-frames 100 --require-complete
```

## 解释边界

- 这证明手机实际 QNN 路径的检测质量；不是 PC ONNX Runtime、NNAPI 或模拟结果。
- `coverage=1` 只代表采集完整；仍需同时报告 Precision、Recall、F1、IoU、AP50 和 mAP50-95。
- 正常实时桌面流的帧 ID 不在 `1..N` 时，评估器会报告不完整覆盖并拒绝结论。这是防止不同视频源误混的保护。

## 实机验收记录（2026-07-22）

在 `23116PN5BC`（Snapdragon 8 Gen 3）上完成 484/484 帧的严格回放。运行前先停止常规桌面流并等待手机接收/解码队列清空；以 2 帧预热 MediaCodec 后重新从 IDR 开始追踪，最后发送 1 个无标注尾帧冲刷解码器。控制输出始终关闭。

本次可复核证据固定为：

- 检测追踪：`analysis_output/qnn-detection-trace-dataset-484-primed.csv`，SHA256 `D464BDA1B672E08D1A67D9E9BC1EAE08765E905C9826291639E2CA2B837BE3EF`；
- H.264 输入：`dual_machine_runtime/out/dataset_images1_320.h264`，SHA256 `00D6E57B1C9F5F60F5DDB220CA9F55C0696E723A4511680F1245031D108F5775`；
- 本轮复核评估器：`dual_machine_runtime/out_ninja_final6_static/VisionForgeDatasetEvaluate.exe`，SHA256 `8155C5474E27025148A74F9509289D89C33C6E853726C0721D3F77729CAFFA78`。

2026-07-23 重新执行以下严格命令，退出码为 0：

```powershell
dual_machine_runtime\out_ninja_final6_static\VisionForgeDatasetEvaluate.exe `
  --labels D:\software\新建文件夹\images\images1\labels `
  --trace analysis_output\qnn-detection-trace-dataset-484-primed.csv `
  --max-frames 484 --require-complete
```

```text
coverage=1.0000
tp=465 fp=515 fn=20
precision=0.474490
recall=0.958763
f1=0.634812
matched_mean_iou=0.791454
ap50_class0=0.9211
map50_95_class0=0.4892
```

这组数值仅适用于 `images1` 的 484 帧、当前 W8A16 QNN 图和后处理阈值。它是手机真实执行的精度证据，不代表其他数据集、游戏画面或全场景泛化精度。

同目录的 `qnn-detection-trace-dataset-484-final.csv` 只有 482/484 个唯一帧 ID，严格复核会以 `incomplete_trace_coverage` 退出；它不得替代上面的完整 `primed` 证据，也不得用于发布完整覆盖结论。

## 置信度阈值扫描

在同一份完整手机追踪上，仅重放过滤已导出的检测框，得到以下代表性点：

| 最低置信度 | Precision | Recall | F1 |
|---:|---:|---:|---:|
| 0.25（追踪采集下限） | 0.4745 | 0.9588 | 0.6348 |
| 0.75 | 0.4833 | 0.9526 | 0.6412 |
| 0.84 | 0.5114 | 0.9216 | 0.6578 |
| 0.85（F1 最高） | 0.5210 | 0.8948 | 0.6586 |
| 0.86 | 0.0000 | 0.0000 | 0.0000 |

`0.85` 是本数据集的数学 F1 峰值，但它紧贴当前模型输出的置信度上沿；为了给模型量化波动和新场景留下余量，当前产品默认采用 `0.84`，并保留用户可调范围，而不把本次数据集峰值硬编码为全局最优。
