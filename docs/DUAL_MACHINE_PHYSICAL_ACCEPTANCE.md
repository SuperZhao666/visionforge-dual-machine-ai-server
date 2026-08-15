# 双机发布版物理验收

本文档定义同一正式 APK 的蓝牙 HID、MAKCU 双路线验收和最终安全空闲收尾。所有设备操作必须由同一名验收人员串行完成。

## 不变量

- 两条路线必须使用同一个 APK SHA256、Android 设备序列号和正式 Host 构建。
- 蓝牙 HID 是扩展路线；最终默认路线必须恢复为 `makcu_usb`。
- 最终触发键必须恢复为 `mouse5`（界面“侧键 2”）。
- 最终状态必须是 Host 已停止推流、APP 自动待命、控制输出关闭、无待完成鼠标移动、正式使用已本地关闭且服务端确认停止。
- 最终安全空闲证据必须晚于两条物理路线的采样结束时间。
- 采集最终 XML 和 APP 导出的 `visionforge-mobile-runtime.jsonl` 后，不得再安装、启动、导航或操作 App、Host、手机。后续只允许离线生成、校验和打包。

## 顺序

1. 对最终 APK 和安装回读 APK 计算 SHA256，确认完全一致。
2. 使用蓝牙 HID 路线完成真实 Windows 光标移动，生成 `bluetooth_hid` 物理路线证据。
3. 使用 MAKCU 路线完成真实 Windows 光标移动，生成 `makcu_usb` 物理路线证据。
4. 停止 Host 推流，验证 APP 自动关闭数据面并等待 `dual_machine_formal_stop_finished local_closed=true server_confirmed=true`，随后保持自动待命且余额不再减少。
5. 重新选择 MAKCU，重新选择“侧键 2”，等待至少一个 5 秒健康周期。
6. 确认最后健康快照为 `phase=ready`、`output_requested=0`、`output_enabled=0`、`native_move_completion_pending=0`。
7. 从右上角导出未截断的单一 `visionforge-mobile-runtime.jsonl` 快照，并采集最终控制页 UI XML。
8. 停止所有设备操作，只执行下面的离线命令。

若路线输出会在采样前把光标推到屏幕边界，应使用采样器的 warmup 区间回中。warmup 样本会标记为无效，分析器不会跨无效区间计算人工跳变；进入正式 measurement 后不得再发送 Windows 输入。

```powershell
python tools\capture_windows_cursor_samples.py `
  --route bluetooth_hid `
  --android-apk $FinalApk `
  --device-serial $DeviceSerial `
  --warmup-seconds 3 `
  --duration-seconds 20 `
  --output $BluetoothCursorSamples
```

## 生成终态证据

```powershell
python tools\final_safe_idle_evidence.py `
  --android-apk $FinalApk `
  --device-serial $DeviceSerial `
  --bluetooth-route-evidence $BluetoothRouteEvidence `
  --makcu-route-evidence $MakcuRouteEvidence `
  --mobile-log $FinalMobileEvents `
  --ui-xml $FinalControlUiXml `
  --output $FinalSafeIdleEvidence `
  --require-complete
```

成功输出必须包含：

```text
VISIONFORGE_FINAL_SAFE_IDLE_EVIDENCE ... complete=True
```

## 生成正式设备证据

`--mobile-log` 必须列出蓝牙路线日志、MAKCU 路线日志和最终安全空闲日志；`--ui-evidence-dir` 必须包含最终安全空闲 XML。

```powershell
python tools\create_formal_device_evidence.py `
  --android-apk $FinalApk `
  --windows-exe $WindowsExe `
  --host-exe $CanonicalHostExe `
  --ui-evidence-dir $UiEvidenceDirectory `
  --mobile-log $BluetoothMobileEvents `
  --mobile-log $MakcuMobileEvents `
  --mobile-log $FinalMobileEvents `
  --bluetooth-route-evidence $BluetoothRouteEvidence `
  --makcu-route-evidence $MakcuRouteEvidence `
  --final-safe-idle-evidence $FinalSafeIdleEvidence `
  --device-serial $DeviceSerial `
  --installed-package-version 1.0.0 `
  --apk-installed `
  --output $FormalDeviceEvidence `
  --require-complete
```

正式设备证据采用 `visionforge-dual-machine-device-evidence-v3`。校验器会从嵌入的原始事件、光标样本和 UI XML 重算双路线与终态检查；手工修改 `checks` 不能形成通过证据。
