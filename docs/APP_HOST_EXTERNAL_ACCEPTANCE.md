# 真实设备与生产环境验收

以下状态均为 `NOT_RUN_EXTERNAL`。包内代码和可移植状态机已经测试，但不能替代目标环境证据。

## Windows Host

- Windows 11/Server 2022，目标 NVIDIA GPU 与正式驱动；
- DXGI `WAIT_TIMEOUT`、`ACCESS_LOST`、设备移除、显示模式切换；
- NVENC 与 Media Foundation fallback；
- 左/上方显示器负坐标和跨显示器区域；
- 每种故障下确认 IDR 请求只在完整发布后消费。

## Android App

- 正式 Android SDK/NDK 与签名配置；
- MediaCodec 重建期间连续 epoch 切换；
- QNN/HTP 各 SoC skel、模型 ABI、温度和内存；
- App 前后台、进程重建、网络切换；
- 观察 active/candidate/retired epoch 和 blocker。

## 物理控制设备

- MAKCU USB 枚举、端点、断开重连和写完成；
- Bluetooth HID 注册、授权、丢事件与幂等 reconcile；
- ticket、late ACK、post-ACK 新鲜画面和 recovery exhausted；
- 控制关闭条件必须先于异步资源清理。

## 网络长稳

- CAT6 与 Wi-Fi 分别执行 2/8/24 小时；
- 注入丢包、重复、乱序、抖动、短断网、Host/App 重启；
- 通过条件：无旧 epoch 回退、无半帧提交、无预测链静默损坏、内存有界、恢复可解释。

## Server 与生产服务商

- 使用 `requirements-dev.lock` 在 Python 3.11 环境跑 Platform/Sidecar 全量 pytest；
- 支付沙箱/正式通知、金额槽并发、outbox 重试；
- SMTP TLS、退信和超时；
- 生产 Ed25519/证书/APK 签名；
- 灾备恢复、数据库迁移、密钥轮换和撤销版本拒绝。
