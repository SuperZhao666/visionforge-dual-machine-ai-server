# R3 目标设备与生产环境验收

下列项目在可移植 Linux 环境中无法真实证明，最终状态必须是 `NOT_RUN_EXTERNAL` 或
`NOT_RUN_ENVIRONMENT`，不得改写为 PASS。

## Windows Host

- 多显示器含负坐标的 DXGI 捕获；
- WAIT_TIMEOUT、ACCESS_LOST、显示模式切换和设备移除；
- NVENC 与 Media Foundation 实际编码及回退；
- 真实 CAT6/Wi-Fi 丢包、乱序、断网、网卡替换；
- stream epoch 状态文件在 Windows 锁、崩溃和多实例下的耐久性；
- 2/8/24 小时持续运行及内存、句柄、GPU 资源趋势。

## Android

- MediaCodec 重建、切前后台、锁屏、温控和内存压力；
- Qualcomm QNN/HTP 私有 SDK、模型、SoC 架构和持续推理；
- MAKCU USB、Bluetooth HID、权限、拔插和设备切换；
- 真机 ACK 后新鲜画面可见性与控制阻断。

## Server/商业链路

- 安装锁定 requirements 后的全量 Platform/Sidecar pytest；
- 支付商回调、金额槽位并发、outbox 崩溃恢复；
- SMTP 实际投递；
- 生产证书、私钥、APK/Host 正式签名；
- Runtime Catalog/Release Manifest 正式发布；
- 灾备恢复后的数据库迁移和密钥配对。

每一项必须保存：设备与版本、命令、配置、原始日志、开始/结束时间、失败回滚和最终签字。
