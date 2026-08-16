# VisionForge 系统架构

## 1. 架构目标

本次重建不以“把所有逻辑塞回一个可运行进程”为目标，而是建立可验证的边界：

- **领域规则不依赖框架**：业务不变量、帧身份和状态机不直接依赖 FastAPI、SQLite、socket 或 Android UI。
- **外部调用不进入核心事务或状态锁**：数据库事务不包围 Sidecar 网络请求；Host 的状态锁不包围 UDP sink。
- **失败必须形成明确终态**：异常不能被吞掉后继续报告成功；超时不能自动放行旧画面或旧 ticket。
- **跨语言协议只有一份语义**：Java 与 C++ 对 epoch、sequence、分片上限和绝对 deadline 使用同一范围。
- **交付本身可验证**：最终包由原子构建器生成，内部清单逐文件绑定大小与 SHA-256。

## 2. 总体组件

```text
支付/注册/客户端请求
        │
        ▼
Platform HTTP Interface
        │
        ▼
Application Use Cases ──────► Domain Ports / Value Objects
        │                              ▲
        ▼                              │
SQLite / SMTP / Crypto / HTTP Sidecar Adapters
        │
        ├── immutable entitlement outbox ──► Worker ──► Sidecar
        └── signed release/runtime catalog

Windows Host
Capture → Encode → FrameIdentity → Fragment → DatagramSink
                                  │
                                  ▼
Mobile APP
Header decode → bounded reassembly → Annex-B classification
→ ordered handoff → decoder restart coordinator → decoded metadata
→ post-ACK visibility / control decision
```

## 3. Python 服务端分层

### 3.1 `domain`

`domain` 保存：

- 订单、支付事件、entitlement、健康状态等值对象；
- 应用层所需的端口协议；
- 统一错误类型及 HTTP 映射所需语义。

它不导入 FastAPI、SQLite、HTTPX 或具体 Sidecar 客户端。

### 3.2 `application`

`application` 编排用例：

- 创建、取消、结算订单；
- 将支付事实与不可变 outbox 在同一数据库事务中落盘；
- 租约领取、确认、退避与 dead-letter；
- 注册挑战、持久化限流、heartbeat、业务 readiness；
- 签名发布目录与 usage ticket 规则。

统一 `Clock` 从组合根注入。安全令牌、TOTP、HMAC、限流、支付和 outbox 不再各自读取系统时间。

### 3.3 `infrastructure`

基础设施适配器负责：

- SQLite 事务、schema 与约束错误翻译；
- SMTP；
- Ed25519/HMAC/TOTP；
- 有界、禁止重定向、严格 URL 的 Sidecar HTTP 调用；
- 用户令牌、usage ticket 与持久化 outbox。

网络调用发生在数据库事务之外。Sidecar 响应在解析 JSON 前执行字节上限。

### 3.4 `interfaces` 与 `bootstrap`

`interfaces` 只处理 HTTP/CLI 边界：原始请求体、认证头、DTO、状态码和用例调用。所有签名端点通过同一 64 KiB 流式读取器读取原始字节。

`bootstrap/container.py` 是唯一组合根，负责共享：

- `Clock`；
- 数据库与迁移；
- 认证器与签名器；
- Sidecar adapter；
- health checks 与应用服务。

## 4. C++ Host 分层

### 4.1 `domain`

- `FrameIdentity`：`(stream_epoch, frame_sequence)`，epoch 限制在 Java 可表示的正有符号 `long` 范围。
- `DecodedFrameMetadataLedger`：拒绝退休 epoch、序号回退、同身份语义冲突；新 epoch 必须由新鲜 IDR 建立。
- `VideoPipelineStatus`：线程安全、低基数、单调身份；APP 解码确认不能越过 Host 完整发布高水位。
- `VirtualDesktopMapper`：支持多显示器负坐标与边界验证。

### 4.2 `application`

- `HostStreamingOrchestrator`：区分正常帧、等待超时、access lost、device removed 与失败。
- `VideoDeliveryLedger`：每个分片只有一个交付终态，完整 IDR 必须全部唯一分片发送成功。
- `ControlCommandCoordinator`：精确 ticket、deadline、可见性和 blocker 编排。

### 4.3 `infrastructure`

- `DatagramFragmenter`：统一 wire header 与分片上限。
- `FileEpochReservationStore`：原子替换、文件 `fsync`、目录 `fsync`；持久化失败不继续使用未保证唯一的 epoch。

### 4.4 `interfaces`

`HostRuntimeCompositionRoot` 串联采集、身份生成、发布、状态与 APP 回调。它使用：

- `capture_mutex_`：只串行化产生 frame identity 的采集事务；
- `state_mutex_`：保护短时状态读取/更新；
- 外部 sink 调用期间不持有 `state_mutex_`，避免重入死锁。

## 5. Java Mobile 分层

- `domain.video`：协议头、epoch guard、Annex-B 分类、按序 handoff、解码元数据。
- `domain.control`：ticket、ACK 后可见性、Bluetooth reconcile、控制决策。
- `application`：有界重组与运行时组合根。
- `ports`：解码、恢复、诊断端口；Android Service/Activity 只实现适配器。
- `core`：兼容 API 与原子只读状态，不再复制领域协议规则。

## 6. 关键不变量

1. 空 DATA、畸形头或 REPEAT 不能推进 epoch。
2. 新 epoch 的普通预测帧不能提前重启旧解码器；必须先获得完整、有效 IDR。
3. restart 期间只合并到最新目标；迟到旧回调不终止新重启。
4. 同一帧身份的内容/语义冲突一律 fail-closed。
5. ACK 后必须观察到身份更晚、内容更新且时间戳可信的画面；deadline 到达后进入恢复，不自动放行。
6. ticket 只有一个终态；迟到 ACK 不得完成新 ticket。
7. 支付数据库事务只记录事实和 outbox，不发送网络请求。
8. 最终发布状态、工件哈希、大小、commit 与 key id 均在签名载荷内。

## 7. 可观测性

Host 与 APP 都暴露低基数 blocker、持续时间和 transition ID。重复写入相同 blocker 不制造伪 transition；旧帧和旧回调不让最后身份回退。
