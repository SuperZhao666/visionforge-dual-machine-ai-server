# Host → APP 端到端截图/视频流协议

## 1. 帧身份

每个可发布访问单元由以下复合身份唯一标识：

```text
FrameIdentity = (stream_epoch, frame_sequence)
```

- `stream_epoch` 在 Host 启动/重建时从持久化预留区间取得，范围为 `1..Long.MAX_VALUE`。
- `frame_sequence` 是 epoch 内无符号 32 位序号。
- 比较顺序先 epoch、后 sequence；新 epoch 序号归零不是回退。

## 2. Host 发送侧

### 2.1 采集状态

Host 明确区分：

- `Frame`：进入 `PUBLISHING_FRAME`，尚不能提前宣称链路可运行；
- `WaitTimeout`：已有历史帧时可发布 REPEAT，首帧前只等待；
- `AccessLost`：重建 duplication；
- `DeviceRemoved`：重建采集设备；
- `Failed`：进入失败/恢复状态。

### 2.2 完整 IDR 发布

`VideoDeliveryLedger` 为一次访问单元建立局部账本。只有所有唯一分片都得到成功终态，`PublishSummary.complete()` 才为真。socket 返回失败或抛异常均形成失败终态；不能清除 IDR 请求。

`IdrDeliveryTracker` 绑定精确帧身份。迟到的旧 IDR、重复回调或部分发送不能满足后来发起的 IDR 请求。

### 2.3 分片

wire header 固定携带：类型、epoch、sequence、fragment index 与 fragment count。Host 和 APP 使用一致的上限；分片索引冲突、重复载荷不一致和超限均被拒绝。

## 3. APP 接收侧

### 3.1 有界重组

`VideoPreflightReassemblyWindow` 在改变 epoch 高水位前验证 DATA 载荷。它限制：

- 并发半帧数；
- 单访问单元字节数；
- 全窗口总字节数；
- 分片数量；
- 绝对超时与 gap。

畸形高 epoch、空 DATA、REPEAT 和冲突分片不能清空健康会话。

### 3.2 码流分类

`H264AccessUnitClassifier` 只读解析 Annex-B，拒绝：

- 缺失起始码；
- 非零前导垃圾；
- 空/截断 NAL；
- `forbidden_zero_bit`；
- 保留/无效 NAL 类型。

分类器不修改码流，也不假设每帧只有一个 NAL。

### 3.3 按序交接与解码器重启

`OrderedAccessUnitHandoff` 保证 epoch/sequence 单调；队列冲突或溢出会要求新鲜 IDR。

`DecoderRestartCoordinator` 保证同一时刻最多一个物理重启：

- 更高 epoch 只更新目标；
- 较低 epoch 为陈旧请求；
- 旧完成回调被忽略；
- 不可能的未来回调触发会话重建；
- 重启失败清空 in-flight，允许同一 epoch 经完整重建后重试。

新 epoch 的普通预测帧不会提前触发重启。只有完整 IDR 能取得新解码会话所有权。

## 4. REPEAT 与恢复

REPEAT 仅表示没有新鲜内容，不能作为推理输入，也不能推进 epoch。收到 REPEAT 后：

1. 丢弃半帧；
2. 关闭 handoff，要求新鲜 IDR；
3. 请求 IDR；
4. 超过有界重试预算后升级为完整会话重建；
5. 恢复耗尽时保持阻断，不回退到旧画面。

## 5. ACK 后可见性

控制 ACK 不等于画面已经反映控制结果。`PostAckVisibilityGate` 只有在以下条件同时成立时放行：

- 内容确实更新；
- 观察身份严格晚于 ACK 源身份；
- `observed_at >= ack_time`；
- `observed_at <= now`；
- 未到绝对 deadline。

到达 deadline 后进入 `RECOVERY_REQUIRED`，不会自动使用旧检测结果。

## 6. 当前验证范围

离线测试覆盖：epoch 退休、gap、分片冲突、资源上限、IDR 完整交付、socket 异常、迟到回调、解码器重启失败、负坐标桌面、ACK 可见性和 sanitizer。

真实双机网络抖动、设备编码器/解码器和长时间运行见 `EXTERNAL_ACCEPTANCE.md`。
