# 移动端控制状态与恢复

## 1. 设计原则

控制链不以“收到 ACK 即成功”为判定，而以 **精确命令终态 + 更新后画面可见性 + 当前链路健康** 为共同条件。

## 2. 精确 ticket

每个命令 ticket 包含单调 ID 与绝对 deadline：

- 同一时刻最多一个 pending ticket；
- ticket ID 不允许复用或回绕；
- 完成、到期、取消只能产生一个终态；
- 错误 ticket 与迟到 ACK 不修改当前 ticket；
- transition ID 饱和时 fail-closed，不回绕到旧身份。

## 3. ACK 后门禁

ACK 源画面的 `(epoch, sequence)` 被记录。后续控制只在看到身份更晚、内容已更新且时间戳处于可信区间的画面后恢复。超时进入恢复，不静默放行。

## 4. Bluetooth reconcile

`BluetoothReconcileCoordinator` 将恢复事件转换为幂等 reconcile 请求：

- 相同事件 ID 不重复创建任务；
- pending 请求在确认前持续可见；
- 周期健康检查是后备路径；
- generation 不回绕，空间耗尽时阻断而不是复用旧 ACK。

## 5. 控制 blocker

运行时只暴露有限、稳定的 blocker，例如：

- `WAITING_FRESH_IDR`
- `WAITING_POST_ACK_VISIBILITY`
- `TICKET_PENDING`
- `TRANSPORT_NOT_READY`
- `DETECTED_NOT_TRACK_ELIGIBLE`
- `SUBCOUNT_UNRESOLVABLE`
- `RECOVERY_EXHAUSTED`

同时发布 blocker 持续时间、transition ID 和 correlation ID。相同 blocker 的重复更新不会制造新 transition。

## 6. 外部适配器边界

核心模块通过端口调用解码器、恢复器和诊断器。适配器抛出的异常被转换为明确恢复状态，不允许异常穿透接收/控制线程后留下“进程仍活着但业务已停”的假健康。
