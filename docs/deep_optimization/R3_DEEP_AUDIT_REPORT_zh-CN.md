# VisionForge / MINGSIM R3 深度架构、全链路与性能审计报告

## 1. 本轮定位

R3 不是重新命名旧 ZIP，也不是把独立示例代码附在工程外部。它以已经验证的
`BETTER_BEST` 完整工程为基线，直接修改 Android App、Windows Desktop Host、
Shared Protocol、Server/Sidecar 的生产源码、构建文件、测试和自动防退化门禁。

原两轮审计的 34 项代码级问题继续作为不可回退基线；R3 重点复核那些即使已有文档
说明、仍可能在长期运行、异常并发和热路径压力下暴露的问题。

## 2. 本轮发现并闭合的新增问题

### R3-001：有限退休 epoch 环不能提供永久防回滚保证

旧生产接收路径只记住固定数量的退休 epoch。运行足够久以后，最早记录会被淘汰，
极迟到的旧 Host 数据理论上可能重新进入候选会话。

修复后使用单调 `retired_through` 高水位。任何 `epoch <= retired_through` 的包永久拒绝，
不再依赖有限历史容器；候选 epoch 也只能向更高值推进。

### R3-002：Host epoch 需要跨进程、跨崩溃持久化

仅根据 PID、启动时间或内存计数推导 epoch，无法证明进程重启后绝不复用旧身份。
Host 生产组合根现在在发送任何帧前，通过 `FileEpochReservationStore`：

1. 在独立锁文件上获得跨进程排他锁；
2. 读取最后已提交 epoch；
3. 写入临时状态文件并强制落盘；
4. 原子替换正式状态文件；
5. 成功后才允许会话开始。

无法持久预留时 Host fail-closed，不再退回随机或内存派生值。

### R3-003：ACK 后可见性必须绑定完整帧身份

只比较 sequence 会在新 stream generation 将序号重置后产生两类错误：

- 旧 generation 的大 sequence 可能错误越过门禁；
- 新 generation 的小 sequence 可能被永久判旧。

MAKCU ticket、完成回调、可见性门禁和诊断快照现在统一携带
`(stream_generation, source_sequence)`，并新增原生 C++ 回归测试。

### R3-004：Native UDP 热路径存在不必要的预拷贝

协议层新增只读 `VideoFragmentView`。接收线程先以 `std::span` 校验 20 字节头和 payload
边界，只有分片通过身份、数量、索引、epoch 和资源预算检查后，重组器才持有必要字节。
旧拥有型 API 保留为兼容层并委托给 view 解析，避免出现两套协议语义。

### R3-005：分片完成判断不应每包扫描整个位图

E2E 重组器增加 `received_fragments` 计数。每个合法新分片以 O(1) 更新计数，完成条件由
计数与 `fragment_count` 比较，不再在每次 push 后遍历全部分片槽位。

### R3-006：Android 预检与解码缓存需要明确字节预算

Java 预检窗口接受原始 datagram 的 offset/length 切片，在验证完成前不创建 payload
副本；完整 Access Unit 也不再通过 `ByteArrayOutputStream` 形成第二份全量副本。

解码队列的复用池同时受对象数和总字节数约束。超预算时淘汰最大缓存，Service 关闭时
清空；未来时间戳不会被错误当成“非常新”而长期驻留。

### R3-007：干净 SQLite 数据库被自身严格 schema 证明错误拒绝

旧实现只压缩空白后比较 `sqlite_master.sql`。SQLite 会保留建表语句的无害格式，导致
模块自己新建的安全表在干净库启动时被判为不可信。

新实现是 token-exact SQL 规范化器：只忽略空白和注释，保留字符串、标识符、操作符和
全部安全约束 token。格式差异相等；删除 CHECK、UNIQUE、FOREIGN KEY 等仍然不同并
fail-closed。新增测试同时证明“干净库通过”和“预建弱表拒绝”。

### R3-008：安全测试替身与 cryptography 46 抽象接口不兼容

测试用 RSA 私钥替身补齐新版抽象基类要求的 `__copy__`，恢复了 127 项凭据安全用例。
这只改变测试兼容层，没有放宽生产密码学验证。

### R3-009：MAKCU 完整帧身份修复原先未进入 Linux 可移植 CTest

MAKCU 输出门禁是平台无关逻辑，但原 CMake 仅在 Android/目标环境间接覆盖。
R3 将其作为非 Windows 可移植测试目标加入 CTest，使最终 Release 与 Sanitizer 门禁从
23 项提升为 24 项，防止控制链修复仅存在于源码却没有真正执行。

## 3. 最终生产链路及关键不变量

```text
Windows 虚拟桌面
  → DXGI/D3D11 捕获
  → NVENC / Media Foundation 编码
  → H.264 Access Unit
  → 全分片发布结果
  → UDP 20 字节 VF2G/VF2R 协议
  → Android 有界重组
  → candidate epoch 两阶段提交
  → MediaCodec 解码与合并重建
  → QNN/Portable 推理
  → Target Tracker / Motion Planner
  → MAKCU USB / Bluetooth 输出
  → 精确 ticket ACK
  → ACK 后完整帧身份可见性确认
```

全链路必须持续满足：

- 帧身份是 `(stream_epoch, frame_sequence)`，不是 sequence 单值；
- IDR 只有全部必要分片发布成功才建立参考链；
- 半帧、冲突分片、超时和超预算均 fail-closed；
- 退休 epoch 永不复活，候选 epoch 永不倒退；
- decoder restart 只提交最新 generation/epoch；
- 实时帧允许 latest-wins，业务命令、支付和授权事件不得套用丢弃策略；
- ticket 只有一个终态，迟到 ACK 不能完成其他 ticket；
- ACK 后必须观察到更大的完整帧身份，超时不能自动放行旧检测；
- entitlement、peer、decoder、inference、device 任一失效都会关闭控制。

## 4. 性能优化原则

本轮优先删除可证明的结构性浪费，而不是通过降低校验换取速度：

- 网络头解析采用只读 view；
- 分片只在通过有界 admission 后复制一次；
- 完成判断从 O(n) 位图扫描改为 O(1) 计数；
- 完整 AU 使用预计算长度的一次性缓冲区；
- 解码复用池同时限制对象数和字节数；
- 旧 epoch 判断为常数时间高水位比较；
- Host epoch 持久化只发生在会话建立/恢复，不进入逐帧热路径。

便携 CI 上的微基准仅作为观察证据，不能替代真机性能结论。精确样本在
`R3_AUDIT/reports/final_performance_probe.json`。

## 5. 验证边界

可移植环境已实际运行的项目和精确结果记录在
`R3_AUDIT/reports/FINAL_VALIDATION.json`。以下必须在目标环境运行，不能从本报告推导
为 PASS：Windows DXGI/NVENC/MF、Android MediaCodec/QNN/HTP、MAKCU、Bluetooth、
真实双机网络长稳、支付、SMTP、生产签名和灾备恢复。
