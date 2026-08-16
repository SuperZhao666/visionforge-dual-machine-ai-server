# R3 实时性能与资源预算

## 热路径预算

1. 协议头解析不得复制 payload；C++ 使用 `VideoFragmentView/std::span`，Java 使用有界
   `ByteBuffer` 视图。
2. 分片只允许在协议、身份、索引和资源预算通过后复制一次。
3. 每个新分片的完成判断必须为 O(1)，禁止重新扫描全部 fragment slot。
4. 重组器必须同时限制：最大在途帧、单帧字节、总在途字节、分片数量、超时。
5. Decoder 复用池必须同时限制缓存数量和总字节；关闭时归零。
6. 退休 epoch 判断必须为 O(1) 高水位比较。
7. ACK 可见性判断必须比较完整帧身份，不能用系统墙钟推断因果关系。

上述结构由 `tools/check_realtime_pipeline_contract.py` 自动检查。

## 架构复杂度预算

`tools/check_app_host_architecture.py` 对关键大文件设硬上限。上限只是阻止继续膨胀，
不是鼓励把类写到边界；新增职责优先进入 domain/application/infrastructure 独立组件。

## 便携环境观察值

最终包内 `R3_AUDIT/reports/final_performance_probe.json` 保存 25 次重复运行的 median、p95、
max。它们只用于发现数量级退化，不承诺目标 Windows/Android 设备的延迟、吞吐或功耗。
真机必须按照外部验收文档采集捕获、编码、传输、解码、推理和控制各阶段分位数。
