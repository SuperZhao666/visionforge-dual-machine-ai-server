# VisionForge App / Host 端到端完整重建与改进报告

## 1. 交付范围

最终源码树保留完整基线中的 Android App、Windows Host、Server、Sidecar、Shared Protocol、安全防御、发布材料、QNN/JNI 运行资产、测试和文档，同时新增或改造 150 余个 App/Host/E2E 相关文件。最终精确文件数与 Git HEAD 由 ZIP 根目录的 `FINAL_STATUS.json` 记录。

## 2. Android App 分层

生产 UI 不再直接依赖 `MobileRuntimeService.LocalBinder`、Service 私有 phase 或设备适配器。新增稳定边界：

```text
MainActivity
  → MobileRuntimeBinding / command port / state port
  → immutable MobileRuntimeReadModel
  → MobileRuntimeCompositionRoot
  → video / decoder / inference / control coordinators
  → JNI / MediaCodec / QNN / USB / Bluetooth / network adapters
```

关键实现位于：

- `inferencebenchmark/runtime/`：生产 UI/Service 端口、命令协议、只读状态与组合根；
- `inferencebenchmark/video/`：App 兼容层视频 DTO、探针和重建协调；
- `mobile/application|core|domain|ports/`：可脱离 Android 框架验证的领域状态机；
- `MainActivity.java` 与 `MobileRuntimeService.java`：仅在边界处映射 Android 生命周期和 UI 表示。

`MakcuDeliveryState` 被拆为独立不可变值对象，避免设备交付证据继续隐藏在大型电路类中；完整 Java 源清单同步纳入该文件，并由回归测试验证。

## 3. Windows Host 分层

Host UI 通过 `HostRuntimeFacade` 与稳定 DTO 调用应用层，不再向上暴露 DXGI、D3D11 texture、socket、编码器对象或后台线程：

```text
Desktop UI
  → HostRuntimeFacade / HostStartRequest / HostRuntimeReadModel
  → Host application layer
  → capture / encode / publish / recovery ports
  → DXGI / D3D11 / NVENC / Media Foundation / UDP / CAT6 adapters
```

截图区域成为纯值对象，校验有符号坐标、负坐标显示器、零尺寸、交集、边界与算术溢出。生产 Windows 编译仍由新增 CI Windows lane 和目标工作站验收负责；Linux 可移植域模型及契约测试已经进入当前构建图。

## 4. Host → App 视频协议

固定 20 字节网络序头：

```text
magic:u32 | stream_epoch:u64 | frame_sequence:u32 |
fragment_index:u16 | fragment_count:u16
```

数据与重复帧 magic 分别为 `VF2G` 和 `VF2R`。Java 和 C++ 都限制 epoch 为正 63 位范围，访问单元最大 2 MiB、payload 最大 1400 字节、最大分片数统一为 1498。

完整帧身份是 `(stream_epoch, frame_sequence)`。sequence 到 `UINT32_MAX` 后必须切换 epoch，禁止静默回绕。

## 5. 完整 IDR 发布

Host 为一次访问单元维护发布账本。只有每个唯一分片都有成功终态，才允许：

- 消费当前 IDR 请求；
- 更新时间戳；
- 宣告参考链已建立；
- 继续发送依赖该 IDR 的预测帧。

部分发送、socket 异常、结果不确定或迟到旧 IDR 都保持恢复请求。

## 6. 有界重组与候选 epoch

接收端维持 active 与 candidate 两套有界重组状态。未来 epoch 的单个分片不能替换健康会话。候选只有在以下条件全部成立后提交：

1. 完整收齐；
2. header 和资源预算合法；
3. 重复分片内容一致；
4. 访问单元为可接受的新鲜 Annex-B IDR；
5. 解码器重建协调器接受最新目标。

退休 epoch 进入固定容量历史环，不能重新激活。半帧、冲突、超时、缺口、内存/帧数超限都会被回收并请求恢复。

## 7. 解码器重建与控制链

解码器重建在途时，更高 epoch 只更新目标而不并发创建第二次物理重建。旧回调不会覆盖新目标；不可能的未来回调会触发 fail-closed 会话恢复。

控制链保留并强化：

- 精确 ticket、统一绝对 deadline、单一终态；
- late ACK 不完成错误 ticket；
- ACK 后可见性比较完整帧身份；
- 超时不自动放行旧画面；
- REPEAT 不推进新鲜度；
- 检测存在与可控制 track 资格分离；
- Bluetooth 恢复事件幂等 reconcile；
- blocker、transition ID 和持续时间进入稳定读模型。

## 8. 自动防退化

新增：

- `tools/check_app_host_architecture.py`；
- `tools/check_video_transport_contract.py`；
- 检查器自测；
- Java 全量/严格源清单；
- `tools/run_app_host_e2e_portable_checks.sh`；
- `.github/workflows/app-host-e2e-architecture.yml`；
- C++ 随机化传输仿真。

门禁会拒绝旧 12 字节协议、删除 epoch、分片上限漂移、UI 重新依赖私有 Service、Host DTO 泄漏平台类型、IDR 部分发布确认、无界重组、退休 epoch 恢复和复杂度预算回退。
