# 双机方案 Windows Host 兼容性审计

> Current migration note (2026-08-01): this compatibility audit contains historical 320x320 host measurements. The active host AI capture contract now derives from the 416x416 default mobile model in the four-model catalog.

审计日期：2026-07-22

## 1. 结论

正式 Windows 产品是 `VFHost.exe`。它的业务热路径只包含自动选中游戏
显示输出的中心 320x320 DXGI 捕获、D3D11 桥接、H.264 编码和向
`10.57.23.2:5000` 的 UDP
发送。Host 不链接控制驱动，不处理目标或位移，不调用 `SendInput`；推理、后处理
和 MAKCU 均属于 Android。构建入口及实际输出名见
`dual_machine_runtime/host/windows/build_host_application.bat`。

生产视频链路固定为 CAT6 `10.57.23.1/24 <-> 10.57.23.2/24`。Android 物理
输出门由前台服务按 Ethernet、视频、解码、QNN 与 MAKCU 健康事实自动 fail-close；
Host 不参与启用、关闭或恢复决策。

当前实机已证明 Intel Iris Xe 捕获、跨 GPU 上传到 RTX 3050 Ti NVENC、同一 Iris Xe
对应的 Intel QSV H.264 MFT，以及 Microsoft 软件 H.264 回退可以运行。尚未逐机验证
的 GPU、显示拓扑或驱动组合必须保留为物理验收项，不能由代码审计推定通过。

## 2. 生产编码策略

| 捕获 GPU | 机器条件 | 自动生产路径 |
|---|---|---|
| NVIDIA | 同卡 NVENC 可用 | DXGI -> 同卡 NVENC |
| Intel/AMD | 存在可用 NVIDIA | DXGI -> 跨卡桥接 -> NVIDIA NVENC |
| Intel/AMD | NVENC 不可用、捕获适配器存在硬件 H.264 MFT | DXGI -> Adapter-LUID 同卡硬件 MFT |
| 任意 | NVENC 与同卡硬件 MFT 均不可用 | DXGI -> Microsoft 软件 H.264 MFT |

NVENC 可能通过初始化探测，但在首个真实帧的资源注册、映射或编码时失败。此时
本次 Host 生命周期先跳过 NVENC，再尝试捕获适配器对应的 Windows 硬件 MFT；
硬件 MFT 首个真实样本失败后才熔断到 Microsoft 软件路径，避免反复命中同一失效
后端。实现与事件分别位于：

- `dual_machine_runtime/host/windows/src/host_runtime_service.cpp`
- `%LOCALAPPDATA%\VisionForge\DualMachine\host-events.jsonl`

Windows hardware MFT 已进入生产自动策略，并使用 `MFT_ENUM_ADAPTER_LUID` 只枚举
捕获适配器对应的硬件编码器，不能把其他显卡的 transform 误报为同卡回退。Intel
QSV 的停止释放崩溃已通过标准 `END_OF_STREAM` / `END_STREAMING` 顺序修复。当前
MFT 输入仍包含有界 GPU 回读和 CPU BGRA->NV12 转换，不是零拷贝；AMD VCN 使用同一
通用实现但尚无 AMD 实机证据。生产候选列表见
`dual_machine_runtime/host/windows/include/vfdual/host_encoder_policy.hpp`。

## 3. 显示与捕获兼容矩阵

| 场景 | 当前行为 | 当前证据 | 边界 |
|---|---|---|---|
| 1920x1080、144 Hz 单屏 | 自动选择唯一有效输出，取中心 320x320 ROI | 当前实机 DXGI 与最终热路 | 已实测 |
| 2560x1440 / 3840x2160 | 按 DXGI 物理像素范围计算中心 320x320，不依赖 UI 缩放 | 坐标/选择测试 | 未逐台物理屏实测 |
| 多屏与负坐标 | 优先顶部全屏/大面积无边框外部窗口所在输出；无候选才回退主屏；ROI 按输出局部坐标计算 | 选择与几何测试 | 热插拔仍需物理验收 |
| 运行时恢复 | 保留启动时精确 `display_id`，避免 Alt-Tab/通知导致漂移；仅原输出消失时重新自动选择 | 代码、单测与复核 | 真实热拔插仍需验收 |
| DPI 100%–200% | 捕获用 DXGI 纹理尺寸，GUI 用 Per-Monitor DPI | 代码与 GUI 测试 | 各组合截图仍需验收 |
| Intel + NVIDIA 混合显卡 | Intel 捕获，跨卡桥接后 NVENC | Iris Xe + RTX 3050 Ti | 已实测 |
| NVIDIA 直连显示器 | 同设备、同尺寸时优先零拷贝 NVENC | 策略与 session 测试 | 当前内屏未证明直连 |
| 无可用 NVENC | 同卡硬件 MFT，失败才回退 Microsoft 软件 H.264 | Intel QSV 实机与软件热路 | AMD/其他 Intel 代际待验收 |
| AMD 捕获 | 有 NVIDIA 则跨卡 NVENC，否则尝试 Adapter-LUID 对应 VCN，再回退软件 | 通用代码与策略测试 | AMD 实机待验收 |
| RDP/虚拟/镜像输出 | 仅使用 Windows 标记为附加到桌面的 DXGI 输出并按设备名去重 | 代码审计 | 虚拟驱动仍可能伪装为桌面输出 |

显示选择与 ROI 依据：

- `dual_machine_runtime/host/windows/src/host_display_catalog.cpp`
- `dual_machine_runtime/host/windows/src/host_runtime_service.cpp`
- `dual_machine_runtime/host/windows/tests/host_display_catalog_tests.cpp`

## 4. 当前性能证据

当前 144 Hz 屏幕提供的独立新帧约为 144 FPS。Host 不使用配置 FPS 做采集调度；
`encoder_timing_fps` 只是码流时基元数据。

| 路径 | 样本 | P50 capture | P50 bridge | P50 encode | P50 total | total 换算 |
|---|---:|---:|---:|---:|---:|---:|
| Iris Xe -> RTX 3050 Ti NVENC | 2000 帧 | 1676 us | 2250 us | 2646 us | 6819 us | 146.649 FPS |
| Iris Xe -> Intel QSV H.264 MFT | 100 帧 | — | — | 约 3090 us | — | 编码器理论约 324 FPS |
| Microsoft 软件 H.264 | 1000 帧 | — | — | — | 6782 us | 147.449 FPS |

软件路径请求 240 Hz 元数据时由 Microsoft MFT 自动协商为 120 Hz；热循环仍没有
120 FPS 调度上限。原始逐帧数据在
`%LOCALAPPDATA%\VisionForge\DualMachine\host-metrics.csv`，字段写入实现见
`dual_machine_runtime/host/windows/src/streamer_metrics_csv.cpp`。

以上数据只证明当前机器与当前 320x320 流。P50 不是最坏值，也不是端到端手机
时延；144 Hz 新帧源、UDP、MediaCodec、QNN、后处理和 MAKCU 必须分别计入最终
验收。

## 5. 兼容性证据分级

### 已实测

- Windows 单屏中心 320x320 DXGI 捕获；
- Iris Xe 捕获到 RTX 3050 Ti 跨卡 NVENC；
- Iris Xe 捕获适配器 LUID 对应的 Intel QSV H.264 MFT，100 帧实际编码与安全停止；
- 最终 NVENC 2000 帧热路分位数；
- Microsoft 软件 H.264 的 240 -> 120 Hz 元数据协商及 1000 帧热路；
- 固定 CAT6 地址上的 UDP 发布；
- 产品 EXE 名称为 `VFHost.exe`。

### 仅代码/测试覆盖

- NVIDIA 直连同卡零拷贝路径；
- 2K/4K、负坐标、多屏自动选择、运行时锁屏与输出消失重选；
- NVENC 真实首帧失败后的软件熔断；
- AMD/Intel 捕获时的 Adapter-LUID 硬件 MFT 策略分派。

### 尚待物理验收

- 纯 AMD、其他代 Intel、不同代 NVIDIA 机器；
- 外接屏、热插拔、RDP/虚拟显示驱动和多 DPI 组合；
- NVENC 驱动重启/设备丢失、软件 MFT 长时稳定性与停止清理；
- 最终 CAT6、Android、QNN、MAKCU 端到端延迟、热稳定与错误恢复。

审计构建产物可位于 `analysis_output/host-final-cmake-2315/VisionForgeHost.exe`；
它只用于审计，不应覆盖用户当前运行的正式 EXE。
