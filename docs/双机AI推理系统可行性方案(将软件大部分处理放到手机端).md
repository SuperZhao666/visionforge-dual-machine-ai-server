# 双机 AI 推理系统可行性方案（全软件 UDP 架构版）

> Current migration note (2026-08-01): this feasibility draft predates the four-model 416x416 migration. Any 320x320 preprocessing text below is historical, not the active runtime contract.

> **文档用途**：供本地 AI Agent / 人工分析后执行实施。所有性能数字均标注【实测值 / 估算值 / 标称值】。
> **文档版本**：改用"UDP 串流进、UDP 鼠标包出"的全软件方案；推理后端从 NCNN/Vulkan 切换为**高通骁龙专属 QNN（Hexagon NPU）路径**。

---

## 0. 阅读指南（致审查方）

- 【实测值】：公开可查的第三方/官方实测，附来源；
- 【估算值】：由标称算力或同类实测外推，±50% 误差可能；
- 【标称值】：厂商 datasheet / 官方文档宣称值；
- 审查重点：第 7 章性能预算、第 9 章风险登记、第 11 章开放问题。

---

## 1. 项目概述

### 1.1 目标

构建双机 AI 视觉推理系统：**主设备（PC）运行目标影像 → 画面经 UDP 串流发送至手机 → 手机端 YOLO 推理（骁龙 NPU）→ 推理结果转换为鼠标指令经 UDP 发回 PC → PC 端接收程序注入鼠标输入**。

### 1.2 设计约束（v2.0 已修订）

| 约束 | v1.0 | v2.0（当前） | 修订说明 |
|---|---|---|---|
| 主设备软件足迹 | 零软件 | **允许运行 2 个自有小程序**（推流端 + 鼠标接收端） | 用户决策：以软件足迹换取 ¥0 硬件成本与更低延迟 |
| 硬件采购 | ≤ ¥200 | **¥0** | 采集卡、Pro Micro 全部取消 |
| 副设备 | 小米 14 Pro（骁龙 8 Gen 3） | 同左 | 不变 |
| 推理后端 | NCNN/Vulkan（全芯片通用） | **QNN / Hexagon NPU（仅骁龙）** | 用户决策：先做骁龙极致性能，其余芯片暂不适配 |
| 实时性 | 端到端 ≥ 60 FPS，延迟 < 100ms | 端到端 ≥ 60 FPS，延迟目标 **< 40ms** | 软件链路理论延迟显著低于采集卡链路 |

### 1.3 现有资产（零成本）

- 小米 14 Pro：骁龙 8 Gen 3（Adreno 750 GPU 标称约 2.8~3.2 TFLOPS FP32；Hexagon V73M NPU 第三方普遍引用 45 TOPS INT8；LPDDR5X 77GB/s）；
- 笔记本：RTX 3050Ti Laptop（NVENC 硬件编码器，用于推流端零开销编码）；
- USB 数据线 ×1（充电线即可，用于 USB 网络共享有线链路）。

---

## 2. 系统总体架构（v2.0）

```
┌──────────────── 笔记本（Windows）────────────────┐
│  ① 推流端：DXGI/NVENC 抓屏编码 → H.264 over UDP   │
│  ④ 接收端：UDP socket 监听 ← 解析鼠标包 → SendInput│
└───────┬───────────────────────────────▲─────────┘
        │ H.264 视频流                   │ 鼠标指令包（~16 B/条）
        │ （下行）                        │ （上行）
   ═════╪════════════════════════════════╪═════  单一物理链路：
        │        （千兆局域网 / 5GHz WiFi）
        ▼                                │
┌──────────────── 小米 14 Pro（Android，免 root）────────────────┐
│  ② 收流解码：UDP 收包 → MediaCodec 硬解（<10ms 级）→ RGB 帧    │
│  ③ 推理：预处理 320×320 → QNN（Hexagon NPU, INT8/FP16）→ 检测框 │
│     → 坐标映射 → 生成鼠标指令 → UDP 发出                        │
└───────────────────────────────────────────────────────────────┘
```

**模块解耦**：推流端 / 收流解码 / 推理 / 鼠标收发，四个模块独立开发、独立验收、可单独替换。

---

## 3. 软件选型与开源仓库调研（本方案核心资产）

### 3.1 推理链路（骁龙 NPU 极致路径）

| 仓库 | 地址 | 质量评估 | 在本方案中的用途 |
|---|---|---|---|
| **quic/ai-hub-models**（高通官方） | github.com/quic/ai-hub-models | 官方维护、BSD-3、持续更新；**模型目录直接包含 YOLOv11-Detection / YOLOv8-Detection / YOLOv10-Detection**；每个模型带导出脚本、量化 recipe、真实设备 profile 数据 | **主依赖**。`pip install qai_hub_models` 后一条命令把 YOLOv11 编译为骁龙 8 Gen 3 的 NPU 格式，并在高通云端真实设备上给出 profile 帧率 |
| **quic/ai-hub-apps**（高通官方） | github.com/quic/ai-hub-apps | 官方示例 App 集；Android 端示例（相机实时取帧 + 推理 + 后处理）支持 CPU/GPU/NPU（Hexagon HTP），明确支持骁龙 8 Gen 1/2/3、888、8 Elite；NPU 精度 FP16/INT8 | **Android 端骨架代码**。直接以其"实时相机推理"示例为底，把取帧源从相机换成 UDP 解码帧 |
| Qualcomm AI Hub（云服务） | aihub.qualcomm.com | 免费注册（Qualcomm ID + API Token） | 模型编译/量化/profile 的云工具链，免去本地配置 QNN SDK 的麻烦；编译产物（QNN context binary / TFLite+委托）下载后本地集成 |

**部署链**：

```
训练/权重（可选：AutoDL 云端，3090 约 ¥1.2~1.8/h）
  → YOLOv11n PyTorch (imgsz=320)
  → qai_hub_models 导出脚本（AI Hub 云端编译，device 选 Samsung Galaxy S24 / 同级 8 Gen 3 机型）
  → 产物：QNN 格式模型（Hexagon NPU, INT8 量化 + 校准数据集）
  → Android App 集成（参考 ai-hub-apps 示例）
```

**注意**：AI Hub 模型库自带的是 COCO 通用权重；项目自定义权重需用其导出脚本走"自定义 checkpoint"路径（脚本支持 `--help` 查看权重加载参数），量化校准需自备数百张代表性图片。

### 3.2 收流解码链路（手机端，UDP → 可推理帧）

| 仓库 | 地址 | 质量评估 | 用途 |
|---|---|---|---|
| **Consti10/LiveVideo10ms** | github.com/Consti10/LiveVideo10ms | 专为"UDP 低延迟直播流"写的 Android 库：MediaCodec 硬解 + C++ 多线程收发，实测解码 Galaxy S9+ 8.0~11.5ms、Pixel 3 10.5~11.2ms【实测值】；支持 RAW/RTP over UDP；FPV 圈实战多年。维护频率低（2019 起），但协议层稳定、代码量小 | **首选参考/直接集成**。其 VideoCore 模块输出的帧可对接推理预处理 |
| **ALI-BABAI/h264_stream_decocer** | github.com/ALI-BABAI/h264_stream_decocer | 2026 年仍更新的 FFmpeg 7.1 有状态 H.264 解码库（Android/iOS），FFI 友好 | 备选：需要 AAC 音频或更现代的 FFmpeg 基线时 |
| moonlight-android | github.com/moonlight-stream/moonlight-android | 大型成熟开源串流客户端（解码 ~8~15ms【实测值】） | 仅作架构参考（抖动缓冲、解码管线），代码量过大不宜直接改 |
| LizardByte/Sunshine | github.com/LizardByte/Sunshine | 开源串流主机端标杆（DXGI 抓屏 + NVENC/AMF/QSV 编码） | **推流端实现参考**：其抓屏/编码/封包管线是工业级范本；也可直接整用（见 3.4 方案对比） |

### 3.3 推流端（PC 端，Windows）

关键参数：NVENC 硬编（3050Ti 占用 ~1~3% GPU）、零 B 帧、小 GOP、`mpegts` 封装。手机端 ffplay/自研 App 验证时用低延迟旗标：`-fflags nobuffer -flags low_delay -probesize 32`。

- **路径 （正式版）**：自研推流端（C++/Rust），抓屏用 **DXGI Desktop Duplication API**（全屏独占也能抓、GPU 内零拷贝），编码 NVENC，UDP 直发——参考 Sunshine 源码实现。

### 3.4 鼠标指令回传链路（手机 → PC）

- **手机端**：UDP socket 发送定长二进制包（建议 16 B：`[dx:int32][dy:int32][buttons:uint8][seq:uint32][reserved]`），发送频率与推理帧率同步；
- **PC 接收端**：自研 Windows 小程序（<200 行）：`WSARecvFrom` 收包 → 校验 seq → `SendInput()` 注入相对移动。
  - Ghub 2020或2021年版本，同原来单机项目迁移即可。
- **参考实现**：KDE Connect（github.com/KDE/kdeconnect-android + 桌面端）的"远程鼠标板"功能即"手机经网络控制 PC 光标"的成熟开源实现，可对照其协议与注入方式；deskflow（原 Synergy 系开源 KVM）同理。

### 3.5 链路传输介质（USB 数据线 / 局域网）

- **千兆有线局域网 / 5GHz WiFi 同路由**。

---

## 7. 性能预算

### 7.1 帧率链路

NVENC 编码 60~120 FPS 无压力；USB 网络共享带宽 ≥480Mbps，1080p60 H.264（8~15 Mbps）占用 < 5%；瓶颈在**手机解码 + 推理的串行耗时**——解码 ~10ms + 推理 ~5~10ms【估算】，串行约 15~20ms/帧，**支撑 50~65 FPS 端到端**；若解码/推理流水线化（双缓冲并行），可逼近 100+ FPS。

### 7.2 推理能力（QNN 路径）

- 【标称/生态事实】AI Hub 官方模型目录直接提供 YOLOv11-Detection，支持 8 Gen 3 NPU（INT8/FP16），导出脚本自动量化 + 云端真机 profile；
- 【估算值】YOLOv11n@320 在 Hexagon V73M（45 TOPS INT8 标称）上纯推理 **3~8ms/帧（125~300 FPS）**，量化精度损失典型 1~2% mAP【经验值】；
- **S2 阶段必须用本机实测替换以上估算**。

### 7.3 端到端延迟预算【估算值】

| 环节 | 延迟 |
|---|---|
| 抓屏 + NVENC 编码 | 2~8ms |
| USB 网络共享传输 | ~1ms |
| MediaCodec 解码 | 5~12ms |
| 预处理 + NPU 推理 + 后处理 | 5~12ms |
| UDP 回传 + SendInput 注入 | 1~3ms |
| **合计** | **约 14~36ms** |

---

## 8. 风险登记表

| # | 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|---|
| R1 | gdigrab 抓不到独占全屏画面 | 高（特定场景） | 黑屏 | 路径 B：DXGI Desktop Duplication（Sunshine 源码参照） |
| R2 | AI Hub/QNN 工具链学习曲线（注册、量化校准、Android 集成） | 中 | 工期 +3~5 天 | 先用 NCNN/Vulkan 打通全链路（全机型保底），再换 QNN 后端——抽象层设计保留双后端 |
| R3 | INT8 量化掉点 | 中 | mAP -1~3% | AI Hub 量化需校准集；可回退 FP16 NPU |
| R4 | HyperOS 后台杀进程/网络限流 | 中 | 链路中断 | 电池优化白名单 + 前台服务 + 锁后台 |
|      |                                                           |                |               |                                                              |
|      |                                                           |                |               |                                                              |
| R7 | 持续 NPU 负载发热降频 | 高 | 帧率 7~8 折 | 预算已含余量；散热背夹（¥30~50，可选） |
| R8 | LiveVideo10ms 库老化（2019 基线）与新 Android 版本兼容性 | 中 | 编译/兼容问题 | 备选 h264_stream_decocer（FFmpeg 7.1，2026 活跃）或直接用 MediaCodec 官方示例自写解码层 |

---

## 9. 诚实声明（审查方必读）

1. 推理帧率（7.2）在 S2 阶段完成前均为估算值；QNN INT8 的真实帧率以 AI Hub 云端 profile + 本机实测为准。
2. LiveVideo10ms 的 8~11.5ms 解码实测出自骁龙 835/845 时代机型，8 Gen 3 上预期更好，但未经实测。

---

## 10. 开放问题

1. 推流端独占全屏兼容性（R1）需在目标影像实际运行形态下测试；
2. 接收端是否需提权（管理员）才能向提权窗口注入输入——视目标应用权限而定；
3. UDP 丢包策略（最新帧优先 / seq 丢弃）与解码器花屏恢复（IDR 请求机制）需在 S1 设计。

---

## 附录 A：参考仓库清单（2026-07-20 调研快照）

| 仓库 | 用途 | 许可证 |
|---|---|---|
| github.com/quic/ai-hub-models | YOLOv11 骁龙 NPU 编译/量化/profile | BSD-3 |
| github.com/quic/ai-hub-apps | Android NPU 推理示例骨架 | BSD-3 |
| github.com/Consti10/LiveVideo10ms | 手机端 UDP H.264 低延迟解码 | 见仓库 |
| github.com/ALI-BABAI/h264_stream_decocer | FFmpeg 7.1 解码库（备选） | 示例/教育用途声明 |
| github.com/LizardByte/Sunshine | 推流端抓屏/编码实现参考 | GPL-3.0 |
| github.com/moonlight-stream/moonlight-android | 解码/抖动缓冲架构参考 | GPL-3.0 |
| github.com/KDE/kdeconnect-android | 网络鼠标协议参考 | GPL |
| github.com/oblitum/Interception | 驱动级输入注入（可选） | LGPL |
