# 双机运行时验收基线

> Current migration note (2026-08-01): this acceptance baseline contains archived 320x320 measurements. The active four-model runtime now uses 416x416 contracts.

校准日期：2026-07-23  
口径：只记录当前代码、候选二进制和已归档的物理实测证据。任何构建成功、单元测试、纯推理耗时或 provider 枚举都不能替代端到端硬件验收。

## 1. 固定产品边界

```text
Windows VisionForge Host
  自动选取 DXGI 输出 -> 屏幕中心 320x320 ROI -> D3D11 桥接 -> H.264 -> UDP

CAT6 点对点
  10.57.23.1/24 <-> 10.57.23.2/24

VisionForge Mobile
  UDP 重组 -> MediaCodec 硬解 -> 预处理 -> QNN/HTP -> 后处理/跟踪/控制策略 -> MAKCU
```

- 生产视频数据面只允许 CAT6 点对点链路，不存在无线视频回退或自动改发 WiFi。
- Host 只负责画面采集、编码和发送；CAT6 就绪、质量探针与 IDR 请求只服务链路恢复。
- Host 不链接输入驱动，不生成目标/位移/按键控制，不调用 `SendInput`。
- Android 负责解码、推理、后处理、跟踪和控制策略；实体输出只允许 `km.move`，不包含点击、自动开火、压枪、回闪、滚轮或任何 Host 输入回传。
- MAKCU 输出由前台服务自动 fail-close：只有 CAT6、视频、解码、近期 QNN 成功且零连续失败、MAKCU 连接全部健康时才启用；任一条件丢失立即关闭，恢复后自动重试。
- Activity 只显示状态和接受参数，不拥有输出门；切到后台不会中断健康的前台服务，也不存在“手动开启控制输出”步骤。

核心实现：

- `dual_machine_runtime/host/windows/src/host_runtime_service.cpp`
- `dual_machine_runtime/host/windows/src/host_cat6_protocol.cpp`
- `android_inference_benchmark/app/src/main/cpp/NativeH264Decoder.cpp`
- `android_inference_benchmark/app/src/main/cpp/QnnHtpBridge.cpp`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileControlRuntime.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputCoordinator.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MakcuSerialController.java`

## 2. 当前候选身份

| 组件 | 路径 | 字节数 | SHA256 | 发布属性 |
|---|---|---:|---|---|
| Host final8 | `analysis_output/host-formal-final8-20260723/VisionForgeHost.exe` | 814,592 | `66BFB23B407A0ADD1576EFADF0AFC4746E6EFA55B56AC96E3B0A93621FDA7C91` | 静态 CRT 候选；Windows Authenticode `NotSigned` |
| Mobile final8 | `analysis_output/mobile-release-final8-20260723/VisionForgeMobile-1.0.0-rc1-final8-dev-signed.apk` | 130,014,224 | `6D67D525DE7ACD8051476EFF309C5A7E9EF013929A534EA15624DD59B5E45B87` | APK v2 有效；Android Debug 开发签名，**不是生产发布包** |
| 手机拉回的已安装 APK | `analysis_output/mobile-release-final8-20260723/installed-base.apk` | 130,014,224 | `6D67D525DE7ACD8051476EFF309C5A7E9EF013929A534EA15624DD59B5E45B87` | 与 Mobile final8 候选字节和哈希完全一致 |
| 当前 Host 实机候选 | `dual_machine_runtime/out_ninja_host_hardening/VisionForgeHost.exe` | 886,784 | `B2A39EFFD0B24DD347A42BF2BEA54493ABE1073A94053668D5185BA02F65FDA6` | 当前物理控制验收使用的运行中候选 |
| 通用硬件编码 Host 候选 | `dual_machine_runtime/out_cmake_host_generic_hw_encoder_final/VisionForgeHost.exe` | 649,216 | `3B60EC3DC3F10F73FBEFFF834601F2DCEA386A1085B2307A9F9DF4148411FAA1` | 35 项 CTest 零失败；当前运行中的 Host 未被覆盖 |
| 当前 Mobile ACK-ticket 候选 | `android_inference_benchmark/app/build/outputs/apk/release/app-release.apk` | 128,561,963 | `B649FF4E38C4E2751AD802C9ABC657A269547AF1B5119E9B4B42B4417ED93542` | 开发签名 Release；**不是生产发布包** |
| 当前手机拉回的已安装 APK | `analysis_output/mobile-ack-ticket-final-20260723/installed-base.apk` | 128,561,963 | `B649FF4E38C4E2751AD802C9ABC657A269547AF1B5119E9B4B42B4417ED93542` | 与当前 Mobile 候选字节和哈希完全一致 |

APK v2 signer 证书 SHA256：`179FAF0492D0B49D66BDEFCC66BC51541602525A25B8AF8C4E42345A770C7155`。

已从测试手机拉回实际安装的 `base.apk`，其字节数和 SHA256 与 Mobile final8 候选完全一致，关闭了上一版“只记录 package/version、未保存安装文件哈希”的缺口。该文件级绑定仍不等同于远程证明或运行进程证明；正式包仍应在健康事件中记录 build ID、APK hash 与 signer 指纹，并改用受控生产签名。

当前自动门候选也已重新从手机拉回并与本地 APK 完整比对一致。它仍使用开发签名；实体链路 PASS 不能替代正式签名发布门禁。

## 3. CAT6 协议与网络契约

| 流向 | 地址/端口 | 用途 |
|---|---|---|
| Host -> Mobile | `10.57.23.2:5000/UDP` | H.264 Annex-B 分片，唯一生产视频流 |
| Mobile -> Host | `10.57.23.1:5003/UDP` | `VF_CAT6_READY_V1` 就绪心跳 |
| Host -> Mobile | `10.57.23.2:5004/UDP` | `VF_CAT6_PROBE_V1` 质量探针 |
| Mobile -> Host | `10.57.23.1:5001/UDP` | `IDR1` 关键帧请求，不是控制通道 |
| Mobile -> Host | `10.57.23.1:67/UDP` | 首次地址配置的隔离 DHCP |

有线不可用时 Host 必须明确失败并重试固定地址，不得把生产视频改发其他接口。Windows 默认路由保持在 WLAN；CAT6 接口无网关、无 DNS。Android WiFi 表保留默认路由，`eth0` 表没有默认路由。

Host 防火墙只维护三条程序绑定的入站 UDP 规则：DHCP、手机公告、IDR。DHCP 规则因未配置客户端前手机还没有 `10.57.23.2`，远端地址只能为 `Any`，但仍限制为有线接口、Host 程序和 UDP 67/68。其余两条同时限制接口、程序、端口和 `10.57.23.1 <-> 10.57.23.2` 地址。

## 4. 捕获、帧率与显示器口径

- Host 没有用户 FPS 上限或帧级固定 `sleep`；它处理 DXGI 提供的独立新帧。
- `encoder_timing_fps` 是编码时间基与关键帧协商字段，不是采集上限。
- 144 Hz 物理桌面最多提供约 144 个独立桌面新帧/秒；游戏内部 200 FPS 不等于 Windows 桌面复制能看到 200 个不同呈现帧。
- 捕获 ROI 始终按所选输出的物理像素矩形计算中心 `320x320`，不会把 1K/2K/4K 全屏先传给手机。
- 点击开始时重新枚举 attached DXGI 输出和可见外部顶层窗口；过滤 Host 自身、Shell、tool window、最小化和 cloaked 窗口；无合格候选时回退系统主屏。
- 自动选屏策略和负坐标/高 DPI 几何已有测试，但当前只有本机单次物理环境证据。多个相似全屏窗口时仍可能选中非预期输出，不能声称所有多屏机器已经实机通过。
- 当前无 DXGI 之外的生产捕获回退；不支持 DXGI 的环境必须明确失败。

## 5. 编码器兼容策略

| 环境 | 当前生产策略 | 实证范围 |
|---|---|---|
| 捕获卡本身支持 NVENC | 同卡 NVENC | 代码/测试覆盖；本轮物理环境未覆盖同卡场景 |
| Intel/AMD 捕获，另有 NVIDIA | D3D11 跨卡桥接到 NVIDIA NVENC | **本机 Iris Xe -> RTX 3050 Ti 已实测** |
| 无可用 NVENC、捕获适配器有 H.264 硬件 MFT | Adapter-LUID 同卡 Windows 硬件 MFT | **本机 Iris Xe -> Intel QSV 已实测 100 帧；AMD 未实测** |
| 无可用 NVENC | Microsoft 软件 H.264 MFT | 本机 320x320 热路径已实测 |

自动顺序固定为 NVENC -> 捕获适配器硬件 MFT -> CPU 软件 MFT。NVENC 或硬件 MFT 首个真实帧失败后，本次 Host 生命周期跳过相应后端，避免恢复循环重复抖动。Intel QSV 320x320、100 帧编码 P50 约 `3.09 ms`（编码器理论约 324 FPS），但 Media Foundation 路径仍含 GPU 回读和 CPU BGRA->NV12，不是零拷贝。不能把本机编码器吞吐扩大为所有纯 CPU/核显机器都能达到 120/150 FPS。

`dumpbin-dependents.txt` 表明 final8 EXE 只依赖 Windows 系统/媒体/D3D DLL，不依赖外置 MSVCP/VCRUNTIME/UCRT DLL；这修复了缺少运行库导致的 `0xc0000142` 风险，但仍需在干净 Windows 10/11 机器验收。

## 6. QNN/HTP 契约与兼容边界

- final8 APK 在 Xiaomi 14 Pro 上报告：QNN HTP、W8A16 split-output、1 张图、HTP Turbo+；输入 614,400 bytes，输出 50,400 bytes。
- QNN 桥接现在严格校验模型 tensor 契约，部分初始化失败会完整清理，避免污染后续重试。
- APK 打包含 V68/V69/V73/V75/V79 运行时闭包；这只证明打包覆盖，不证明各代芯片实机兼容。
- 当前真实硬件证据仅覆盖 Xiaomi 14 Pro / Snapdragon 8 Gen 3 / V75。V68、V69、V73、V79 未实机验收；V81 未包含。
- 不存在已验收的 QNN 不可用生产回退路径。若目标设备 QNN/HTP 初始化失败，当前应明确报错，不能假装在 NPU 上运行。

### 6.1 数据集精度证据与边界

- 已在同一部 Xiaomi 14 Pro 的真实 `MediaCodec -> QNN HTP W8A16 -> C++ 后处理` 路径上，严格覆盖 `images1` 的 484/484 个有标注帧；`--require-complete` 于 2026-07-23 复核退出码为 0。
- 追踪采集下限为 0.25 时：TP 465、FP 515、FN 20、Precision 0.474490、Recall 0.958763、F1 0.634812、匹配框平均 IoU 0.791454、AP50(class0) 0.9211、mAP50-95(class0) 0.4892。
- 当前产品默认置信度 0.84 在同一追踪的阈值重放中得到 Precision 0.5114、Recall 0.9216、F1 0.6578；0.85 的 F1 0.6586 略高，但过于贴近量化输出上沿，因此不作为全局硬编码最优值。
- 完整追踪证据是 `analysis_output/qnn-detection-trace-dataset-484-primed.csv`，SHA256 `D464BDA1B672E08D1A67D9E9BC1EAE08765E905C9826291639E2CA2B837BE3EF`。同目录 `*-final.csv` 实际只有 482/484 个唯一帧 ID，严格复核失败，不能作为完整覆盖证据。
- 这只验证一个 class0 标注数据集；不证明 final8 无标注 Valorant 视频的准确率，也不证明其他地图、分辨率、目标类别、设备或完整控制决策的泛化精度。完整命令和证据身份见 `docs/DUAL_MACHINE_DATASET_QNN_EVALUATION.md`。

## 7. 构建与自动测试门禁

final8 当前集成门禁为 33 项 CTest、0 失败；其中桌面视频硬件环境用例按环境跳过。Host 静态构建完成，Android 的 `verifyMobileRuntimeSnapshot`、`externalNativeBuildRelease` 和离线 `assembleRelease` 均完成。自动测试只能证明契约和构建一致性，不能替代下面的物理端到端窗口。

历史 final7 的 Debug、动态 Release、静态 Release 三套串行 CTest 均为 31 项、0 失败、1 个桌面视频环境跳过。硬件桌面测试不可并行争用 DXGI duplication；并行初始化失败属于测试资源互斥，不是产品运行失败。

历史静态 Release 的定向真实视频测试单独退出码为 0：600 帧，capture P50 `6.880 ms`、bridge P50 `7.111 ms`、encode P50 `1.216 ms`、total P50 `9.696 ms`，由 total P50 换算 `103.135 FPS`。该数据是测试工具热路径，不等于最终端到端吞吐。

## 8. 物理端到端证据

### 8.1 final5 十分钟稳定窗口

证据目录：`analysis_output/final5-longrun-20260723-070410`。

| 端 | 窗口 | 帧/单元增量 | 实测速率 | 关键差分 |
|---|---:|---:|---:|---|
| Host | 610.599 s | 87,867 | **143.903 FPS** | capture timeout `+2`；DXGI missed present `+71`；staging/mailbox/completion/recovery `+0` |
| Mobile | 610.000 s | 87,780 | **143.902 FPS** | 全部输入 drop、重组过期、QNN failure `+0` |

手机窗口起止的 `dropped_access_units=2` 是更早一次 force-stop 恢复产生的绝对历史计数，在该 610 秒窗口内没有新增。不得把绝对值写成 0，也不得把它算成本窗口丢帧。

### 8.2 pre-final6 真实视频 120 FPS

证据目录名为 `analysis_output/final6-raw-video-120fps-20260723`，但归档文件明确命名 `*-pre-final6-runtime.jsonl`，所以必须标记为 **pre-final6**，不能冒充 final6。

- Host：45.048 s / 5,405 帧 = **119.983 FPS**；
- Mobile：44.999 s / 5,399 access units = **119.980 FPS**；
- 选定窗口内没有新增 drop 或 QNN failure，输出门关闭。

### 8.3 final7 真实视频 120 FPS

证据目录：`analysis_output/final7-live-120fps-20260723`，详细复算见其 `metrics.md`。

| 端 | 精确窗口 | 增量 | 实测速率 | 失败/丢弃差分 |
|---|---:|---:|---:|---|
| Host | 50.062 s | 6,006 published | **119.971 FPS** | capture timeout、staging busy、mailbox superseded、completion drop、recovery 均 `+0` |
| Mobile | 49.999 s | 5,999 completed | **119.982 FPS** | 全部输入 drop、重组过期、QNN failure 均 `+0` |

手机终点滚动 300 样本：预处理 P50/P95 `0.562/0.648 ms`，QNN `1.725/2.179 ms`，推理总计 `1.862/2.491 ms`，解码队列 `5.434/7.245 ms`。硬解器为 `c2.qti.avc.decoder`，尺寸 `320x320`。

Host 完整 trace 约 69.660 秒；刺激停止后动态源不再持续呈现，尾段 `capture_timeouts` 累计到 299。因此 0 timeout 只适用于表内稳态窗口。Host 与手机采样边界不同，完整 primary slice 的手机内部重组/解码/渲染/QNN 计数守恒，但 Host 最终发布数与手机区间增量相差 5 帧；不能声称跨端逐帧计数完全相等。

主性能运行排空后手机计数为 19,014；随后为验证 Host 防火墙幂等性又短启停约 3.730 秒，最终归档健康快照为 19,026。两者都不是新的 10 分钟性能窗口；后续短流不能混入上表 120 FPS 复算。

测试刺激来自真实 Valorant 录像，但没有 ground-truth 标注。它证明真实内容能走通采集/编码/网络/硬解/QNN/后处理，不证明检测准确率或控制命中率。

### 8.4 final8 真实视频十分钟 120 FPS

证据目录：`analysis_output/final8-live-120fps-20260723`，候选、归档哈希和逐字段复算见其 `metrics.md`。

| 端 | 精确窗口 | 增量 | 实测速率 | 关键差分 |
|---|---:|---:|---:|---|
| Host | 610.604 s | 72,998 published | **119.550 FPS** | capture timeout、staging busy、completion drop、recovery `+0`；DXGI missed present `+295`；`map_was_still_drawing +2738`；`mailbox_superseded +4` |
| Mobile | 605.001 s | 72,321 completed；72,320 QNN | **119.539 / 119.537 FPS** | rejected datagram、reassembly expiration、input drop、preprocess failure、QNN failure、Java offer/dispatch 均 `+0` |

Host 选取 trace `vfhost-1784770964169-38980` sequence `55 -> 177`；Mobile 选取 trace `996514fd-b316-474d-9b7d-1045720966f3` sequence `65 -> 186`。两个窗口没有同帧边界，不能把两端增量直接相减或声称跨端逐帧零丢失。可以确认的是 Mobile 选定内部窗口的已记录拒收、重组过期、输入 drop 和 QNN failure 差分为 0；Host 生产端仍明确存在上表的异步读回未就绪与 4 次邮箱覆盖。

Mobile 终点滚动 300 样本：预处理 P50/P95 `0.562/0.646 ms`，QNN `1.927/2.598 ms`，推理总计 `2.098/2.850 ms`，解码队列 `5.444/7.004 ms`。全程 `output_requested=0`、`output_enabled=0`，没有驱动实体 MAKCU。

本次仍使用无标注真实 Valorant 录像，只能证明真实内容的 120 FPS 热路径稳定性，不能据此发布检测准确率或控制命中率；精度结论仍只来自 484/484 有标注数据集。

### 8.5 当前候选实体 move-only 控制闭环

当前 APK 在 Xiaomi 14 Pro 上以前台 `MobileRuntimeService` 持有 CAT6、MediaCodec、QNN 和 MAKCU 生命周期，Activity 已切到后台。输入使用本机真实 Valorant 录像，由 Host 对实际桌面中心 ROI 采集，不是伪造检测或直接调用串口。

| 证据点 | 实测值 |
|---|---:|
| 最大单帧检测数 | 4 |
| `candidate_moves` | 301 |
| `java_offer_acceptances` | 301 |
| `device_command_acknowledgements` | 301 |
| `device_move_acknowledgements` | 301 |
| QNN / 连续 QNN failure | 0 / 0 |
| device ACK failure / unexpected response / parser overflow | 0 / 0 / 0 |
| delivery failure / circuit open | 0 / 0 |
| 自动门 | `output_requested=1`、`output_enabled=1` |
| 独立物理结果 | Windows 光标由 `(590,403)` 移动到 `(1198,118)` |

固件 echo/prompt 只能证明 MAKCU 已确认命令，不能单独证明物理执行；上表最后一行使用 Windows 光标位置作为独立证据，二者合并后才认定 `视频 -> QNN -> 控制核心 -> JNI -> USB -> MAKCU -> 物理移动` 闭环通过。测试只覆盖 `km.move`；点击、自动开火、压枪、回闪和滚轮不属于本产品范围。

Activity 切到后台后，进程与前台服务持续存活；后续健康快照达到 314 次 move 候选、314 次 JNI 接受和 314 次固件 move ACK，错误仍为 0。

CAT6 定向故障试验中，只禁用了 Windows `以太网`（InterfaceIndex 9），WLAN 默认路由保持不变。断链后日志记录 `control_output_auto_locked reason=runtime_stopped` 和 `mobile_control_runtime_fail_closed reason=ethernet_unavailable_network_lost`；光标在 T+0、T+2、T+6 秒均为 `(672,783)`。重新启用网卡后，手机在 `84,612 us` 内恢复流水线并记录 `control_output_auto_ready`，随后光标移动到 `(719,494)`。这证明输出门故障关闭和健康恢复均不依赖人工开关。

### 8.6 ACK-ticket 最终候选复验

最终候选在 8.5 自动健康门基础上增加单条在途 ticket、100 ms 固件 ACK 超时、错 ticket fail-close，以及“更新帧序号 + ACK 后至少 8 ms”的可见性屏障。ACK 在途和可见性屏障通过前不推进 tracker/PID/residual/jerk，也不补发积压方案。

最终累计为 351 个候选、345 个 Java 接受、345 个 native 匹配 ACK、345 个 MAKCU move ACK；native ACK failure、timeout、stale feedback、device ACK failure 与 delivery failure 均为 0。`post_ack_visibility_suppressed=170`，证明旧画面重复规划确实被屏障拦截。

两段独立抽样都满足 `candidate/java/native-ack/device-ack` 同时 `+1`：故障前 Windows 光标由 `(640,3)` 变为 `(638,3)`；CAT6 故障恢复后由 `(629,3)` 变为 `(626,3)`。断链窗口中 `(634,3)` 在 T+0、T+0.5、T+2、T+6 秒保持不变；WLAN 仍是唯一活动默认路由。恢复流水线耗时 `83,182 us`，无需手动控制开关。完整证据见 `analysis_output/mobile-ack-ticket-final-20260723/metrics.md`。

最终滚动 162 样本：预处理 P50/P95 `0.591/1.257 ms`，QNN `1.875/3.159 ms`，推理总计 `2.068/3.369 ms`，解码队列 `8.348/15.934 ms`。Activity 切到后台后 PID `26589` 与前台 `MobileRuntimeService` 均持续存在。

最终安装进程连续观察 `927.298 s`（超过 15 分钟），其中故意包含一次 CAT6 禁用/恢复和多次真实视频播放器重启。终点进程仍存活，QNN 4,123 次且失败/连续失败均为 0，345 条已确认 move 的 native ACK、device ACK 和 delivery failure 均为 0。该窗口是故障恢复 soak，不冒充 15 分钟无中断视频吞吐窗口。

## 9. UI 与空闲行为

- final8 保留停止、取消、启动失败、运行失败、重新发现和新会话边界的 telemetry 清空语义；数值控件原位更新，不重建整页。
- final8 按当前 DPI 反算最小客户区 `893x620`。本机 1920x1080、125% DPI 的最大化 `1938x1038` 外框、ready 最小外框 `911x667` 和 running 最小外框 `911x667` 均已物理截图复核，标题、主操作、指标、链路、事件与页脚完整可见。证据见 `analysis_output/design_qa/design-qa.md`。
- 无发送端的 299.999 秒手机空闲窗口中，`receiver_timeouts` 仅增加 69 次（`0.2300 次/s`），`receive_timeout_us` 从 500,000 退避到 5,000,000；accepted/completed/IDR 均保持 0。有效视频到来后超时恢复为 100,000 us。该数据证明 wakeup 频率下降，不等同于 CPU 或功耗测量。
- 停流尾段观察到恢复 IDR 只新增 4 次，随后 timeout 从 500,000 进入 1,000,000 us 档；输出门仍为 0。5 秒退避档由上一条完整 300 秒空闲窗口证明。
- 15.074 秒历史 Host 空闲采样：CPU `0.171875 s`，16 逻辑处理器，折算整机 `0.0713%`、单核等效 `1.1402%`；Host 日志大小无增长且窗口响应正常。
- 96/144/192 DPI 和其他显示器组合仍缺少完整物理截图矩阵，不能把本机 125% DPI 的 PASS 外推到所有显示配置。

## 10. 控制链路成熟度

当前可以证实：

- 后处理、跟踪、move 候选计算在手机热路径运行；
- 自动门只在 Ethernet、视频、解码、QNN 与 MAKCU 全部健康时打开；
- CAT6 丢失时自动 fail-close，链路恢复后自动恢复；
- Activity 在后台时前台服务继续持有完整运行时；
- MAKCU 已逐条返回固件 echo/prompt，且独立 Windows 光标位置证明物理移动；
- Host 没有控制职责。

当前不能证实：

- 每一条命令对应的传感器级位移量；固件 ACK 和终点光标变化不能替代高速外部运动测量；
- 控制算法在真实对局中的命中率；当前录像物理闭环没有逐帧人工控制 ground truth；
- 其他 MAKCU 固件、手机、USB 扩展坞和鼠标组合的兼容性。

因此当前定义的 **move-only 产品控制闭环为 PASS（当前硬件）**；跨设备兼容性和真实对局效果仍是独立验收项，不能外推。

## 11. 验收矩阵

| 项目 | 状态 | 当前证据/缺口 |
|---|---|---|
| CAT6-only 固定数据面 | PASS | 两端固定地址、socket bind 与路由证据 |
| Host 无输入控制/SendInput | PASS | 代码边界与运行时路径 |
| 320x320 中心 ROI | PASS（本机） | 捕获几何事件与真实视频测试 |
| 本机跨卡 NVENC | PASS | Iris Xe 捕获 -> RTX 3050 Ti NVENC |
| Microsoft 软件回退 | PASS（本机） | 320x320 热路径 |
| final5 十分钟持续吞吐 | PASS（当前硬件） | Host/Mobile 约 143.9 FPS，稳定窗口无手机新增 drop |
| final8 十分钟真实视频 120 FPS | PASS（当前硬件） | Host 119.550、Mobile 完成/QNN 119.539/119.537 FPS；手机内部窗口 0 drop/failure；Host 保留 `map +2738`、`mailbox +4` |
| QNN HTP V75 | PASS（当前手机） | QNN 审计与 final8 稳定窗口 72,320 次连续执行 |
| 其他 Snapdragon/QNN 代际 | NOT VERIFIED | 只有打包闭包，无实体机证据；V81 缺失 |
| Intel QSV 硬编码 | PASS（当前硬件） | Adapter-LUID 同卡筛选；320x320、100 帧、P50 约 3.09 ms；安全停止 |
| AMD VCN 硬编码 | NOT VERIFIED | 通用 Adapter-LUID 路径和测试已完成，无 AMD 实机 |
| 纯核显/纯 CPU 多机性能 | NOT VERIFIED | 无目标机器实测 |
| 多屏/4K/负坐标实机矩阵 | PARTIAL | 策略测试通过，本机物理覆盖不足 |
| move-only MAKCU 控制迁移 | PASS（当前硬件） | 最终候选 351/345/345/345（候选/Java/native ACK/device ACK），独立光标位置确认物理移动 |
| 实体 MAKCU 故障安全与恢复 | PASS（当前硬件） | CAT6 断链 6 秒零移动；恢复后自动重新就绪并移动 |
| 模型准确率 | PARTIAL（单数据集 PASS） | `images1` 484/484 帧真实手机 QNN：AP50 0.9211、mAP50-95 0.4892；泛化与其他数据集未验收 |
| 生产 APK 签名 | FAIL | 当前为 Android Debug 开发签名 |
| final8 安装文件内容绑定 | PASS（测试时点） | 手机拉回 `installed-base.apk` 与候选 APK 字节数、SHA256 完全一致；不等于生产签名或远程证明 |
| final8 十分钟真实视频热路径稳定 | PASS（当前硬件） | 610.604/605.001 秒独立稳定窗口；未采集温度和功耗 |
| 温度、功耗与长期降频 | NOT VERIFIED | 十分钟归档没有温度/功耗采样，不能称热设计验收 |
| 独立 UDP 0% 丢包验收 | NOT VERIFIED | Host 探针 `loss=0` 不能替代序列化 UDP 测试 |

## 12. 下一阶段必须保留的验收项

1. 同版本工具或独立 sequence/timestamp harness 完成 UDP 50/100/200 Mbps 双向测试，报告丢包、乱序、重复与抖动；
2. 在 final8 十分钟真实视频基础上补采温度、功耗和更长时段的降频记录；
3. 使用高速外部测量手段标定 MAKCU 指令到物理位移的逐命令延迟和量化误差；
4. AMD、Intel 核显、纯 CPU、NVIDIA 同卡、外接多屏/不同 DPI 的逐机验收；
5. V68/V69/V73/V79 目标 Snapdragon 实机验收，并决定 V81 支持策略；
6. 在更多地图、光照、分辨率和类别数据集上复测 mAP、Precision、Recall，并补齐当前模型文件/量化图的可验证 build ID；
7. 使用正式受控签名生成生产 APK，重新核对安装升级与回滚路径。
