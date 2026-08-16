# VisionForge 单机版与双机版功能差异决策清单

> Current migration note (2026-08-01): this document predates the four-model 416x416 migration. Any 320x320 pipeline text below is historical; the active model set is defined by the Android and shared model catalogs.

更新日期：2026-07-23  
状态：前置问题已修复；本文件只列剩余差异，不授权继续实现。

## 1. 固定架构边界

```text
Windows Host
  DXGI 中心 320×320 ROI -> 硬件 H.264 -> CAT6 UDP

Android
  MediaCodec 硬解 -> QNN/HTP -> 后处理/跟踪/控制 -> MAKCU
```

- Host 只采集、编码、传输，不做推理、后处理、业务控制或输入输出。
- Android 持有推理、后处理、跟踪、运动规划、触发门和 MAKCU 输出。
- 当前正式数据面只有 CAT6，不恢复无线视频回退。

## 2. 本轮已修复，不再列为缺失

| 能力 | 当前状态 | 主要证据 |
|---|---|---|
| 健康/就绪视觉语义 | 已完成 | 链路、QNN、MAKCU、自动控制就绪均使用绿色和正向图标；黄色只表示等待/恢复，红色只表示真实错误 |
| 四种控制触发 | 已完成 | `始终开启`、右键、侧键 1、侧键 2 均为正式模式；2×2 布局；选中态为绿色 |
| 触发持久化与安全默认 | 已完成 | 用户明确选择 `始终开启` 后重启保持；新安装、缺失或损坏值默认侧键 2（Mouse5）；三个物理键模式均在入队、出队和 USB 写入前再次校验 |
| 拟人化/个人化移动 | 已完成运行时迁移 | 可导入桌面 `empirical_envelope_v1` 画像；支持开关、速度、稳定性、变化度；画像通过 JNI 进入 C++ planner，并受限幅、jerk、方向翻转和收敛保护 |
| 静止目标持续识别 | 已完成 | Host 对未变化画面发送 VFRR 保留帧；Android 继续解码和 QNN 推理，但不会把相同旧证据反复输出到 MAKCU |
| 静止画面重连 | 已完成 | 接收端重启后先拒绝无当前基准的 VFRR，并请求 IDR；首个当前 VFRG 只解锁一次，随后静止 VFRR 继续推理、保持控制抑制 |
| 检测到移动控制主链 | 已完成 | NMS、头身配对、几何过滤、两阶段跟踪、稳定 ID、目标锁定/切换/短时丢失、速度/加速度预测、Acquire/Pursuit/Settle、PID、残差、jerk/step/settle 保护均已在 Android C++ 落地 |
| MAKCU 手机直控 | 已完成 | 最终热路径只有 Android `km.move(dx,dy)`；Host 没有 SendInput 或控制 socket |
| 品牌图标一致性 | 已完成 | Android Launcher、最近任务和应用页头均复用 Host `app.ico` 对应的同一 512×512 品牌母图 |
| 关键日志 | 已完成基础链路 | Host 与 Mobile 均有 trace、sequence、捕获/编码/网络/解码/QNN/重复帧/重同步/触发/MAKCU 指标 |

### 本轮真机证据

- 完全静止的 320×320 目标画面持续得到两个检测框：
  - head：`class=1, confidence=0.850464`
  - body：`class=0, confidence=0.850464`
- 静止测试稳定窗口：
  - 网络重组、解码、QNN：`143.6 FPS`
  - QNN P50：`2.56 ms`
  - 推理总计 P50：`2.67 ms`
- 接收端冷重启后：
  - `resync_actionable_acceptances=1`
  - `last_detection_count=2`
  - `repeated_content_inferences` 与 `repeated_content_control_suppressions` 同步增长
- 最终品牌 APK 运行快照：
  - `repeated_content_access_units=3256`
  - `repeated_content_inferences=3252`
  - `repeated_content_control_suppressions=3252`
  - `trigger=mouse5`
  - `output_requested=0`
  - `output_enabled=0`
  - `offered_moves=0`
  - `usb_write_completions=0`
- 已导入个人画像仍在最终 APK 中生效配置：
  - `personal_trajectory_enabled=1`
  - speed `1.216`
  - stability `1.269`
  - variation `0.671`
  - envelope points `16`

## 3. 剩余八项：等待用户逐项决定

| 编号 | 单机版能力 | 双机版当前状态 | 若选择实施，正确落点 |
|---:|---|---|---|
| 1 | 本机响应校准、按游戏/DPI/分辨率/灵敏度保存画像 | **部分**：手机 C++ 已有轴向响应预算和保守上限，但没有实体校准工作流 | Android 采集与标定；结果进入 Mobile planner，不能把控制搬回 Host |
| 2 | 完整语义调参：识别、目标锁定、切换、短时丢失、稳定性、响应速度等 | **部分**：当前只暴露预设、增益、死区、单轴上限、置信度和个人画像三个尺度 | Android 仅暴露少量可理解的语义参数，映射到已有 C++ 策略；不把全部底层常量直接扔给用户 |
| 3 | 多模型与性能/精度档位 | **已迁**：当前为四模型 416x416 W8A16 QNN HTP 组合：`valorant-yellow-416-v11s-no-flash`、`overwatch2-416-yolov5`、`delta-force-416-v8s`、`counter-strike-2-vombit-416-v8s` | 模型注册表、输入、类别、量化、tensor contract、SoC 与手机实测数值报告见各模型 canonical 清单；CS2 私有构建使用同一套模型哈希闭包校验 |
| 4 | 个人轨迹采集、分析、生成和历史管理 | **部分**：手机已能导入并运行桌面画像，但不能在手机上制作/管理画像 | Android 制作工具与历史页；核心个人化 planner 无需重写 |
| 5 | 完整效果评估页和解释性报告 | **部分**：手机有原始 detection trace、推理页 pipeline metrics 和设置中的单文件运行日志导出，没有独立诊断页或成品评分报告 | Android 离线评估/报告层；复用已有 trace，不阻塞实时热路径 |
| 6 | 手动背闪宏 | **缺失** | 若用户选择：Android -> MAKCU，物理侧键手动触发，默认关闭，可中断、冷却并记录日志；禁止放到 Host |
| 7 | 自动触发/自动开火 | **缺失** | 若用户选择：独立于移动链的 Android fail-closed 状态机，并保证异常/退出时释放；禁止偷偷混入 `km.move` |
| 8 | 账号、授权、购买、在线更新、帮助、EULA、错误上报等商业产品壳 | **缺失/未迁移** | 由用户决定哪些进入 Android、哪些保留桌面；它们不是当前端到端控制闭环缺陷 |

## 4. 明确不是缺口

- 压枪/后坐力不是本项目能力，不迁移、不列待办。
- Windows SendInput、GHUB、Interception、Leonardo 不是双机移动端缺口。
- 桌面 CUDA/TensorRT/DirectML/CPU 推理栈不迁移到手机。
- Host 端推理、后处理、控制 socket、鼠标输出不迁移。
- 无线视频传输或无线回退不恢复。
- 不为了名称一致而强行替换当前已验证的两阶段跟踪和有界预测实现。

## 5. 历史可复核产物（SUPERSEDED）

The hashes and paths below belong to the historical acceptance evidence and
are not the current release identity. The current source of truth is
`release/release-manifest.json`; this checkout does not contain those ignored
or externally staged binaries, so they must not be treated as current
artifacts.

- 最终 APK：`android_inference_benchmark/app/build/outputs/apk/release/app-release.apk`
- APK 字节数：`128707847`
- APK SHA256：`A109E812F94B1C96E0B4D3C1035E5FB9697BC67A77F534F653E66AA52C772B91`
- 手机回拉 APK：`analysis_output/mobile-brand-final-installed-base.apk`，字节数和 SHA256 与本地最终 APK 完全一致
- 最终品牌真机图：`analysis_output/vf_brand_final.png`
- 最终四模式控制页真机图：`analysis_output/vf_control_brand_final.png`
- 静止目标与最终运行日志：`analysis_output/mobile-events-final.jsonl`、`analysis_output/mobile-events-brand-final.jsonl`

下一步必须由用户从第 3 节八项中明确选择；未选择项不继续实现。
