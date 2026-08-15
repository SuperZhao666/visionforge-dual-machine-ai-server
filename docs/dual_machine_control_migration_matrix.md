# Android 双机控制算法迁移矩阵

> Current migration note (2026-08-01): this migration matrix was written before the four-model 416x416 runtime switch. Mentions of a 320x320 move-only contract below are historical notes, not the active model input contract.

## 不可变边界

双机链路的控制所有权固定在 Android：

```text
Windows 主机：DXGI -> H.264（NVENC 优先、Media Foundation 回退）-> UDP 视频（绝不生成、接收或执行控制）
Android C++20：解码 -> QNN/HTP -> 后处理 -> 选择/锁定/跟踪 -> 运动规划 -> 有界控制量
Android Java：UI、前台服务自动健康门、USB Host 串口
MAKCU：km.* 物理输出
```

禁止加入 SendInput、Windows 驱动回退、Android 到主机的控制 socket，或仅凭“视频已启动”绕过完整健康判定。当前物理输出只有
`MakcuSerialController` 写出的 `km.move(dx,dy)`。压枪/后坐力明确不属于本项目。手动背闪与自动触发/开火当前均未实现，
是否增加由用户另行决定；即使选择实施，也只能落在 Android -> MAKCU，并使用独立的 fail-closed 门，不能由 Host 或其他回退路径代偿。

状态定义：**已迁** 表示当前 Android move-only 产品热路径已有实现、测试和相应实体证据；**待用户决策** 表示当前未实现，
只有用户明确选择后才允许设计和开发；**产品外** 表示桌面旧功能不属于本双机产品，不能伪装成“待迁移”需求。

## 桌面模块到 Android 映射

| 桌面来源 | 桌面职责 | Android 当前映射 | 状态与证据 | 边界/后续验收 |
|---|---|---|---|---|
| `src/target_selector.py` | head 优先；无 head 时选 body 上部比例点；同类按置信度、离中心距离、面积排序 | `MobileControlCore::choose_best` / `candidate_for` | **已迁**：class 1 head 绝对优先，class 0 body 使用 `y1 + h*0.18`；同类保持桌面排序契约；权威一对一 head/body 配对来自 `MobileTargetTracker` | 其他类别模型需要独立元数据和策略，不能沿用当前 class 0/1 |
| `src/detection_filter.py` | head/body 尺寸、宽高比、边界、远小目标、配对关系及校准模式几何过滤 | `YoloPostprocessor` 做解码/NMS；`MobileControlCore::geometry_reject_reason` 做控制前有限值、模型边界、边缘接触、分类尺寸和宽高比过滤；`MobileTargetTracker` 做一对一 head/body 配对 | **已迁**：逐原因计数、有限值/边界/尺寸/宽高比和一对一配对均有 C++20 回归，当前阈值另有 484 帧手机 QNN 数据集证据 | 桌面旧“校准模式”和未验证的裁切例外不属于当前产品；新数据分布需重新验收而非暗中放宽 |
| `src/target_validation.py` | 控制前移动目标复验、body fallback 复验、边缘和配对边界 | `MobileControlCore` 的 secondary validation、head-only/body-fallback gate 与配对/边缘 fail-fast | **已迁**：拒绝发生在 lock/PID 状态变更前，拒绝原因进入 native 指标；最终候选已有真实视频、QNN、345 个固件 ACK 和独立物理移动证据 | 跨设备/固件和真实对局效果仍需逐环境验收 |
| `src/target_lock.py` | 持续身份、track-id/IoU/距离连续性、切换确认、丢失预测/短保持、拒绝证据 | `MobileControlCore::association_admissible` / `match_locked` / `update_pending_switch` | **已迁**：稳定 track-id、GIoU/受限中心连续性、严格 singleton rebind、挑战者连续确认、head 对 body 绝对抢占及逐原因拒绝计数均已落地；paired head 短暂掉检时，完全相同且几何可信的 body track 仿射延续 head 目标，不换锁、不重置 planner | Mahalanobis 协方差门不是当前确定性 320x320 move-only 契约，不作为隐藏待办 |
| `src/tracker.py` | 桌面旧版 Kalman/EMA/多项式预测及 ego-motion | `MobileTargetTracker` 速度预测 + `MobileMotionPlanner` 速度/加速度前馈 | **已迁（当前确定性契约）**：稳定 track-id、限速速度观测、有界加速度估计与前馈已落地；预测误差夹在 head 安全区/body 框内 | Kalman/Mahalanobis 不是当前 320x320 move-only 必需条件；无相机响应标定时不伪造概率协方差 |
| `src/bytetrack_tracker.py` | 多目标两阶段关联、track-id、丢失 buffer | `MobileTargetTracker` | **已迁**：按类别隔离，高/低置信度两阶段关联，IoU/中心距离匹配，速度预测、lost buffer、稳定 track-id 和一对一 head/body 配对；非零且不一致的 track-id 禁止几何重关联 | 默认检测置信度 0.84；换模型或数据分布必须重新标定 |
| `src/head_aim_policy.py` | 将跟踪后的控制点限制在 head 安全内区和锚点滞后范围 | `MobileControlCore::candidate_for(head)` | **已迁**：head 锚点按比例计算，夹在安全 inset/radius 内，并施加最大锚点滞后；诊断与回归已覆盖 | 无当前产品缺口 |
| `src/runtime_controller.py` | PID、死区、限幅、残差/整形、时效门、过冲保护、响应标定、驱动调度 | `MobileControlCore::process` -> `MobileMotionPlanner::plan` -> `MakcuMoveBridge` | **已迁（move-only）**：帧龄/序号/单调时间门、响应 gain、PID/anti-windup、残差量化、速度/加速度前馈、phase/jerk/step/响应预算和自动 fail-close 均已落地；最终候选取得 345 个固件 ACK，并由两段独立光标变化确认物理执行 | 高速外部测量的逐命令时延/量化误差标定属于跨硬件验收，不是未接通代码 |
| `src/relative_response_guard.py` | 在线学习 px/count、未确认命令账本、近中心 crossing/step 安全预算 | `MobileMotionPlanner::response_budget` / final guard + `MakcuMoveCommitGate` / `MakcuMoveVisibilityGate` | **已迁（保守可证明契约）**：按轴响应上界、step/settle、最终方向/几何预算、单条 ACK ticket、100 ms 超时和 ACK 后更新帧+8 ms 可见性屏障均已落地 | 在线 px/count 学习需要外部可见响应标定；当前产品选择显式参数和保守屏障，不用未经验证的在线估计替代证据 |
| `src/motion_phase.py` | Acquire/Pursuit/Settle、滞回、pursuit jerk、近目标临界阻尼 | `MobileMotionPlanner::update_phase` / `jerk_axis` / settle guard | **已迁**：三相状态机、进入/退出滞回、pursuit acceleration/jerk、临界阻尼 settle PD、内圈 latch、限步和 crossing 抑制均有严格回归 | 无当前产品缺口 |
| `src/personal_trajectory_shaper.py` | 桌面个人轨迹画像、包络与变化度 | `PersonalTrajectoryProfile` 导入/持久化；`MobileMotionPlanner::shape_personal_packet` 在 Pursuit 阶段做确定性、有界整形 | **已迁（运行时）**：速度、稳定性、变化度和包络进入 Android C++ planner，并继续受限幅、jerk、翻转和收敛保护 | 手机本地画像采集、分析和历史管理尚未实现，列入待用户决策 |
| `src/ego_motion_timeline.py` | 只记录成功 HID 包，并在其可见帧时消费；有界 pending FIFO | `MakcuMoveCommitGate` + `MakcuMoveVisibilityGate` | **已迁（当前单在途契约）**：只有匹配 ticket 的固件 ACK 才释放；下一次规划还必须来自更新帧且晚于 ACK 8 ms；失败、错票据和超时全部 fail-close | 不声称完成游戏相机响应学习；需要外部标定后才可把 8 ms 保守屏障替换为设备/游戏特定模型 |
| `src/fire_state.py` | 桌面旧版自动开火与左键所有权 | 无 `km.left` 路径 | **待用户决策**：当前双机运行时只有 `km.move`，尚未实现自动触发/开火 | 若用户选择，必须是 Android 独立 fail-closed 状态机，异常/退出时保证释放；禁止放到 Host |
| `src/backflash_macro.py` | 桌面旧版物理侧键回闪宏 | 当前已能读取 MAKCU 物理按键流，但没有背闪状态机或按键输出 | **待用户决策**：当前没有回闪功能 | 若用户选择，必须由 Android 使用物理侧键手动触发，默认关闭，可中断、有冷却和完整日志 |

## 当前 Android 文件职责

| 文件 | 所有权 |
|---|---|
| `YoloPostprocessor.cpp/.hpp` | QNN split-output 解码、阈值和逐类 NMS；不拥有控制状态 |
| `MobileTargetTracker.cpp/.hpp` | 纯 C++20 多目标两阶段关联、稳定 track-id、lost buffer、速度预测与一对一 head/body 配对；不拥有 JNI/USB/网络 |
| `MobileMotionPlanner.cpp/.hpp` | 纯 C++20 响应预算、速度/加速度预测、运动相位、PID/残差、jerk/step 和 settle/翻转守卫；不拥有 JNI/USB/网络 |
| `MobileControlCore.cpp/.hpp` | 纯 C++20 几何过滤、freshness、选择、安全锚点、lock/switch/hold，并在目标选择后调用运动规划层；无 JNI/USB/网络依赖 |
| `MakcuMoveBridge.cpp/.hpp` | 唯一 native 控制边界；串行调用控制核心并把非零移动交给 Java |
| `MakcuSerialController.java` | 唯一 USB Host 串口所有者；latest-wins 写 `km.move`，不做目标/控制算法 |
| `MobileControlRuntime.java` / `ControlOutputCoordinator.java` / `ControlProfile.java` | 进程级控制所有权、前台服务自动 fail-close 健康门和参数持久化；Activity 只观察状态 |

## 第三切片验证边界

纯 C++ 回归：

```powershell
Set-Location android_inference_benchmark
g++ -std=c++20 -Wall -Wextra -Werror -pedantic `
  app/src/main/cpp/MobileMotionPlanner.cpp `
  app/src/main/cpp/MobileMotionPlannerTests.cpp `
  -Iapp/src/main/cpp -o $env:TEMP/vf_mobile_motion_planner_tests.exe
& $env:TEMP/vf_mobile_motion_planner_tests.exe

g++ -std=c++20 -Wall -Wextra -Werror -pedantic `
  app/src/main/cpp/YoloPostprocessor.cpp `
  app/src/main/cpp/MobileTargetTracker.cpp `
  app/src/main/cpp/MobileMotionPlanner.cpp `
  app/src/main/cpp/MobileControlCore.cpp `
  app/src/main/cpp/MobileControlCoreTests.cpp `
  -Iapp/src/main/cpp -o $env:TEMP/vf_mobile_control_core_tests.exe
& $env:TEMP/vf_mobile_control_core_tests.exe

.\gradlew.bat :app:verifyMobileMotionPlannerNative `
  :app:verifyMobileControlCoreNative --rerun-tasks --no-daemon
.\gradlew.bat :app:externalNativeBuildRelease --no-daemon `
  -PqnnSdkRoot=<QAIRT SDK 根目录>
.\gradlew.bat :app:check --no-daemon -PqnnSdkRoot=<QAIRT SDK 根目录>
```

新增 planner 用例覆盖：参数契约、NaN、无效/倒退时间、超龄/重复观测、phase 进出滞回、按轴响应预算、残差量化、pursuit step/jerk、速度/加速度预测、head/body 预测边界、方向翻转、settle crossing 和新目标状态复位。既有 core 用例继续覆盖 head/body 选择、安全 inset、lock/switch/hold、几何过滤、跟踪关联和控制前 freshness。

第二切片的真实时序入口位于 `NativeH264Decoder`：接收完成时的 `steady_clock` 时间保存在 pending frame，控制时用同一时间计算解码排队、预处理和 QNN 已消耗的帧龄。控制单调门使用手机进程内生成的 `control_sequence`，而不是会在主机编码恢复或链路切换后归零的主机 `frame_id`；主机帧号只保留作数据追踪。控制序号或 pending 时间缺失、倒退、重复或超龄时，C++ 核心保持零输出，并在 `makcu_move_bridge_report()` 暴露 stale、non-monotonic、几何拒绝、head 抢占、切换等待和 settle 计数。

`makcu_move_bridge_report()` 现在追加 phase、planner suppression、预测误差、加速度、响应预算、response/jerk/step limiter 以及各拒绝计数。paired-head 连续性由 `head_body_projection_continuations`、`head_body_projection_recoveries`、`maximum_head_body_projection_recovery_pixels` 与 `rejected_head_body_projection_geometry` 区分投影延续、真实头恢复、最大测量校正和几何拒绝；恢复帧会重基 planner 历史并保留原速度，防止把投影误差误算成单帧反向运动。该路径不包含 FPS 上限、固定发送周期或热路径休眠。诊断代表软件决策，不代表 USB 已接受。

设备 move completion 或 ACK 后可见性尚未满足时，fresh content 仍进入 `observe_tracking_only()`。该路径现在只允许完全相同的当前锁身份逐帧刷新 `locked_candidate_` 的几何和目标速度，也允许既有 paired-head 的升级、投影与真实头恢复；禁止确认 challenger 或发送第二条 move，且 `motion_plans` 必须保持不变。这样快速目标在 ACK 等待窗口内累计移动超过单帧锁几何门后，恢复发送仍从最新连续身份继续，而不是使用发送前旧框误入丢锁。`tracking_only_frames` 与 `tracking_only_lock_updates` 分别记录观察帧和成功锁刷新次数；该修复不增加等待时间或发送周期。

CS2 原先保留了通用的两帧丢锁保持，因此相同掉检在 200 FPS 约 10 ms、40 FPS 约 50 ms，手感随 fresh-content 吞吐变化。现在桥接层先应用用户/profile 的 `switch_confirmation_ms`，模型策略再将 CS2 `lost_target_hold_duration_us` 同步到该单调窗口；标准值为 25 ms，用户自定义 10–100 ms 仍是权威输入。OW2 继续使用独立 70 ms 丢锁保持，且模型策略不得覆盖用户的 switch confirmation。精简日志通过 `switch_confirm_us`、`lost_hold_us` 暴露最终有效值；这只改变时间判定，不限制帧处理或发送吞吐。

ACK 后画面响应若在锁/轨迹时限内仍无法确认，`MobileControlCore` 现在会废弃不可信的旧屏幕空间锁，并复用既有的单调时间切换确认完成重捕获。超时当帧的任意替代检测不能直接产生第二次相机移动；`reacquisition_pending_frames` 与 `reacquisition_confirmations` 记录等待和完成。该路径不休眠、不节流，fresh observation 仍全部处理。

paired-head 的 head/body 是同一物理人物，不再能共同伪造“两目标相机位移”。可见响应拟合按当前有效数量从 head 或 body 中只选一个见证类别；一个人物最多贡献一次，多人物的同类轨迹仍可形成共同位移。单人物 support 只确认响应已可见，实际应用仍采用保守响应估计，避免吞掉目标自身速度；精简日志通过 `ego_response_support` 暴露最大支持数。

运行中修改 gain、deadzone、最大轴增量、switch confirmation 或个人轨迹时不再直接用新配置覆盖仍有旧 ticket 的 native 核心。`ControlOutputCoordinator` 按“关闭并排空物理交付→disabled profile 清理旧 ticket→应用 enabled 新 profile→重开交付”执行控制面事务；`configure_makcu_control_profile()` 同时持有 publish 线性化锁，防止旧 publish 的 Java 拒绝回调在新配置之后执行 fail-close。恢复暂停期内调参会保持 fail-closed，并由后续健康协调重新启用。该路径不在逐帧热路径中，不增加 FPS 上限、固定周期或休眠。

构建门禁仍只证明算法和 Android ARM64 编译闭包，不能单独证明物理执行。最终实体证据由真实 Valorant 视频、Xiaomi 14 Pro QNN/HTP、351 个候选、345 个 Java 接受、345 个 native 匹配 ACK、345 个 MAKCU 固件 ACK，以及两段独立 Windows 光标位置变化组成；ACK 后旧画面屏障触发 170 次。CAT6 断链 6 秒零移动，恢复后自动继续。该证据关闭了当前硬件上的 move-only 端到端缺口，但不能外推到其他手机、MAKCU 固件、扩展坞或鼠标。
