# VisionForge 控制链业务逻辑专项审查与低能力 LLM 修复指南（增量版）

> **仓库**：`SuperZhao666/visionforge-dual-machine-ai-server`  
> **审查分支**：`main`  
> **静态证据冻结提交**：`a488012430770b4c54259521508aa77cf7ff0193`  
> **文档性质**：上一份《全业务代码审查与低能力 LLM 修复指南》的**增量附录**，不是替代版。  
> **专项范围**：视频帧新鲜度 → 检测 → track 资格 → 运动规划 → native ticket → Java 传输 → 精确 ACK → ACK 后视觉反馈 → 故障恢复。  
> **结论**：发现 **7 项控制链问题**：P1 5 项、P2 2 项；另列出 6 组现场动态验证。没有把尚未动态复现的候选夸大为 P0。

## 1. 结论先行

用户描述的“**检测到目标，一开始还移动，后来完全不移动**”，与源码最吻合的首要故障链是：

1. 第一条或前几条移动获得精确 ACK；
2. native 侧 arm `MakcuMoveVisibilityGate`，要求下一次移动前必须看到 ACK 之后的新鲜画面；
3. 视频链出现重复帧/VFRR，`ReceiverRepeatResyncPolicy` 进入等待“新鲜、非 VFRR IDR”的状态；
4. 普通帧、重复帧和 VFRR IDR 都不能解除该状态；
5. 等待状态和 post-ACK gate 都没有完整的有界恢复生命周期；
6. 控制链继续 fail-closed，但没有清晰故障提示，于是表现为**先移动，后永久静默**。

这条链由 `CTRL-001 + CTRL-002` 描述，症状匹配度最高。其次应依次检查：

- `CTRL-003`：100ms 原生 ticket 总期限与 Java 写入/ACK 局部预算过近，可能把合法晚 ACK 判为过期；
- `CTRL-004`：检测框仍存在，但 track 重置后置信度不足以重新建立控制 track；
- `CTRL-005`：误差进入“死区之外、响应预算却向下取整为 0”的永久零输出带；
- `CTRL-007`：Bluetooth 物理状态恢复后，上层依赖周期性 reconcile，可能长时间仍未重新启用。

**不要先调阈值、删 gate、放宽重复帧或增加无限超时。** 第一修复波必须先加入统一 blocker 诊断并取得现场证据。

## 2. 与上一份报告的关系：防冲突硬约束

### 2.1 两份报告的权限边界

上一份报告继续负责：构建、发布门禁、正式安全、私有工件、部署、支付、授权、密钥、Sidecar、主站和运维。  
本报告只负责上述 Android 控制链中的**可靠性、liveness、状态语义、deadline 和可观测性**。

上一份报告有一条全局禁止项：“不得修改目标识别效果、控制算法、输入注入……”。本报告是用户明确授权的**窄范围例外**，仅允许：

- 修复重复帧/关键帧恢复状态机；
- 修复 ACK 后可见性等待的 liveness；
- 统一 ticket deadline；
- 区分检测、track 资格和规划终态；
- 在不削弱过冲保护的前提下修复无进展语义；
- 增加控制链诊断和事件驱动恢复。

本报告**不授权**扩大目标范围、提高自动化攻击性、改变模型效果、规避平台检测、删除安全约束或修改正式发布协议。

### 2.2 受保护路径

- server/**
- deploy/**
- dual_machine_runtime/formal_security_*
- dual_machine_runtime/production_usage_ticket_v1_public.pem
- android_inference_benchmark/app/formal-security-*
- android_inference_benchmark/app/formal-security-loader.gradle
- android_inference_benchmark/app/build.gradle
- android_inference_benchmark/app/src/main/cpp/CMakeLists.txt
- android_inference_benchmark/app/src/main/java/**/DualMachineReleaseSecurityConfig.java
- 任何支付、授权、entitlement、usage-ticket、密钥、Release 门禁或正式安全协议文件

### 2.3 条件共享路径

以下文件可能同时被旧报告的其他修复触及，任何修改必须执行 hunk 级人工冲突检查：

- android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java
- android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileControlRuntime.java
- dual_machine_runtime/shared/include/vfdual/model_contract.hpp

### 2.4 正确的分支基线

静态证据来自冻结提交 `a488012430770b4c54259521508aa77cf7ff0193`，但修复代码**不能**回到该提交覆盖正在进行的旧修复。每个 CTRL 任务必须基于“已经包含所有已接纳旧修复”的 active head：

```bash
git status --short
git rev-parse HEAD
git merge-base --is-ancestor a488012430770b4c54259521508aa77cf7ff0193 HEAD
git diff --name-only a488012430770b4c54259521508aa77cf7ff0193..HEAD > /tmp/visionforge-prior-changed-paths.txt
```

执行规则：

1. `git status --short` 非空时停止，不得自动 stash 或覆盖他人工作。
2. `merge-base --is-ancestor` 失败时停止，报告当前分支历史不包含审查基线。
3. 将本 Issue 的允许路径与 `/tmp/visionforge-prior-changed-paths.txt` 求交集。
4. 无交集：创建 `fix/CTRL-xxx-<slug>`，继续 RED。
5. 有同文件但无同 hunk：在 active head 上小步修改，运行两份报告涉及的测试。
6. 有同 hunk：停止自动修改，输出 `MANUAL_MERGE_REQUIRED`，由人工确定语义。
7. 每个 CTRL Issue 独立提交，不得把旧报告修复顺手重构。

## 3. 控制链实际状态流

```text
Host 视频流
  ↓
DualMachineReceiver
  ↓  [CTRL-001: repeat/VFRR 后可能无限 WAITING_FRESH_IDR]
ReceiverRepeatResyncPolicy
  ↓
NativeH264Decoder（只有新内容进入控制发布）
  ↓
YoloPostprocessor（检测展示阈值）
  ↓  [CTRL-004: 有检测 ≠ 可新建 track]
MobileTargetTracker
  ↓
MobileControlCore / MobileMotionPlanner
  ↓  [CTRL-005: 非死区但 response budget=0]
MakcuMoveBridge（single-flight ticket）
  ↓  [CTRL-003: 100ms 总期限与 Java 局部预算竞争]
ControlOutputMoveDispatcher
  ↓
USB MakcuSerialController / Bluetooth HID
  ↓
精确 ACK / 回执
  ↓
MakcuMoveVisibilityGate.arm()
  ↓  [CTRL-002: 等 ACK 后新鲜画面可永久 armed]
下一帧视觉响应确认
  ↓
下一次移动
```

控制停止并不等价于检测停止。系统中至少存在四类“有检测但无移动”的合法/异常状态：

- 检测存在，但没有达到新 track 资格；
- planner 判断死区、设备分辨率极限或响应 guard 不允许移动；
- ticket/传输/ACK 尚未完成或已经 fail-closed；
- ACK 后等待真正的新鲜画面，重复画面不能继续驱动。

当前实现缺少将这些状态统一暴露给用户的契约，因此必须先执行 `CTRL-006`。

## 4. 问题总表

| Issue | 严重度 | 证据状态 | 症状匹配 | 摘要 |
|---|---:|---|---|---|
| CTRL-001 | P1 | CONFIRMED_SOURCE | VERY_HIGH | 重复帧重同步状态可无限等待“新鲜非 VFRR IDR”，控制链缺少有界恢复 |
| CTRL-002 | P1 | CONFIRMED_SOURCE | VERY_HIGH | 成功 ACK 后的画面可见性门可永久保持 armed，缺少超时状态与恢复闭环 |
| CTRL-003 | P1 | CONDITIONAL_CONFIRMED | HIGH | 原生 100ms ticket 完成期限与 Java 25ms 写入 + 50ms ACK 预算过于接近，存在合法 ACK 被判过期的竞争 |
| CTRL-004 | P1 | CONFIRMED_SEMANTIC_GAP | MEDIUM_HIGH | “检测框可见”与“可建立控制 track”使用不同阈值，重置后可能持续检测但永远无法重新移动 |
| CTRL-005 | P1 | CONFIRMED_SOURCE | MEDIUM_HIGH | 响应上界向下取整产生“非死区但永久零输出”区间，最小一步救援到达得太晚 |
| CTRL-006 | P2 | CONFIRMED_SOURCE | DIAGNOSTIC_BLOCKER | 控制抑制原因被混入 deadzone 等计数，缺少唯一“当前阻断原因”状态 |
| CTRL-007 | P2 | CONDITIONAL_CONFIRMED | MEDIUM | Bluetooth HID 异步恢复未主动驱动控制协调器，恢复依赖周期性 reconcile |

## 5. 低能力 LLM 强制执行协议

每次只下发一个 CTRL Issue。禁止让低能力模型阅读标题后“顺手优化整个控制算法”。

### 5.1 固定顺序

1. 在包含旧修复的 active head 上创建单独分支。
2. 执行路径交集和 hunk 冲突检查。
3. 只读取本 Issue 的证据文件、直接调用方和测试。
4. 先写 RED 测试或故障注入，保存命令、退出码和关键输出。
5. 用不超过 12 行写清根因和触发序列；不能只说“可能是线程问题”。
6. 只修改允许路径；遇到受保护路径立即停止。
7. 保留 fail-closed、新鲜度、序列、IDR、exact ticket、授权和响应上界不变量。
8. 运行 GREEN：单元测试、状态机测试、故障注入和业务验收。
9. 检查 diff，没有阈值拍脑袋调整、无限超时、旧帧放行、无关重构。
10. 按固定字段报告，等待人工合并。

### 5.2 固定输出字段

```text
TASK_ID:
AUDIT_BASE_COMMIT:
ACTIVE_REPAIR_HEAD:
PRIOR_FIXES_PRESENT:
FILES_READ:
OVERLAP_CHECK:
RED_COMMAND_AND_OUTPUT:
ROOT_CAUSE:
FILES_CHANGED:
PATCH_SUMMARY:
GREEN_COMMAND_AND_OUTPUT:
BUSINESS_ACCEPTANCE:
SAFETY_INVARIANTS:
ROLLBACK:
UNRESOLVED:
```

### 5.3 全局禁止项

- 不得重置、覆盖、撤销上一份报告对应分支的已完成修复。
- 不得从冻结提交另起一条孤立分支后强推覆盖当前修复主线；必须基于包含已接纳旧修复的 active head。
- 不得修改 server、部署、支付、授权、usage-ticket、密钥、Release 门禁和正式安全协议。
- 不得删除重复帧、新鲜度、IDR、序列、ACK exact-ticket、授权或 fail-closed 检查。
- 不得用“超时后自动放行旧检测”恢复移动。
- 不得无条件降低检测/新 track 阈值、扩大目标范围或提升自动控制能力。
- 不得把 floor 直接改成 ceil、无条件发送最小一步或删除响应上界。
- 不得把所有超时改为无限/极大值。
- 不得把 HTTP/线程存活/检测框存在当作控制链业务成功。
- 不得一次修多个 CTRL Issue；每个 Issue 一个提交、一个 RED、一个 GREEN。
- 不得打印图像、目标坐标明细、票据、密钥或用户敏感数据到诊断日志。
### 5.4 可直接复制给低能力 LLM 的任务提示词

```text
你只修复任务 <CTRL-ISSUE-ID>。

审查证据基线是 a488012430770b4c54259521508aa77cf7ff0193，但你必须在“已经包含上一份报告已接纳修复”的当前 active head 上工作，
禁止 reset/checkout 回冻结提交覆盖旧修复。先执行 git status、rev-parse、merge-base 和 changed-path overlap 检查。

只读取并修改本 Issue 的 allowed_paths。命中 protected_paths、同 hunk 冲突、缺少现有恢复接口或协议语义不明确时，
立即停止并报告 MANUAL_MERGE_REQUIRED 或 HUMAN_PROTOCOL_DECISION_REQUIRED。

严格执行：
RED 复现 → 根因 → 最小补丁 → GREEN → 业务验收 → 安全不变量 → 回滚。
不得删除重复帧/新鲜度/IDR/序列/exact-ticket/fail-closed/授权/响应上界检查；
不得通过旧帧放行、无限超时、无条件降阈值、floor 改 ceil、无条件最小一步制造“又能动了”的伪修复。
未实际运行的测试写 NOT RUN 和原因。最后只按本报告规定的 15 个字段输出。
```

## 6. 修复波次

### W-CTRL0｜只加诊断与 RED 测试，不改变控制行为

- **任务顺序**：CTRL-006
- **退出条件**：现场停止时能得到唯一 blocker；所有后续任务先有可复现 RED。

### W-CTRL1｜修复新鲜内容/关键帧 liveness

- **任务顺序**：CTRL-001 → CTRL-002
- **退出条件**：重复帧仍不能驱动控制；等待新鲜 IDR 和 post-ACK 可见性均有有界、共享、可观测的恢复状态。

### W-CTRL2｜统一 ticket deadline 与 exact-once 终态

- **任务顺序**：CTRL-003
- **退出条件**：跨 JNI、USB 写入和 ACK 等待使用同一单调绝对 deadline；无双终态和错票。

### W-CTRL3｜修复检测展示与 track 资格语义

- **任务顺序**：CTRL-004
- **退出条件**：检测、track 资格和 active track 明确区分；任何阈值调整均通过模型 replay 和人工门禁。

### W-CTRL4｜修复安全响应 guard 的收敛语义

- **任务顺序**：CTRL-005
- **退出条件**：不存在 active 状态下无解释的永久零输出区间；过冲保护不回退。

### W-CTRL5｜事件驱动的 Bluetooth 恢复

- **任务顺序**：CTRL-007
- **退出条件**：异步连接恢复能立即、幂等地触发 reconcile，周期健康检查仍作为后备。

## 7. 逐项修复说明

### CTRL-001｜P1｜重复帧重同步状态可无限等待“新鲜非 VFRR IDR”，控制链缺少有界恢复

**证据状态**：CONFIRMED_SOURCE；源码状态机闭合；是否为本机主因需动态日志确认  
**症状匹配**：VERY_HIGH  
**摘要**：一旦接收端观察到重复帧，ReceiverRepeatResyncPolicy 会进入 awaiting_fresh_idr；此后普通非 IDR 帧和 VFRR IDR 都不被视为可恢复内容，只有新鲜、非 VFRR 的 IDR 才解除。该状态本身没有超时、重试预算、主动请求 IDR 或重建会话的闭环。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/cpp/ReceiverRepeatResyncPolicy.hpp`
- `android_inference_benchmark/app/src/main/cpp/DualMachineReceiver.cpp`
- `android_inference_benchmark/app/src/main/cpp/NativeH264Decoder.cpp`

**关键符号/路径**

- `vfdual::ReceiverRepeatResyncPolicy::on_repeat`
- `vfdual::ReceiverRepeatResyncPolicy::should_accept`
- `vfdual::ReceiverRepeatResyncPolicy::awaiting_fresh_idr`
- `DualMachineReceiver 的重复帧/IDR 接收分支`

**源码事实**

- `on_repeat()` 将 `awaiting_fresh_idr_` 置为 true。
- 等待期间，非 IDR 的普通帧被拒绝；带 VFRR 标记的 IDR 也不能解除等待。
- 只有新鲜、非 VFRR 的 IDR 才清除等待状态。
- 策略对象没有记录进入时间、恢复期限、重试次数或升级动作。
- 控制发布只接受可操作的新内容；因此该等待可使后续检测与移动链长期没有新输入。

#### 触发序列

1. 系统正常收到新内容，检测到目标并至少成功移动一次。
2. 流进入重复帧/VFRR 路径，策略进入 `awaiting_fresh_idr`。
3. 发送端后续只给 P 帧、重复帧，或给带 VFRR 标记的 IDR。
4. 接收端持续拒绝这些帧作为新鲜控制内容。
5. 没有主动请求合格 IDR、超时重连或明确故障状态，控制表现为永久停止。

#### 根因

安全策略只定义了“什么帧不能继续控制”，没有定义“等待新鲜关键帧失败后如何有界恢复”。这是典型的 fail-closed 正确、liveness 不完整：拒绝重复内容是正确的，但无限等待不是完整业务状态机。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/cpp/ReceiverRepeatResyncPolicy.hpp`
- `android_inference_benchmark/app/src/main/cpp/DualMachineReceiver.cpp`
- `与上述策略直接对应的新 C++ 测试文件`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 使用可控单调时钟：先送一帧可操作内容，再送 repeat/VFRR，确认进入 WAITING_FRESH_IDR。
2. 持续送普通 P 帧和 VFRR IDR，证明当前代码永远不会退出等待。
3. 持续时间超过配置的恢复期限，当前代码仍不产生重同步请求、会话重建或明确终止状态，测试必须 RED。
4. 送入新鲜非 VFRR IDR，确认当前允许恢复；此测试用于保留既有安全语义。

#### 精确修复步骤

1. 把布尔量扩展为明确状态：NORMAL、WAITING_FRESH_IDR、RECOVERY_REQUESTED、RECOVERY_EXHAUSTED；不要用多个松散布尔量。
2. 记录 `entered_at_monotonic_us`、`last_repeat_sequence`、`recovery_attempts` 和 `session_epoch`。
3. 保留当前拒绝规则：等待期间绝不能把重复帧、普通 P 帧或 VFRR IDR伪装成 `content_updated=true`。
4. 在等待超过有界期限后，通过 Receiver 已存在的生命周期接口发出一次幂等恢复请求：优先复用现有“请求关键帧”能力；若协议没有该能力，则复用现有断流/重连/解码器重建路径。
5. 若仓库没有可复用的请求 IDR 或会话重建接口，立即停止编码并报告 `HUMAN_PROTOCOL_DECISION_REQUIRED`；不得擅自发明未认证的线协议消息。
6. 恢复请求必须限频并带 session epoch；同一等待周期只能有一个在途恢复动作。
7. 达到重试预算后进入 RECOVERY_EXHAUSTED：继续 fail-closed，停止声称控制正常，并把原因上报给运行状态。
8. 只有新鲜非 VFRR IDR 或全新 session epoch 才能回到 NORMAL；普通帧不得越权解锁。

#### 禁止的伪修复

- 把 repeat/VFRR 帧直接标记为新内容。
- 等待超时后直接允许旧检测继续移动。
- 删除 IDR、新鲜度或 VFRR 判定。
- 用无限重连循环代替有界恢复。
- 在没有现有协议依据时自行增加一个未认证的“请求 IDR”网络消息。

#### GREEN 与业务验收

- 重复内容期间移动计数保持为 0，安全不回退。
- 达到恢复期限后恰好触发一次恢复动作，重复定时器不会造成重连风暴。
- 获得新鲜非 VFRR IDR 后，在同一或新 session epoch 中恢复可操作帧。
- 一直得不到合格 IDR 时进入明确的 RECOVERY_EXHAUSTED，而不是无限静默等待。
- 状态、进入时间、等待年龄、重试次数可从诊断快照读取。

**依赖**：CTRL-006  
**人工门禁**：必须  
**冲突策略**：本任务独占 ReceiverRepeatResyncPolicy 与 DualMachineReceiver 的重同步状态机。CTRL-002 只能消费其状态/恢复接口，不能再实现第二套 IDR 重试逻辑。  
**回滚**：回退到原拒绝策略并保留新增诊断字段；若新恢复动作造成重连风暴，立即关闭自动恢复开关，继续 fail-closed 并保留 RECOVERY_REQUIRED 告警。

### CTRL-002｜P1｜成功 ACK 后的画面可见性门可永久保持 armed，缺少超时状态与恢复闭环

**证据状态**：CONFIRMED_SOURCE；源码条件闭合；与 CTRL-001 组合高度符合用户症状  
**症状匹配**：VERY_HIGH  
**摘要**：每次精确移动 ACK 成功后，原生侧会 arm 可见性门。只有后续帧同时满足“内容更新、序列号更大、观测时间不早于 ACK”才允许下一次移动。门没有最大等待时间、状态年龄、恢复动作或故障转移；若新鲜内容链中断，第一次移动后即可长期静默。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp`
- `android_inference_benchmark/app/src/main/cpp/MakcuOutputGate.hpp`
- `android_inference_benchmark/app/src/main/cpp/MakcuOutputGateTests.cpp`
- `android_inference_benchmark/app/src/main/cpp/NativeH264Decoder.cpp`

**关键符号/路径**

- `fail/success completion path that arms MakcuMoveVisibilityGate`
- `MakcuMoveVisibilityGate::arm`
- `MakcuMoveVisibilityGate::allows`
- `publish_makcu_move_for_detections`

**源码事实**

- 精确移动完成成功后，gate 记录源帧序列和 ACK 单调时间并进入 armed。
- 解锁要求 `content_updated` 为真、帧序列严格大于源序列、观测时间不早于 ACK。
- gate 没有 armed 年龄、最大等待期限、timeout 状态或恢复回调。
- 现有测试正确要求重复画面永远不能驱动后续移动，但没有测试长期等待后的诊断和恢复。
- NativeH264Decoder 只把真正更新的内容发布到控制链，因此重复帧期间 gate 可持续 armed。

#### 触发序列

1. 目标检测产生第一条移动，传输返回精确 ACK。
2. MakcuMoveVisibilityGate 被 arm。
3. 后续流只有重复内容，或 Receiver 因等待新鲜 IDR 不再交付新内容。
4. gate 的三项解锁条件持续不满足。
5. 没有超时转移，所有后续移动被抑制，看起来像“开始动，之后完全不动”。

#### 根因

ACK 后视觉反馈屏障是正确的安全/闭环设计，但实现只有成功解锁路径，没有WAITING、RECOVERY_REQUIRED、EXHAUSTED 等失败生命周期。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/cpp/MakcuOutputGate.hpp`
- `android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp`
- `android_inference_benchmark/app/src/main/cpp/MakcuOutputGateTests.cpp`
- `仅为本 gate 新增的测试/诊断结构`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 成功完成 ticket 并 arm gate；持续提供重复帧，证明当前 gate 永久 armed。
2. 提供序列更大但 `content_updated=false` 的帧，必须仍拒绝。
3. 提供内容更新但观测时间早于 ACK 的帧，必须仍拒绝。
4. 超过预期等待期限，当前代码没有状态转换或恢复请求，测试必须 RED。

#### 精确修复步骤

1. 为 gate 增加显式快照：DISARMED、WAITING_POST_ACK_VISIBILITY、RECOVERY_REQUIRED；记录 armed_at、source_sequence、required_observed_at、session_epoch。
2. 引入与 CTRL-001 共用的 `fresh_content_recovery_timeout`，不得再创建互相矛盾的第二套超时常量。
3. 超时后绝不能直接解锁并继续移动；应转入 RECOVERY_REQUIRED，保持输出 fail-closed，并调用 CTRL-001 提供的幂等恢复接口。
4. 获得满足三项原条件的新鲜内容后正常 disarm；保留所有现有新鲜度、序列和单调时间约束。
5. 会话 epoch 变化时允许以明确的 session reset 方式清理旧 gate；不能仅因任意异常就静默清门。
6. 将 gate 当前状态、等待年龄、源序列、当前序列、所需/实际观测时间写入统一 blocker 快照。
7. 若 CTRL-001 尚未完成，本任务只实现状态和诊断，不单独实现重连；以依赖阻塞结束，避免两套恢复器竞争。

#### 禁止的伪修复

- 删除可见性门。
- 把超时等价为“自动放行下一次移动”。
- 放宽为序列相等、旧时间或重复内容也能解锁。
- 收到任意检测框就清除 gate。
- 在 CTRL-001 之外再实现一套独立重连/请求 IDR 逻辑。

#### GREEN 与业务验收

- 正常新鲜帧在 ACK 后到达时，gate 按原规则解除且控制继续。
- 重复帧、旧序列、ACK 前观测帧始终不能解除 gate。
- 超时后状态变为 RECOVERY_REQUIRED，输出仍为 0，并只触发一次共享恢复动作。
- 新 session 或合格新鲜 IDR 恢复后，旧 gate 不污染新 epoch。
- 诊断能直接回答 gate 已等待多久、在等哪一帧、为何未解锁。

**依赖**：CTRL-001, CTRL-006  
**人工门禁**：一般代码审查即可  
**冲突策略**：本任务只拥有 post-ACK visibility gate。IDR 请求、会话重建和重试预算归 CTRL-001；响应确认逻辑不在本任务中改写。  
**回滚**：关闭自动触发恢复但保留 timeout 状态和指标；不得回滚为超时自动放行。

### CTRL-003｜P1｜原生 100ms ticket 完成期限与 Java 25ms 写入 + 50ms ACK 预算过于接近，存在合法 ACK 被判过期的竞争

**证据状态**：CONDITIONAL_CONFIRMED；预算冲突已由源码确认；真实触发频率需时序采样  
**症状匹配**：HIGH  
**摘要**：原生 pending move 的最大完成年龄为 100ms，计时在 JNI 投递前开始；Java USB 路径本身允许约 25ms 写入和 50ms 精确响应等待，再叠加线程排队、JNI、USB 调度和解析，余量很小。负载抖动时原生可能先过期，Java 随后才收到正确 ACK，继而触发 fail-close/重连链。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MakcuSerialController.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MakcuResponseStreamParser.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputMoveDispatcher.java`

**关键符号/路径**

- `kMaximumMoveCompletionAgeUs`
- `MakcuSerialController 的写入超时`
- `MakcuSerialController 的 exact ACK timeout`
- `completeMakcuMove / native ticket completion path`

**源码事实**

- 原生 ticket 完成年龄上限为 100,000 微秒。
- Java 串口写入超时约 25ms，精确响应等待约 50ms。
- 原生计时还包含 Java executor 排队、JNI 调度、USB 调度和解析时间。
- 当前接口没有把统一绝对 deadline 传递给 Java，各层分别按自己的局部超时判断。
- 晚到 ACK 与原生过期之间缺少结构化、可观测的裁决结果。

#### 触发序列

1. 控制线程创建 ticket 并开始 100ms 原生计时。
2. Java 控制 executor 因 GC、调度或前一任务延迟排队。
3. USB 写入接近 25ms，ACK 接近 50ms。
4. 原生在 Java 回报前判定 ticket 过期并 fail-close。
5. 合法 ACK 晚到，被当成 stale/错误，传输进入重连或熔断，移动中断。

#### 根因

多层使用相对超时而没有共享单调绝对 deadline；总预算没有包含排队和跨层开销，也没有 exact-once 的超时/晚 ACK 终态协议。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputMoveDispatcher.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputMoveSink.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MakcuSerialController.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MakcuPendingMoveSlot.java`
- `对应 Java/C++ 测试文件`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 用可控 scheduler 模拟 30ms 排队 + 25ms 写入 + 50ms ACK，证明局部均未超时但总年龄超过 100ms。
2. 模拟原生先过期、Java 后收到正确 ACK，证明当前可能出现两个终态或错误 fail-close。
3. 模拟 ACK 恰好位于 deadline 前后 1ms，验证边界是否确定且只完成一次。
4. 模拟旧 ticket 晚 ACK 到达新 ticket 已创建的场景，确保不会完成或解锁错误 ticket。

#### 精确修复步骤

1. 确定一个唯一的单调绝对 deadline，由创建 ticket 的原生层生成，并随 ticket 跨 JNI 传给 Java；不要只传相对毫秒。
2. Java pending slot 保存 ticket、issued_at、deadline；进入 executor、写入前、等待 ACK 前均计算 remaining budget。
3. 写入和 ACK 等待必须裁剪到剩余预算；剩余预算不足时返回明确的 EXPIRED_BEFORE_WRITE 或 EXPIRED_BEFORE_ACK。
4. 定义结构化终态：ACK_OK、WRITE_TIMEOUT、ACK_TIMEOUT、DEADLINE_EXPIRED、STALE_ACK、TRANSPORT_ERROR；禁止用一个布尔量混合。
5. 用原子 compare-and-set 确保每个 ticket 只完成一次；晚 ACK 只能记录为 stale，不得重新 arm gate，也不得完成后续 ticket。
6. 把 queue_delay_us、write_duration_us、ack_duration_us、total_age_us、deadline_remaining_us 写入诊断。
7. 先通过故障注入测出 P99/P99.9，再由人工选择总 deadline；不得仅把 100ms 随意改成 5000ms。
8. 若 deadline 到期时底层命令状态不确定，保留现有 fail-closed/reconnect 语义；修复目标是确定裁决，不是忽略超时。

#### 禁止的伪修复

- 简单把所有超时改成无限或极大值。
- 收到任何 ACK 都视为当前 ticket 成功。
- 删掉 exact ticket 校验。
- 原生和 Java 各自保留互不相关的独立总超时。
- 晚 ACK 后直接恢复 gate，而不检查 ticket 和 session epoch。

#### GREEN 与业务验收

- 每个 ticket 恰好一个终态，任何并发顺序下完成次数均为 1。
- 总 deadline 前的精确 ACK 成功，deadline 后的 ACK 只计 stale，不改变控制状态。
- 正常负载和注入抖动下不再出现“局部都成功、总链却过期”的模糊结果。
- 故障时仍 fail-closed，且能区分排队过久、写入超时、ACK 超时和晚 ACK。
- 至少完成 10,000 次故障注入/边界循环，无错误 ticket 解锁。

**依赖**：CTRL-006  
**人工门禁**：必须  
**冲突策略**：只修改 ticket 生命周期和交付时序，不修改 USB 协议字节、正式安全协议或设备授权。  
**回滚**：保留新增诊断，回退 deadline 传播；若出现错误放行，立即恢复原 100ms fail-closed 行为。

### CTRL-004｜P1｜“检测框可见”与“可建立控制 track”使用不同阈值，重置后可能持续检测但永远无法重新移动

**证据状态**：CONFIRMED_SEMANTIC_GAP；阈值语义差异已确认；是否命中用户现场需记录置信度  
**症状匹配**：MEDIUM_HIGH  
**摘要**：后处理阈值低于新建 track 阈值。目标置信度落在两者之间时，界面/检测结果仍可显示目标，但 tracker 不允许建立新的控制 track。控制因响应确认失败或丢轨重置后，这种差异会从“之前能跟踪”变成“仍检测到却永远不再移动”。

#### 证据定位

**文件**

- `dual_machine_runtime/shared/include/vfdual/model_contract.hpp`
- `android_inference_benchmark/app/src/main/cpp/YoloPostprocessor.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp`

**关键符号/路径**

- `postprocess confidence threshold`
- `new_track_confidence_threshold`
- `MobileTargetTracker 的新轨建立判定`
- `MobileControlCore 的 reset/reacquisition 路径`

**源码事实**

- Valorant 合同示例：后处理约 0.27，新建 track 约 0.50。
- OW2 示例：约 0.20 对 0.40；Delta：约 0.20 对 0.50；CS2：约 0.25 对 0.40。
- YoloPostprocessor 会保留达到后处理阈值的检测。
- MobileTargetTracker 对冷启动新 track 使用更高阈值。
- MobileControlCore 在响应确认超时、丢轨或恢复时可重置/重新获取 track。

#### 触发序列

1. 高置信度目标先建立 track，系统开始移动。
2. 因可见性、响应确认、短暂遮挡或传输故障，控制核心重置 track。
3. 目标仍被检测，置信度落在 postprocess 与 new-track 阈值之间。
4. 检测结果继续存在，但 tracker 持续拒绝建立新控制 track。
5. 系统没有对用户暴露“检测到但不具备 track 资格”，表现为无原因停止。

#### 根因

检测展示语义和控制资格语义没有统一状态输出，也没有为“最近有效 track 的受限重获取”建立独立、可校准的业务契约。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.hpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.hpp`
- `dual_machine_runtime/shared/include/vfdual/model_contract.hpp（条件共享，需人工冲突检查）`
- `对应 replay/单元测试`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 构造置信度处于 postprocess 与 new-track 阈值之间的检测，证明检测存在但 tracker 无 track。
2. 先用高置信度建立 track，再触发 reset，随后持续提供中间置信度检测，证明当前无法重获取。
3. 记录 current detection count、max confidence、new-track threshold；当前状态没有明确 blocker reason。
4. 对每个 model contract 做边界测试：阈值前后 0.001。

#### 精确修复步骤

1. 首先增加明确判定结果：NO_DETECTION、DETECTED_NOT_TRACK_ELIGIBLE、TRACK_ELIGIBLE、TRACK_ACTIVE；上层不得把它们都显示成“已检测”。
2. 诊断快照必须包含最大置信度、冷启动阈值、持续跟踪阈值、候选 class、空间门限和 reset 原因。
3. 不要直接降低 new-track 阈值。先用用户现场录制帧和每个模型的离线 replay 证明置信度分布。
4. 如确有必要，在 model contract 中增加独立 `reacquire_track_confidence_threshold`：只适用于最近有效 track、限定时间窗、同 class、与预测位置足够接近、帧为新鲜内容。
5. 该重获取阈值必须位于 postprocess 与 cold-start new-track 阈值之间，并由模型回放验证；默认值先等于现有 new-track 阈值，避免无证据改变行为。
6. 重获取窗口到期后回到冷启动规则；不能让一个旧 track 永久降低准入条件。
7. 对响应确认失败触发的 reset，记录具体 reset reason，避免把流问题误归因于置信度。

#### 禁止的伪修复

- 把所有 model 的 new-track 阈值统一降到后处理阈值。
- 只要屏幕上有框就允许控制。
- 忽略 class、空间连续性、帧新鲜度和重获取时间窗。
- 用真实现场以外的单个截图拍脑袋调阈值。
- 修改模型或扩大目标选择范围来掩盖状态机问题。

#### GREEN 与业务验收

- 任何“有检测但无 track”状态都能从 blocker 快照直接识别。
- 高于冷启动阈值的目标能在规定的新鲜帧数内建立 track。
- 中间置信度目标只在满足受限重获取契约时恢复，冷启动仍保持原安全阈值。
- 低置信度、错误 class、远离预测位置、旧帧或超出时间窗均不能借重获取路径进入控制。
- 每个模型都有固定 replay 数据集和边界测试，不以人工目测作为唯一验收。

**依赖**：CTRL-006  
**人工门禁**：必须  
**冲突策略**：model_contract.hpp 是条件共享文件。若上一份报告修复分支已改该文件，先人工合并字段和默认值；不得重排整个合同或覆盖安全/版本字段。  
**回滚**：关闭受限重获取开关并恢复原 new-track 行为；保留 DETECTED_NOT_TRACK_ELIGIBLE 诊断。

### CTRL-005｜P1｜响应上界向下取整产生“非死区但永久零输出”区间，最小一步救援到达得太晚

**证据状态**：CONFIRMED_SOURCE；数学路径闭合；现场区间取决于运行参数与校准值  
**症状匹配**：MEDIUM_HIGH  
**摘要**：MotionPlanner 先用 floor 计算允许响应 budget，再把 PID 输出夹到该 budget。当误差已经大于 deadzone、但不足以换算成 1 个安全计数时，budget 为 0，desired 被清零；后面的最小 1 计数 settle rescue 因 desired 已为 0 而无法触发。系统可长期处于“未到死区、也绝不移动”。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.hpp`
- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlannerTests.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp`

**关键符号/路径**

- `response budget floor calculation`
- `PID output clamp by response budget`
- `residual update/reset`
- `one-count settle rescue`

**源码事实**

- 允许 budget 由 `floor(abs(predicted_error) * response_fraction / response_upper)` 形成。
- budget 为 0 时，期望输出被夹为 0，残差无法稳定积累成安全的一步。
- 后置的一计数救援依赖非零 desired，因此不能修复前面已经归零的情况。
- 按示例默认值 response_upper=1.0、response_fraction=0.95、deadzone=0.5，可形成约 0.5 < |error| < 1.0526px 的零输出带；实际范围必须读取运行配置。
- 现有测试验证了响应上界较大时应抑制不安全的一计数，说明不能简单把 floor 改成 ceil。

#### 触发序列

1. 初始误差较大，planner 正常发送若干移动。
2. 目标接近中心，误差进入 deadzone 之外但 response budget 仍为 0 的区间。
3. PID desired 被夹为 0，后置 rescue 无法触发。
4. 只要测量响应上界和目标误差保持在该区间，所有后续帧均输出 0。
5. 用户看到目标仍偏离但完全不再移动。

#### 根因

规划器把“设备分辨率下不可安全执行的一步”和“已进入 deadzone/已经完成”混为零输出，缺少显式的不可分辨终态、持续无进展检测和有证据的一计数策略。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.hpp`
- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlannerTests.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.hpp`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 按运行默认值扫描误差，从 deadzone-0.2 到 2px，打印 outcome 和 move；证明存在 deadzone 外连续零输出带。
2. 在该带内连续输入稳定目标 100 帧，证明当前既不移动也没有明确 settled/unresolvable outcome。
3. 用较大的 response_upper 重放，证明把 floor 改成 ceil 会产生已知不安全过冲。
4. 验证现有不安全一计数抑制测试必须继续通过。

#### 精确修复步骤

1. 让 planner 返回结构化 PlanOutcome：MOVE、DEADZONE_SETTLED、SUBCOUNT_UNRESOLVABLE、RESPONSE_MODEL_INVALID、NO_TARGET，而不是只返回 dx/dy。
2. 当误差大于 deadzone 但 budget 为 0 时，进入 SUBCOUNT_UNRESOLVABLE；不得把它计为 deadzone。
3. 由 response_upper、response_fraction 和设备最小计数推导 `device_resolution_settle_px`，并在状态中说明“已到设备可安全分辨率”还是“响应模型异常”。
4. 只有当最坏情况的一计数位移不会越过配置的安全界限，并且目标稳定、帧新鲜、方向连续时，才允许受约束的一计数动作。
5. 若不能证明一计数安全，则保持 0 输出并把业务状态标记为 SETTLED_WITHIN_DEVICE_RESOLUTION，而不是声称仍在主动跟踪移动。
6. 增加 no-progress 帧计数；若误差明显大于可分辨终态却长期 budget=0，则使响应模型失效并要求重新校准，不能无限静默。
7. 残差积累只允许在同一 track、同一方向、同一 session epoch 和新鲜帧上进行；丢轨、方向反转或恢复时清零。

#### 禁止的伪修复

- 直接把 floor 改为 ceil。
- 无条件发送最小 1 计数。
- 把 deadzone 扩大到覆盖问题而不向用户说明。
- 删除 response_upper 安全约束。
- 跨 track、跨 session 或重复帧累积残差。

#### GREEN 与业务验收

- deadzone 外 budget=0 时必有明确 SUBCOUNT_UNRESOLVABLE 或设备分辨率终态。
- 所有现有过冲保护测试继续通过。
- 可证明安全的一计数路径在边界上不振荡、不越过安全限制。
- 不可证明安全时保持 fail-closed，但用户和日志能知道不是传输故障。
- 参数扫描不存在“状态显示 active、连续 100 帧零输出且无 blocker”的区间。

**依赖**：CTRL-006  
**人工门禁**：必须  
**冲突策略**：本任务只改变规划结果语义和有界收敛，不调整目标选择、模型输出或传输协议。  
**回滚**：关闭受约束一计数功能，恢复原零输出；保留 PlanOutcome 和 no-progress 诊断。

### CTRL-006｜P2｜控制抑制原因被混入 deadzone 等计数，缺少唯一“当前阻断原因”状态

**证据状态**：CONFIRMED_SOURCE；源码可观测性缺口已确认  
**症状匹配**：DIAGNOSTIC_BLOCKER  
**摘要**：当前多个无移动分支最终只表现为 has_move=false，并被部分计入 deadzone_suppressed；没有一个跨接收、跟踪、规划、ticket、传输的当前 blocker 枚举及状态年龄。因此现场只能看到“检测还在、移动没了”，无法区分等待 IDR、等待 ACK 后新帧、无 track、预算为 0 或传输断开。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/cpp/MakcuMoveBridge.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp`
- `android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.cpp`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputCoordinator.java`

**关键符号/路径**

- `g_deadzone_suppressed`
- `control report/snapshot`
- `runtime health/reconcile status`

**源码事实**

- 无 move 的多个原因会汇入相同计数或仅留下分散统计。
- 没有单一 current_blocker、since_monotonic_us、session_epoch 和 last_transition_reason。
- 接收新鲜度、track 资格、planner outcome、ticket 状态、transport 状态无法在同一时间线关联。
- 现有计数无法直接证明系统是安全抑制、等待恢复还是逻辑卡死。

#### 触发序列

1. 任一层进入抑制。
2. 上层仍显示检测或连接状态。
3. 统计只增加 deadzone/ignored/failed 等宽泛计数。
4. 运维和低能力 LLM错误修改阈值、熔断或 gate，形成伪修复。

#### 根因

控制链缺少跨层、低基数、单调时钟一致的状态观测契约；统计是事后计数，不是可解释的当前状态机。

#### 允许修改路径

- `上述控制文件中的诊断结构和只读快照`
- `新建 `ControlBlockerReason` / `ControlDiagnosticsSnapshot` 等低耦合文件`
- `仅为展示诊断而对 MobileRuntimeService/MobileControlRuntime 做窄范围接线`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 分别触发 WAITING_FRESH_IDR、WAITING_POST_ACK_VISIBILITY、无 track、subcount、ticket pending、transport not ready，证明当前快照不能唯一识别。
2. 证明当前 deadzone_suppressed 在非 deadzone 分支也可能增长或无法排除。
3. 构造 blocker 切换，当前没有 since/age 和 transition sequence。

#### 精确修复步骤

1. 定义唯一低基数枚举：RUNNABLE、NO_DETECTION、DETECTED_NOT_TRACK_ELIGIBLE、WAITING_FRESH_IDR、WAITING_POST_ACK_VISIBILITY、WAITING_RESPONSE_CONFIRMATION、RESPONSE_GUARD_NO_PROGRESS、TICKET_PENDING、TICKET_DEADLINE_EXPIRED、TRANSPORT_NOT_READY、CIRCUIT_OPEN、USER_DISABLED、AUTH_DISABLED、RECOVERY_EXHAUSTED。
2. 建立单一快照：blocker、since_monotonic_us、transition_id、session_epoch、frame_sequence、content_updated、target_count、max_confidence、track_state、planner_outcome、ticket_id、transport_state。
3. 每次状态转换只在一个所有者处写入，其他层提供事实字段；禁止多层互相覆盖 blocker。
4. 保留旧指标兼容性，但修正 deadzone 计数只表示真正 deadzone；为旧名称提供迁移说明。
5. 日志使用 JSON Lines 或结构化事件，不打印票据、密钥、图像内容或高基数目标坐标。
6. MobileRuntimeService 只读取并展示/导出快照，不在 UI 线程推导业务状态。
7. 加入不变量：有检测且无 move 时 blocker 不能为 RUNNABLE；blocker 变化必须增加 transition_id。

#### 禁止的伪修复

- 只增加更多无关联日志字符串。
- 把目标坐标、原始图像或 secret 写入日志。
- 让 Java、C++ 各自维护互相冲突的 current blocker。
- 删除旧指标而不给迁移期。
- 用 UI 文案替代底层状态事实。

#### GREEN 与业务验收

- 故障发生后单条快照即可确定阻断层和持续时间。
- 所有无 move 分支都有非 RUNNABLE blocker。
- blocker 枚举低基数、线程安全、不会因每帧坐标造成指标爆炸。
- 旧 dashboard 在迁移期仍可工作，新 dashboard 能按 blocker 分解。
- 现场日志可以直接驱动本报告的动态决策树。

**依赖**：无  
**人工门禁**：一般代码审查即可  
**冲突策略**：这是其他 CTRL 任务的先决诊断层。只增加状态事实，不提前实现各任务的行为修复。MobileRuntimeService 和 MobileControlRuntime 属条件共享文件，发生同 hunk 冲突必须人工合并。  
**回滚**：关闭新快照导出但保留内部枚举；不得通过回滚重新混淆 deadzone 与其他原因。

### CTRL-007｜P2｜Bluetooth HID 异步恢复未主动驱动控制协调器，恢复依赖周期性 reconcile

**证据状态**：CONDITIONAL_CONFIRMED；状态通知断层已确认；永久停机与否取决于服务调度  
**症状匹配**：MEDIUM  
**摘要**：HID 注册和主机连接由 Android 异步回调更新适配器内部状态，但没有直接通知控制协调器。一次报告失败即可使传输核心进入 fail-closed/circuit 状态；物理连接恢复后，重新启用依赖MobileRuntimeService 后续周期性健康/reconcile，而不是事件驱动。

#### 证据定位

**文件**

- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/AndroidBluetoothHidDeviceAdapter.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/BluetoothHidMouseTransportCore.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/BluetoothHidOutputFailClosedPolicy.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputCoordinator.java`

**关键符号/路径**

- `BluetoothHidDevice.Callback registration/connection callbacks`
- `BluetoothHidMouseTransportCore failure/circuit state`
- `MobileRuntimeService periodic authorization/health reconcile`
- `ControlOutputCoordinator.reconcile`

**源码事实**

- Android 异步 callback 会更新 adapter 的注册/连接字段。
- 没有看到 callback 将“恢复可用”事件直接投递给 ControlOutputCoordinator。
- 传输核心在报告失败后进入 fail-closed 状态。
- 服务中存在周期性健康/reconcile 路径，因此该问题不应被夸大为必然永久停机，但恢复延迟和依赖关系真实存在。

#### 触发序列

1. Bluetooth HID 已工作并发送过移动。
2. 短暂断连或一次 sendReport 失败，core fail-closed。
3. Android 回调随后显示 HID/host 已恢复。
4. 协调器未立即收到事件，必须等待下一次服务 reconcile。
5. 服务繁忙、生命周期暂停或周期较长时，用户看到长时间不再移动。

#### 根因

底层连接状态是事件驱动，上层控制授权/传输状态是轮询驱动，二者缺少线程安全、幂等的桥接。

#### 允许修改路径

- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/AndroidBluetoothHidDeviceAdapter.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/BluetoothHidMouseTransportCore.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/MobileRuntimeService.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ControlOutputCoordinator.java`
- `对应 Java 单元/集成测试`

受保护路径沿用第 2.2 节。若 active repair head 已修改上述允许文件，仍需按 hunk 检查，不能因为“在允许列表里”就覆盖旧补丁。

#### RED：修复前必须复现

1. 模拟 sendReport 失败后立即触发 registered/connected 回调，证明当前协调器不会立即 reconcile。
2. 暂停周期性 health task，证明恢复完全依赖轮询。
3. 回调风暴测试：多次 registered/connected 变化不能造成并发重连或重复 sink 安装。

#### 精确修复步骤

1. 为 adapter 定义只读 TransportStateListener；回调只发布状态快照，不在 Binder/系统回调线程直接重连或调用 native。
2. MobileRuntimeService 在自己的串行 executor 上接收事件并调用幂等 `requestControlOutputReconcile(reason, generation)`。
3. 用 generation/session epoch 丢弃旧回调，避免断开事件晚到覆盖新连接。
4. 保留现有周期性 reconcile 作为后备，不要删除健康巡检。
5. 协调器恢复成功后必须重新验证 adapter registered、host connected、授权、用户开关和 circuit 状态，不能只因一个回调就放行。
6. 是否调整“一次失败即熔断”必须单独用故障率数据决定；本任务默认不降低 fail-closed 敏感度。
7. 导出 callback_to_reconcile_us、reconcile_to_ready_us 和恢复结果。

#### 禁止的伪修复

- 在 Bluetooth 系统回调线程直接阻塞重连。
- 收到 connected 回调就绕过授权、用户开关或 circuit 检查。
- 删除周期性健康检查。
- 简单把失败阈值从 1 改大来掩盖状态通知问题。
- 忽略 generation，允许旧回调改变新会话。

#### GREEN 与业务验收

- 连接恢复事件能在受控 executor 上立即触发一次幂等 reconcile。
- 回调乱序和风暴不会出现重复 sink、并发重连或错误 ready。
- 周期性健康检查仍能在事件丢失时恢复。
- 未授权、用户关闭或 circuit 未安全复位时不会因回调自动启用输出。
- 故障注入能测量并约束 callback 到 ready 的恢复延迟。

**依赖**：CTRL-006  
**人工门禁**：一般代码审查即可  
**冲突策略**：MobileRuntimeService 是条件共享文件；仅增加事件接线和诊断，不改授权、支付、票据或正式安全逻辑。  
**回滚**：关闭事件驱动 listener，保留周期性 reconcile；保留恢复延迟指标用于后续分析。

## 8. 已排除的误判：禁止按这些方向乱修

### 投递熔断器打开后绝不会重连

- **结论**：排除为通用根因
- **理由**：底层 `isReady()` 将 circuit 状态纳入就绪判定，协调器在非 ready 时会进入重连路径，成功重连会复位 circuit。不能通过删除熔断器解决。

### latest-only pending slot 必然覆盖并丢失原生 ticket

- **结论**：正常路径下不成立
- **理由**：原生 move commit gate 实行单 ticket 在途，通常在完成前不会再提交第二个 ticket。保留并发回归测试即可，不能把邮箱改成无界队列。

### ACK 时间和帧 observed_at_us 属于不同 clock domain

- **结论**：已排除
- **理由**：审查到的 ACK 和接收帧观测时间均来自单调 steady clock 语义；问题是等待无界，不是已证明的时钟域混用。

### native fail-close 回调同步重入配置函数导致 g_publish_mutex 自锁

- **结论**：当前调用链未闭合
- **理由**：Java sink 的 failClosedDelivery 只关闭 delivery gate 并清 pending slot，未在该回调中同步调用 native profile 配置。不得据此进行锁重构。

## 9. 现场动态验证矩阵

静态源码可以证明状态机缺口，但不能仅凭静态审查断言用户设备当前一定命中哪一个分支。  
先完成 `CTRL-006` 的统一快照，再按下列验证采集。所有时间必须使用同一单调时钟；禁止用 wall clock 拼接因果链。

### VERIFY-CTRL-01｜确认是否卡在重复帧/等待新鲜 IDR

**关联任务**：CTRL-001, CTRL-002

**采集字段**

- `session_epoch`
- `frame_sequence`
- `frame_type(IDR/P/other)`
- `VFRR/repeat flag`
- `content_updated`
- `repeat_resync_state`
- `repeat_resync_age_us`
- `visibility_gate_state`
- `visibility_gate_age_us`

**步骤**

1. 从启动前清空诊断日志，完整记录“第一次移动前 2 秒至停止后 10 秒”。
2. 停止后不立即重启，观察是否持续 WAITING_FRESH_IDR 或 WAITING_POST_ACK_VISIBILITY。
3. 手动使用现有受支持方式重建视频会话/请求关键帧；若新鲜 IDR 后立即恢复，强支持 CTRL-001/002。

**判定**：若停止时 awaiting_fresh_idr/visibility armed 持续增长且无合格 IDR，为命中；若新鲜帧持续正常到达，则转查 VERIFY-CTRL-03/04/05。

### VERIFY-CTRL-02｜核对 post-ACK gate 三项解锁条件

**关联任务**：CTRL-002

**采集字段**

- `ticket_id`
- `source_sequence`
- `ack_monotonic_us`
- `current_sequence`
- `current_observed_at_us`
- `content_updated`
- `gate_decision`

**步骤**

1. 对每个成功 ACK 记录 gate arm 事件。
2. 对随后每个可见帧记录三项条件的逐项真假，不只记录总布尔结果。
3. 观察停止后究竟是内容未更新、序列未增长还是时间条件未满足。

**判定**：任一 gate armed 超过恢复 SLA 且无明确状态转换，即确认 CTRL-002 业务缺口。

### VERIFY-CTRL-03｜测量 ticket 总时序和晚 ACK

**关联任务**：CTRL-003

**采集字段**

- `ticket_created_us`
- `java_enqueue_us`
- `java_start_us`
- `write_start/end_us`
- `ack_wait_start/end_us`
- `native_expire_us`
- `completion_result`
- `late_ack_count`

**步骤**

1. 正常运行、CPU 压力、GC 压力和 USB 抖动四组各采集至少 1000 个 ticket。
2. 计算 queue、write、ACK 和 total 的 P50/P95/P99/P99.9。
3. 检查是否存在 Java ACK_OK 但 native 已 deadline expired 的同 ticket 事件。

**判定**：发现任何同 ticket 的双终态或 ACK_OK 晚于 native expire，即确认现场命中。

### VERIFY-CTRL-04｜确认检测置信度是否落在显示阈值与新 track 阈值之间

**关联任务**：CTRL-004

**采集字段**

- `model_id`
- `detection_count`
- `max_confidence`
- `postprocess_threshold`
- `new_track_threshold`
- `tracker_decision`
- `reset_reason`

**步骤**

1. 记录停止前后 5 秒的每个新鲜帧。
2. 按 model contract 对照最大置信度。
3. 重点观察 track reset 后是否长期为 DETECTED_NOT_TRACK_ELIGIBLE。

**判定**：若检测持续存在且置信度稳定处于两阈值之间、没有 active track，则命中。

### VERIFY-CTRL-05｜扫描响应 guard 的零输出区间

**关联任务**：CTRL-005

**采集字段**

- `predicted_error_x/y`
- `deadzone`
- `response_upper`
- `response_fraction`
- `computed_budget`
- `desired_move`
- `planner_outcome`

**步骤**

1. 使用现场校准参数离线扫描每轴误差。
2. 对停止现场记录连续 100 帧，判断误差是否大于 deadzone 但 budget=0。
3. 验证一计数的最坏位移，禁止仅凭视觉决定是否放行。

**判定**：存在 deadzone 外连续零 budget 且无明确终态，确认 CTRL-005。

### VERIFY-CTRL-06｜Bluetooth 断连/恢复事件到 ready 的延迟

**关联任务**：CTRL-007

**采集字段**

- `adapter_callback_us`
- `adapter_registered`
- `host_connected`
- `core_circuit_state`
- `reconcile_requested_us`
- `reconcile_completed_us`
- `output_ready`

**步骤**

1. 注入一次 sendReport 失败、短断连和回调乱序。
2. 分别在周期任务正常与暂停测试环境下测量恢复。
3. 确认没有授权绕过、重复 sink 或并发 reconnect。

**判定**：物理状态已恢复但协调器只有周期轮询后才变化，确认事件通知缺口。

## 10. 统一诊断事件格式

建议每次状态转换写一条低基数 JSON Lines 事件，而不是每帧打印大量字符串：

```json
{
  "ts_mono_us": 0,
  "transition_id": 0,
  "session_epoch": 0,
  "frame_sequence": 0,
  "frame_kind": "IDR|P|REPEAT|UNKNOWN",
  "content_updated": false,
  "repeat_resync_state": "NORMAL|WAITING_FRESH_IDR|RECOVERY_REQUESTED|RECOVERY_EXHAUSTED",
  "visibility_state": "DISARMED|WAITING_POST_ACK_VISIBILITY|RECOVERY_REQUIRED",
  "detection_count": 0,
  "max_confidence": 0.0,
  "track_state": "NONE|CANDIDATE|ACTIVE",
  "planner_outcome": "MOVE|DEADZONE_SETTLED|SUBCOUNT_UNRESOLVABLE|NO_TARGET",
  "ticket_id": 0,
  "ticket_state": "NONE|PENDING|ACK_OK|DEADLINE_EXPIRED|STALE_ACK",
  "transport_state": "READY|NOT_READY|CIRCUIT_OPEN|RECONNECTING",
  "current_blocker": "WAITING_FRESH_IDR",
  "blocker_age_us": 0
}
```

约束：

- 不记录原始图像、完整坐标轨迹、票据内容、密钥、账号或设备敏感标识。
- 每次 blocker 转换记录一次；稳定状态按低频采样，避免每帧日志洪泛。
- `transition_id` 单调递增；跨线程事件使用 `session_epoch + frame_sequence + ticket_id` 关联。
- 诊断不得改变控制时序，不得在实时线程同步写磁盘。

## 11. 停止后五分钟内的判定树

1. 查看 `current_blocker`。
2. 若为 `WAITING_FRESH_IDR`：
   - 检查 repeat/VFRR 和 fresh non-VFRR IDR；
   - 执行 VERIFY-CTRL-01；
   - 修复顺序 CTRL-001 → CTRL-002。
3. 若为 `WAITING_POST_ACK_VISIBILITY`：
   - 逐项检查 content_updated、sequence、observed_at；
   - 执行 VERIFY-CTRL-02。
4. 若为 `TICKET_DEADLINE_EXPIRED`、`ACK_TIMEOUT` 或 `STALE_ACK`：
   - 执行 VERIFY-CTRL-03；
   - 不要先调大所有超时。
5. 若为 `DETECTED_NOT_TRACK_ELIGIBLE`：
   - 执行 VERIFY-CTRL-04；
   - 不要直接降低阈值。
6. 若为 `RESPONSE_GUARD_NO_PROGRESS` / `SUBCOUNT_UNRESOLVABLE`：
   - 执行 VERIFY-CTRL-05；
   - 不要把 floor 改 ceil。
7. 若为 `TRANSPORT_NOT_READY` / `CIRCUIT_OPEN` 且使用 Bluetooth：
   - 执行 VERIFY-CTRL-06。
8. 若停止时 blocker 仍为 `RUNNABLE`：
   - `CTRL-006` 尚未覆盖全部分支，先补诊断，不得猜修。

## 12. 推荐的 RED/GREEN 测试组织

为了减少与旧修复的冲突，优先新增测试文件或只追加独立测试用例，不重排现有文件：

- `ReceiverRepeatResyncPolicyTests`：fake clock、repeat、VFRR IDR、fresh IDR、恢复预算；
- `MakcuOutputGateTests`：ACK 边界、旧序列、旧时间、重复内容、timeout→recovery；
- `MakcuMoveDeadlineTests`：跨 JNI 的统一 deadline、late ACK、exact-once；
- `MobileTargetTrackerReacquireTests`：冷启动、最近 track、阈值边界、空间/时间门；
- `MobileMotionPlannerTests`：deadzone 外零 budget 扫描、过冲不变量、no-progress；
- `BluetoothHidRecoveryTests`：回调乱序、事件驱动 reconcile、轮询后备。

测试命令不得凭空编造 target 名。先从现有 Gradle/CMake 配置发现真实 target：

```bash
grep -R "MakcuOutputGateTests\|MobileMotionPlannerTests\|add_test\|testDebugUnitTest"   android_inference_benchmark -n
./gradlew tasks --all
cmake --build <existing-build-dir> --target help
```

然后把实际命令、退出码和关键输出写入任务报告。无法运行真机测试时标记 `NOT RUN`，不能用 mock 绿灯冒充物理 USB/Bluetooth 验收。

## 13. 业务级验收场景

### 场景 A：正常连续新鲜视频

- 持续新鲜帧、稳定目标、正常 USB ACK；
- 运行至少 30 分钟；
- 不出现无限 WAITING、双终态、错 ticket 或无解释零输出。

### 场景 B：重复帧与关键帧恢复

- 注入 repeat/VFRR；
- 重复内容绝不能驱动移动；
- 达到期限后有且仅有一次受控恢复；
- 新鲜非 VFRR IDR 到达后恢复。

### 场景 C：永远没有合格 IDR

- 系统必须进入 RECOVERY_EXHAUSTED；
- 输出保持关闭；
- UI/日志明确说明视频新鲜度恢复失败；
- 不得无限显示“运行正常”。

### 场景 D：ACK 边界与系统抖动

- 注入 executor 排队、GC、USB 写入和 ACK 延迟；
- 每个 ticket 恰好一个终态；
- 晚 ACK 不解锁旧/新 ticket；
- 不靠无限超时通过。

### 场景 E：检测与 track 阈值边界

- 对每个 model contract 回放冷启动、持续 track、reset 后重获取；
- 显示检测与控制资格状态一致可解释；
- 低置信度不越权进入控制。

### 场景 F：小误差收敛

- 扫描 deadzone 周围和设备最小计数分辨率；
- 不出现 active 状态下永久零输出；
- 不安全的一计数仍被抑制。

### 场景 G：Bluetooth 短断连

- 断开、恢复、回调乱序和重复回调；
- 事件驱动恢复不绕过授权；
- 轮询后备仍有效；
- 无并发 reconnect 或重复 sink。

## 14. Go / No-Go 清单

只有全部满足才可认为本专项修复闭环：

- [ ] 停止现场能输出唯一 current blocker 及持续时间。
- [ ] repeat/VFRR 期间旧内容绝不驱动移动。
- [ ] WAITING_FRESH_IDR 有有界恢复、重试预算和 exhausted 状态。
- [ ] post-ACK visibility gate 超时不自动放行，而是进入共享恢复。
- [ ] ticket 跨 native/Java 使用统一单调绝对 deadline。
- [ ] 每个 ticket 在任意并发顺序下恰好一个终态。
- [ ] “检测到”与“track 可用”被明确区分。
- [ ] 阈值变化经过逐模型 replay 和人工审查。
- [ ] deadzone 外零 budget 有明确终态，不再伪装为 active。
- [ ] 既有过冲、重复帧、exact-ticket 和 fail-closed 测试全部保留。
- [ ] Bluetooth 恢复事件不绕过授权，周期巡检仍为后备。
- [ ] 新补丁基于包含旧修复的 active head，未覆盖上一份报告工作。
- [ ] `server/**`、支付、授权、密钥和正式安全门禁无无关 diff。
- [ ] 真机 USB、Bluetooth、视频重同步和至少 30 分钟连续运行通过。
- [ ] 未运行的物理测试被明确标记，而不是写成“已验证”。

## 15. 最终判断

本专项没有发现一个可以安全地用“改一行阈值”解决的问题。最可能的根因是**两个正确的 fail-closed 机制叠加后缺少 liveness**：

- Receiver 等不到符合资格的新鲜 IDR；
- ACK 后可见性门等不到符合资格的新内容。

这会精确产生“第一下能动，之后再也不动”的现象。正确修复是：

1. 先建立统一 blocker 和时序证据；
2. 保留重复帧、IDR、新鲜度和 ACK 屏障；
3. 给等待状态增加有界、幂等、共享的恢复生命周期；
4. 再根据日志处理 deadline、track 资格和 subcount 收敛；
5. 所有补丁叠加在旧报告修复后的 active head 上，而不是覆盖旧修复。
