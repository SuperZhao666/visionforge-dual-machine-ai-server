# VisionForge Mobile 正式版 UI 架构

## 1. 决策结论

正式版继续使用现有 **Java Android UI + C++20 NDK 热路径**：Java 只负责生命周期、状态呈现和用户意图；UDP、MediaCodec、QNN HTP、原生后处理及控制桥继续留在 C++/JNI 边界内。此次重构不引入 WebView、Python 运行时或第二套业务状态。

当前视觉基线以三入口生产源码、响应式布局契约和最终正式 APK
实体机截图为准。旧版四入口、独立链路页和手动启停按钮参考图已经退役，
不得继续作为实现或验收依据。

## 2. 为什么没有把现有项目整体改成 Compose

Android 官方当前推荐 UI state、state holder 和单向数据流；`Now in Android` 也以不可变 UI state 和事件回传组织界面。正式版采用这些架构原则，但不在已经打通 QNN/USB 的 Java + NDK 工程内同时引入 Kotlin/Compose 迁移，以免把 UI 重写、构建依赖迁移和实体链路验收绑成一次高风险变更。

参考：

- Android UI layer: https://developer.android.com/topic/architecture/ui-layer
- Android state holders: https://developer.android.com/topic/architecture/ui-layer/stateholders
- Now in Android architecture: https://github.com/android/nowinandroid/blob/main/docs/ArchitectureLearningJourney.md

## 3. 分层与依赖方向

```text
MainActivity（组合根 / 生命周期）
        │  runtime observations + user events
        ▼
MobileUiStateMapper（纯 Java、不可变输出）
        │
        ▼
MobileAppShell（顶栏、页面容器、底部导航）
        │
        ├── AuthorizationScreen
        ├── InferenceScreen
        │      └── LinkStatusSection
        └── ControlScreen
             │
             └── MobileAppActions（事件仅向上回传）
```

规则：

1. Screen 不解析 JNI/原生日志；唯一解析入口仍是 `MobileRuntimeSnapshot`。
2. Screen 不直接持有 QNN、MediaCodec 或 USB 控制器。
3. `MobileUiState` 是单次刷新时刻的不可变快照；页面只读。
4. APP 不暴露推理启停事件；`MobileRuntimeService` 常驻待命，在已验证 Host 真实视频出现后自动启动正式数据面，在断流或租约失效后自动关闭并重新待命。参数修改通过 `MobileAppActions` 回到 `MainActivity` 并热应用。
5. `ControlOutputCoordinator` 和输出设备控制器继续拥有控制安全门；移除控制页提示卡片不会移除或放宽运行时门控，按钮或 Activity 可见性不构成安全边界。

## 4. 页面职责

| 页面 | 单一职责 | 不负责 |
|---|---|---|
| 卡密 | 卡密激活、授权状态与正式使用计时说明 | 用户名密码登录或绕过服务端授权 |
| 推理 | 主机自动发现与连接、四阶段链路健康、接收/解码/推理 FPS、手机/AI 耗时、失败数与延迟趋势 | 手动启停、重复展示同一静态指标或把理论 FPS 冒充端到端 FPS |
| 控制 | 输出路线、模型、瞄准位置、触发方式和参数滑杆 | 手动绕过健康门或生成协议外命令 |

## 5. 设计系统与资产

视觉 token、卡片、按钮、文字、间距和状态色集中在 `VisionForgeTheme`。导航和操作图标来自 Google 官方 Material Icons，按 Apache-2.0 使用，字体及许可证一同打包；页面不使用 emoji、字符画或临时 SVG 代替正式图标。共享顶栏保持 Logo、品牌名和设置按钮同一横行，品牌名强制单行并按可用宽度自动缩放；宽度不超过 360dp 时同步收紧左右留白和图标占位，保证系统大字体下仍优先完整显示品牌名，省略号只作为低于手机常规宽度的最终兜底。

## 6. 可验证门禁

1. `:app:verifyMobileRuntimeSnapshot`：原生报告解析、吞吐、控制门、检测策略及 UI state mapper 的无 Android 依赖契约。
2. `:app:assembleRelease`：Java、C++20、QNN 资产、Release lint、签名身份门禁和 APK 打包。
3. 实机：安装后验证三项底部导航、合并页只保留一个六项实时概览、控制页不再出现闭锁提示卡片、窄屏/大字体顶栏不换行、状态栏安全区、滑杆持久化以及任一故障立即关闭输出。
4. 物理 MAKCU 验收必须同时具备固件命令 ACK 与独立物理移动证据；仅有 Android `syncWrite` 完成不能宣称端到端通过。

## 6.1 Debug 专用 UI 预览入口（V17.8 UI 专项新增）

- 仅 debuggable 构建生效：`MainActivity` 仅在 `FLAG_DEBUGGABLE` 且 intent 带 `com.visionforge.mobile.extra.UI_PREVIEW_ONLY=true` 时进入预览分支；Release 构建忽略该 extra。
- 可选 `com.visionforge.mobile.extra.UI_PREVIEW_DESTINATION=authorization|inference|control` 指定首屏；旧版 `link` 值兼容映射到合并后的 `inference` 页面。
- 预览分支在任何 Service/QNN/MediaCodec/UDP/USB/WakeLock/权限弹窗/资产落盘之前返回；界面状态由纯 Java 的 `UiPreviewState.disconnected()` 经 `MobileUiStateMapper` 构造，全部运行时回调被 `uiPreviewOnly` 守卫短路。
- 契约由 `UiPreviewStateSelfTest` 守护（随 `verifyMobileRuntimeSnapshot` 执行）。

## 7. 可观测性契约

`MobileEventLogger` 只维护应用内部 `files/diagnostics/visionforge-mobile-runtime.jsonl` 这一个追加式 JSONL 文件，并同时写入 Logcat。它不按进程、日期或大小轮转；每次应用进程冷启动生成一个 `trace_id`，每条事件带 UTC 墙钟时间、Unix 毫秒、进程内单调耗时和递增 `sequence`，用于把进程、APP、前台服务、授权、导航、配置、串流、推理、检测跟踪、控制门和崩溃串成一条可还原链路。右上角按钮通过系统文件选择器导出锁定长度的一致快照，运行中的并发追加不会形成半行或混合导出。

控制配置日志记录实际应用后的模型、输出路线、增益、死区、单轴最大输出、触发方式、轨迹参数和输出门状态；模型切换在原正式租约内关闭数据面并热重载，成功后复用会话，失败时回滚，回滚失败才安全停止。控制门拒绝原因与原生配置拒绝分别记录，不以泛化的“操作失败”掩盖根因。诊断还必须区分 native 候选、Java 接受、固件匹配 ACK、ACK 超时/错票据和 ACK 后可见性抑制，不能把任意一层冒充物理执行。所有文件和 Logcat 输出统一经过中央脱敏器，不得包含卡密、token/JWT、Authorization/Cookie、票据、租约、签名、nonce、会话、设备指纹、敏感 ID、USB 序列号、密钥或模型内容。

## 8. 视觉验收边界

设计 QA 以生产源码的响应式布局契约和唯一签名正式 APK 的同视口
实体机截图为双证据。当前报告位于项目根目录 `design-qa.md`；如果手机
被 PIN 锁屏遮挡，报告必须保持阻断，不能用编译通过、预览图或锁屏
截图替代页面视觉验收。
