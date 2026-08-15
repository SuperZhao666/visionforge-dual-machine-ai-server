# CS2 手机端全链路集成与验收契约

本文档定义 `counter-strike-2-vombit-416-v8s` 在 VF Mobile 中何时可以称为“已集成”和“已通过真机全链路”。模型文件存在、UI 按钮存在、通用 QNN 指标非零，都不能单独形成通过结论。

## 1. 固定模型契约

| 字段 | 固定值 |
|---|---|
| 模型 token | `counter-strike-2-vombit-416-v8s` |
| Android QNN 库 | `libcs2_vombit_416_v8s_w8a16.so` |
| 输入 | `1×3×416×416` |
| anchors | `3549` |
| 类别数 | `4` |
| class 0 | `ct_body` |
| class 1 | `ct_head` |
| class 2 | `t_body` |
| class 3 | `t_head` |
| 默认目标 | `t_head` |

CT 只能在 `0/1` 内进行身体与头部配对，T 只能在 `2/3` 内配对。禁止跨阵营头身配对。选择 `ct_head` 或 `t_head` 时，先出现同一人物身体框、随后出现配对头框，属于同一身份的目标升级：不得增加 `lock_id`，不得报告 `switched=true`，不得清空目标速度或重置移动规划器。

小头框短暂掉检但完全相同的 paired-body track 仍存在时，只允许在原锁定几何门通过后，使用前后 body 框的平移和缩放投影最后可信 head 框、目标点与安全锚点。投影期间 `AimSource` 必须保持 `head`，`lock_id` 不变，不得进入 `switch_pending` 或重置运动规划器；真实头框恢复时直接重新接管。恢复帧的“投影估计→真实观测”坐标差属于同一目标的测量校正，必须重基运动规划历史并保留既有目标速度，禁止除以单帧间隔制造虚假的反向速度或加速度；第二个连续真实头框再恢复正常速度估计。尺寸、中心距离、IoU/GIoU 或投影边界不可信时必须拒绝，并通过 `head_body_projection_continuations`、`head_body_projection_recoveries`、`maximum_head_body_projection_recovery_pixels`、`rejected_head_body_projection_geometry` 分别留痕。

物理 move 已提交但设备 ACK 或 ACK 后首个可见响应帧尚未到达时，不得丢弃中间 fresh content 的身份信息。`observe_tracking_only()` 必须只刷新完全相同锁身份的几何和速度，允许原 paired-head 的投影/恢复，但不得运行 motion planner、确认新 challenger 或发送第二条 move；`tracking_only_lock_updates` 必须可证明该刷新真实发生。累计目标运动即使超过发送前旧框的单帧几何门，也必须由逐帧连续身份自然延续，禁止在 ACK 完成后误入丢锁或 `switch_pending`。

CS2 的完整目标短暂掉检不得继续使用 `lost_frame_hold_count` 决定真实时长。运行时必须先应用用户当前 `switch_confirmation_ms`，再令 `lost_target_hold_duration_us` 使用同一单调时间窗口；默认标准配置因此为 `25,000 us`。高低 fresh FPS 下，同样的缺席时长必须在同一时间边界保留或释放锁，处理的中间帧数可以不同但不得改变结果。`mobile_control_health` 必须同时暴露 `switch_confirm_us` 与 `lost_hold_us` 供实体日志核对。

运行中热更新 gain、deadzone、最大轴增量、`switch_confirmation_ms` 或个人轨迹参数时，配置代际必须与在途 move 隔离。协调层必须先同步关闭并排空 Java/USB/HID 交付门，再以 disabled 配置清理 native ticket/可见性状态，随后应用新配置并最后重开物理交付；native 配置过程还必须与完整 publish 事务共用同一线性化锁。禁止旧 move 的拒绝或迟到反馈重置、关闭已经生效的新配置。该事务只发生在用户控制面调参时，不得改变 fresh-frame 热路径吞吐。

设备 ACK 已完成、但可见画面响应在锁/轨迹时限内始终无法确认时，旧屏幕空间锁必须失效。该超时帧中的替代目标不得立即再次输出 move，而应进入已有的 `switch_confirmation_duration_us` 重捕获确认；相同身份达到观测帧数与单调时间条件后才允许恢复输出。该确认只消费持续到达的 fresh observation，不得引入 FPS 上限、固定周期或热路径等待。实体日志通过 `ego_response_timeouts`、`reacquisition_pending` 与 `reacquisition_confirmed` 关联该恢复过程。

可见响应的共同位移只能由独立人物证明。选择 paired-head 时，同一个人的 head 与 body 不得同时计为两个 support；核心应在当前可见的 head/body 类别中选择数量更多的一类作为见证集合，同一物理人物最多贡献一次。单人物即使 head/body 同向移动也只能确认 ACK 可见，不能把人物自身位移放大为相机位移；`ego_response_support` 用于核对最终最大独立支持数。

Java 模型目录、共享 C++ 契约、QNN 加载器、后处理器和控制核心必须使用同一 token、库名、类别数与目标映射；不允许分别维护互相漂移的隐藏副本。

## 2. APK 静态发布门禁

发布 APK 必须同时满足：

1. ZIP 中存在 CS2 QNN 模型库、`libvisionforge_qnn_htp.so` 和完整 QNN HTP stub/skeleton 闭包。
2. 最终 `classes*.dex` 仍包含模型 token、QNN 库名、`vf.game_model.` 入口和四个目标 token。
3. 最终 JNI 桥接库仍包含模型 token、QNN 库名和四类目标契约。
4. `resources.arsc` 中存在 `game_counter_strike_2`，且 `aapt dump --values resources` 显示中文名称“反恐精英2”。
5. APK 为非 debuggable 的 Release 变体，并通过现有签名与四模型 QNN 闭包检查。

执行：

```powershell
python tools\verify_android_release_apk_artifact.py `
  --apk <VFMobile-release.apk> `
  --output <apk-verification.json> `
  --allow-development-android-signing
```

`--allow-development-android-signing` 只适用于实体机测试包。正式商业发布不得使用该选项。

## 3. 真机动态通过条件

必须从归档的 VF Mobile 日志中找到一条模型归属明确的 `mobile_pipeline_metrics`，或同字段的外部运行时快照，并且在同一条指标中同时满足：

```text
model=counter-strike-2-vombit-416-v8s
aim_target=ct_body|ct_head|t_body|t_head
native_applied=true
rendered_frames > 0
qnn_executions > 0
qnn_failures = 0
qnn_fps > 0
preprocess_p50 >= 0
qnn_p50 >= 0
inference_total_p50 >= 0
decode_queue_p50 >= 0
```

`mobile-runtime-latest.txt` 必须代表当前 APP 生命周期，不能沿用上一模型或上一接流会话：服务首次进入 `ready/idle`、模型或目标改变、`running→ready` 停流时都必须覆盖旧快照；相同空闲状态只允许按五分钟有界心跳重写。该策略运行在五秒健康线程，不得进入捕获、解码、QNN 或控制热路径。

正式证据还必须保存：

- 指标详情 SHA256；
- 来源手机日志 SHA256；
- 来源哈希属于本次正式证据归档的手机日志集合；
- 安装 APK、Host EXE、手机 serial 和版本身份；
- 停流后的数据面关闭、正式停费完成和最终安全待命证据。

以下情况一律不通过：

- 只有 `qnn_executions > 0`，没有 `model`；
- 指标属于 Valorant、OW2 或三角洲；
- UI 显示 CS2，但实际 QNN 指标属于其他模型；
- `native_applied=false`；
- `qnn_failures > 0`；
- 指标来自 Host 日志而不是归档手机日志；
- 使用旧 APK、不同 Host 哈希或不同手机会话的数据拼接证据。

## 4. 实体机操作顺序

1. 只使用 `adb install -r` 覆盖安装；禁止卸载，覆盖前后记录 `firstInstallTime`、`ceDataInode`、`deDataInode` 和已安装 `base.apk` SHA256。
2. 确认卡密、剩余时间和用户配置仍存在。
3. 在 VF Mobile 控制页精确选择“反恐精英2”，再选择目标阵营和身体/头部。
4. 日志必须出现 `mobile_game_model_applied`，并包含正确 token 与 `native_applied=true`。
5. 只启动一个标准 `VFHost.exe`，通过正常 GUI 点击“开始传输”。
6. 保持真实 Host→手机视频流，采集模型归属指标及 `qnn_fps`、预处理/QNN/总推理/解码队列延迟、目标切换、移动规划和方向翻转数据。
7. 只通过 Host GUI 停止和关闭，禁止强杀。
8. 验证 `mobile_pipeline_data_plane_closed`、`dual_machine_formal_stop_finished` 和 `billing_started=false`，然后归档手机与 Host 日志。

CS2 动态链路不要求游戏窗口在线；桌面真实帧足以证明指定 QNN 图实际执行。但没有 CS2 游戏画面时，只能证明运行链路与模型身份，不能外推检测准确率、目标切换质量或实战移动手感。

## 5. 性能不可变约束

- 禁止 FPS 上限、固定发送帧率、热路径 `sleep`、软件节流或人为限速。
- 性能指标只描述实际吞吐，不作为发送频率控制输入。
- 为消除抖动而进行的目标身份、轨迹连续性或回压修复，不得通过降低全局帧率实现。
- paired-head 掉检连续性只由同一 body track、几何契约与单调时间控制，不得以帧数抽样、降 FPS 或跳帧伪造稳定。
- `qnn_fps` 只统计有新视觉内容的实际 QNN 执行，不等同于线速接收帧率；完全相同的重复画面可以继续接收、解码和计数，但不得为了抬高表面数值重复推理同一像素或重复产生控制决策。验收时应同时报告 `wire_reassembly_fps`、`fresh_content_fps`、`repeated_content_fps` 与 `qnn_fps`，区分内容去重和性能限速。

## 6. 分发边界

当前 CS2 工件清单声明：

- `integration_eligible=true`；
- `source_metadata_declares=AGPL-3.0`；
- `commercial_distribution_review_required=true`；
- `commercial_release_eligible=false`。

因此当前工件只允许进入开发签名的实体机测试包。构建检测到生产签名时，除非经过审查的清单明确更新为 `commercial_release_eligible=true`，否则必须 fail-fast。加密、混淆或二进制加固不能替代模型许可证审查。
