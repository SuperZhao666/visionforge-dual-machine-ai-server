# VisionForge DualMachineAI Server 完整修复交付报告

## 交付身份

- 修复分支：`fix/CTRL-complete-repair`
- 修复提交：`078ba3eae024df6c6666fcdefbe29f17d5749997`
- 保留的既有修复基线：`bde7d6b`
- 本次连续提交：

```text
078ba3e fix portable protocol contract compilation
c02d6ee fix bounded mobile control recovery and deadlines
248db99 preserve local partial release manifest repair
```

- 从既有基线至修复提交共修改或新增 `48` 个 Git 跟踪文件。
- 交付目录不包含 `.git` 工作区元数据，但 `REPAIR_DELIVERY/patches/` 保存了三个可审计、可应用的提交补丁。

## 已完成的控制链修复

1. **重复帧不再伪造恢复进度**：成功解码的 VFRR/repeat 只维持解码参考链，不再重置新鲜内容/IDR 恢复退避。
2. **ACK 后可见性门具备有界状态**：等待超时仍保持 fail-closed，不会用旧画面自动放行；合格新鲜帧可按原安全条件解除。
3. **统一控制阻断原因**：增加低基数 blocker、持续时间、transition id、frame/ticket/track/planner/transport 诊断。
4. **统一 native → JNI → Java → USB/Bluetooth 的绝对 deadline**：发送前、发送后及晚 ACK 均按同一 ticket 期限裁决，并保持 exact-once 完成。
5. **检测与控制资格分离**：区分无检测、检测到但不可建立控制 track、active track，避免“有框但没动”被误报为 deadzone。
6. **设备最小计数/响应 guard 状态分离**：无法安全执行一计数时提供明确 subcount/device-resolution blocker，不通过 `floor→ceil` 或无条件最小步破坏过冲保护。
7. **Bluetooth 异步恢复接线**：Android profile/host 状态变化会触发幂等上层 reconcile，同时保留授权、用户开关、circuit 和周期巡检门禁。
8. **跨平台基础编译修复**：补齐握手/配对结果类型前置声明，Linux CMake 全量协议测试可编译执行。
9. **保留用户已有 Release Manifest 部分修复**：没有覆盖本地既有工作，并纳入一致性校验、CI 和服务端身份读取。

## 已执行验证

| 验证项 | 结果 | 说明 |
|---|---|---|
| `git_worktree` | **PASS** | clean worktree; diff check passed |
| `git_fsck` | **PASS** | git object database valid |
| `cpp_control_tests` | **PASS** | 8 binaries compiled and passed |
| `makcu_bridge_syntax` | **PASS** | syntax valid; OpenJDK-only JNI conversion warnings retained in log |
| `java_runtime_snapshot` | **PASS** | 164 Java sources compiled; aggregate self-test passed |
| `cmake_portable` | **PASS** | full build passed; 6/6 ctests passed |
| `release_manifest_python` | **PASS** | manifest validator, 3 unit tests, compileall and direct identity passed |
| `gradle_wrapper` | **NOT_RUN** | Gradle 9.2.1 distribution not cached and network unavailable; manual equivalent passed |
| `server_targeted_pytest` | **NOT_RUN** | environment lacks locked bcrypt/slowapi dependencies; source compile and direct manifest tests passed |
| `android_apk_build` | **NOT_RUN** | Android SDK/NDK and physical QNN target unavailable in execution environment |
| `physical_usb_bluetooth` | **NOT_RUN** | requires user's Android device, MAKCU USB adapter/Bluetooth host and live video source |

## 包内容完整性

本包由以下来源合成：

- 修复提交的全部 Git 跟踪源码、配置、测试、文档和脚本；
- 用户原压缩包中的完整 QNN HTP skeleton/runtime 资产；
- 用户原压缩包中的完整 ARM64 JNI/QNN/model `.so`；
- 用户原压缩包中的离线 `security-defense/vendor` 归档和源码；
- 用户原压缩包中的 `xianyu-fulfillment/upstream` 源码与静态资源；
- 发布清单静态目录占位文件；
- 审查报告、机器任务账本、提交补丁和验证日志。

`FILE_COMPLETENESS_MANIFEST.json` 对交付目录中的每个非清单文件记录大小、SHA-256 和来源类别。打包前校验要求：

- 每个非字体 Git 跟踪文件与修复工作树逐字节一致；
- 每个补回的 QNN/JNI/vendor/upstream 文件与用户原包逐字节一致；
- 不含 `.git`、构建缓存、Python cache、真实 `.env`、私钥、keystore；
- 不含原包中 `security-defense/runtime` 和 `security-defense/reports` 的机器现场快照/历史审计日志，它们不是代码，并可能携带部署环境信息；仓库跟踪的 `.gitkeep` 仍保留；
- 不包含 `docs/#U...` 两个重复的转义文件名副本，正确 Unicode 文件名的 Git 跟踪文档已完整保留。

## 字体资产说明

交付规则不允许重新分发字体二进制，因此原包中的 3 个既有字体文件没有放入压缩包。它们的原路径、大小和 SHA-256 已写入 `FONT_ASSET_OMITTED.txt`。需要字节级复原本地工作区时，从你上传的原始压缩包复制回对应路径即可。除这 3 个字体二进制外，代码、QNN/JNI 运行文件和离线依赖均已纳入完整性校验。

## 未在当前环境执行的物理验证

- Android APK 构建：当前容器没有 Android SDK/NDK 和目标 QNN SDK。
- Gradle Wrapper 联网下载：Gradle 9.2.1 未缓存且容器无外网；对应 164 源文件离线聚合编译已通过。
- 完整服务端 pytest：环境缺少锁定的 `bcrypt`、`slowapi`；Python compileall、Release Manifest 直接测试和 3 项一致性测试已通过。
- 真机 USB MAKCU、Bluetooth HID、目标手机 QNN、真实视频流连续运行：需要你的设备链路。

这些项目在报告中标记为 `NOT_RUN`，没有伪报通过。
