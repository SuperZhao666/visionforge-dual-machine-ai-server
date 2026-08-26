# 双机授权 UI 与 QA 构建防回归守则

更新时间：2026-08-25

## 永久禁止回归的两个故障

### 1. “卡密或网络检查失败”反复出现

2026-08-25 的实机根因不是卡密失效，也不是手机断网。错误 QA APK 是在
没有加载正式公共授权材料的情况下由 `assembleQa` 生成的；其生成后的
`BuildConfig` 中以下三项均为空：

- `DUAL_MACHINE_TLS_SPKI_PINS`
- `DUAL_MACHINE_TICKET_PUBLIC_KEYS_BASE64`
- `DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEYS_BASE64`

模型和 QNN 文件仍然会被打包，所以 APK 能安装、能打开，但授权运行时只能
保护性关闭。通用标题“卡密或网络检查失败”又掩盖了真实的构建错误。

永久约束：

- `packageQa`、`packageOwner`、`packageRelease` 和 `bundleRelease` 必须依赖
  `verifyDualMachineReleaseSecurityInputs`。
- 任何一个 TLS Pin、票据公钥或配对凭据公钥缺失时，必须在 APK 生成前失败；
  不允许把坏包留到手机启动后才发现。
- QA/Owner 构建不得直接运行一个没有先加载正式公共材料环境的裸
  `assembleQa`/`assembleOwner` 命令。
- 致命授权材料错误必须映射为专用
  `SECURITY_CONFIGURATION_ERROR`，UI 标题为“授权配置不可用”，不能冒充
  卡密错误或网络错误。

当前正式公共材料入口：

`out/release-materials-20260823/dual-machine-android-gradle-env.ps1`

该文件只包含公开 TLS Pin 与公开验证密钥路径，不包含密码或私钥。构建前应在
同一个 PowerShell 进程中加载它，再调用 Gradle。

### 2. 禁止用“待同步”掩盖真实授权状态

“待同步”无法区分未激活、正在核验和授权材料缺失，用户会误以为继续等待即可
恢复。正式 UI 不再使用这个模糊占位词。

永久约束：

- 未建立 entitlement 时显示“未激活”；激活请求进行中显示“激活中”；服务端或
  双端状态核验进行中显示“核验中”。
- `SECURITY_CONFIGURATION_ERROR` 或其他无法安全确认余额的终态显示“不可用”。
- 已绑定卡密在重启或覆盖安装后，如果有与当前 entitlement 严格匹配的最近一次
  服务器确认余额，应显示该只读缓存并标注为最近验证值；缓存不得恢复正式启动
  权限，正式使用前仍须完成双端认证刷新。
- 当 Host 尚未建立认证会话时，刷新失败可以保持安全关闭，但不得抹除已验证的
  展示余额，也不得退化为授权材料缺失错误。

## 强制回归证据

每次修改 Android 授权构建或 UI 状态机后，至少要提供以下证据：

1. RED：缺失正式公共材料时 `packageQa` 明确失败于
   `verifyDualMachineReleaseSecurityInputs`。
2. GREEN：加载材料后 `assembleQa` 成功，且生成的三项 BuildConfig 均非空；
   报告只能记录是否配置和长度，不能泄露实际 Pin 或公钥正文。
3. 自动化：
   - `python -m pytest -q tests/test_android_qa_security_material_guard.py`
   - `gradlew.bat :app:verifyMobileRuntimeSnapshot --no-daemon`
4. 实机：覆盖安装后截图必须显示正确授权状态和余额；启动日志必须包含
   `dual_machine_authorization_runtime_ready`，且不得包含
   `security_configuration_unavailable`。

2026-08-25 修复后的实机截图：

`out/vf_auth_material_guard_fixed_20260825.png`

故障现场截图：

`out/vf_regression_live_20260825.png`

## 对应代码与测试

- `android_inference_benchmark/app/build.gradle`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ui/DualMachineAuthorizationUiMapper.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ui/DualMachineAuthorizationUiState.java`
- `android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/ui/AuthorizationScreen.java`
- `tests/test_android_qa_security_material_guard.py`
- `android_inference_benchmark/app/src/test/java/com/visionforge/inferencebenchmark/DualMachineAuthorizationPresentationSelfTest.java`
- `android_inference_benchmark/app/src/test/java/com/visionforge/inferencebenchmark/DualMachineAuthorizationCardModeContractSelfTest.java`
