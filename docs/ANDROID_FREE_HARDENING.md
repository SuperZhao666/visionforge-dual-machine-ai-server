# Android 零授权费加固基线

## 正式发布状态与信任边界

本基线中的 R8、资源收缩、JNI hardening、签名自检和调试器检测只负责提高静态分析与篡改成本，不能充当授权、模型机密性或双机身份的最终信任边界。结合本地逆向经验复核后，当前 release APK 仍被正式门禁阻断，原因包括：

- `MobileRuntimeService` 仍用 Android 同一安全边界中的第二个 KeyStore alias 模拟 Host 身份，不能证明远端 Windows Host 持有独立私钥；
- `androidOnlyChannelBinding()` 仅哈希公开路由字段，不是经过相互认证握手得到的 transcript/exporter；
- 视频、presence probe、IDR 与按键包仍缺少统一 AEAD 和 anti-replay；
- portable ONNX 与 QNN 模型 `.so` 仍可随 APK 被提取，R8、APK 签名或 native 符号隐藏不会加密这些内容。

正式 APK 必须额外满足：

1. release 身份密钥由 AndroidKeyStore secure hardware 生成且不可导出；客户端本地 `KeyInfo` 检查只是门禁，服务端仍需验证 Key Attestation challenge、证书链、安全级别和应用身份。
2. Android 只接受真实远端 Host attachment；debug/模拟器可保留测试 attachment，但 release 编译和运行路径必须不可达。
3. 模型使用签名加密 envelope、设备/会话绑定的短期内容密钥、撤销与水印；密钥不写入 APK、native 常量、日志或 bug report。若某硬件运行时无法安全地从内存载入加密模型，则该模型路径不得获得“机密模型”正式声明。
4. 发布产物扫描必须证明 APK 中不存在 portable `.onnx` 和业务模型 QNN `.so` 明文；运行日志、导出包和崩溃转储也不得携带 token、原始 attestation、内容密钥或完整模型片段。
5. `python tools\verify_dual_machine_release_readiness.py --mode formal` 返回 0 之前，不得把本基线描述为“双机数据面安全”或“防破解完成”。

本项目不承诺对拥有本地管理员/root 权限的攻击者隐藏所有运行时明文。可执行的安全目标是：即使 APK/进程被逆向、Hook、补丁或转储，也无法仅凭客户端材料伪造服务端授权、冒充另一台 Host、重放旧会话或长期取得可撤销模型能力。

本文其余部分记录无需商业授权、可用于开发构建的成本型保护。该基线只作用于 Android APP；桌面 Host 的正式身份、租约 gate 与 Authenticode 由独立发布契约约束。

## 已启用

- 正式 `release` 使用 AGP 内置 R8 Full Mode，开启代码压缩、优化、重命名和资源收缩。
- 使用优化版默认规则，并只保留 9 个由 C++ 按名称调用的 Java 回调；不保留整个业务包。
- 启用优化资源收缩器；固定名称加载的 QNN assets 不参与资源删除。
- APK 正式签名关闭旧 v1/JAR 方案，要求 v2 与 v3；正式证书必须在有效期内，并使用 RSA-3072+ 或 EC-256+ 配合 SHA-2。
- 正式 APP 在卡密、租约和正式计费能力初始化前，校验自身当前签名证书、包名、debuggable/testOnly 状态及调试器状态；不匹配时关闭授权数据面。
- 自研 ARM64 库的 release 编译启用栈保护、FORTIFY、符号隐藏、分段回收、RELRO、立即绑定和不可执行栈。
- 发布工具强制生成并校验 R8 `mapping.txt`，默认将其保存到 `%LOCALAPPDATA%\VisionForge\private-release-symbols\android`，不放入仓库、公开发布报告或用户分发目录；同时保存私有 SHA256 侧车与内部符号报告。
- 发布静态门禁要求 APK 只有一个当前签名者、v1=false、v2=true、v3=true、非 debug 证书且 manifest 不可调试。

项目原有的 HTTPS 明文禁用、SPKI 双 pin、服务端签名租约、AndroidKeyStore 设备密钥、卡密正式使用后才计费等网络门禁保持不变。

## 当前不接入

- dProtect 1.0.0 依赖已被 AGP 8 删除的 Transform API，并要求关闭 R8；当前 AGP 8.13.2 / Gradle 9.2.1 工程无法直接使用。
- O-MVLL 当前官方 Android 插件只提供 Linux/macOS 资产，最新版要求 NDK r29；本机为 Windows NDK r27，且 WSL/Docker Linux 构建环境不可用。
- DexGuard、Virbox 等商业产品需要付费授权，不属于本零成本基线。

## 边界

R8 不会加密 QNN 模型 `.so`、assets 或 Qualcomm 预编译库。APK 签名和运行时签名门禁能发现篡改或重签，但不能保证客户端文件绝对不可提取。后续若启用 Linux/NDK r29 构建链，可另行对自研 C++ 冷路径评估 O-MVLL；不得直接处理 Qualcomm 预编译库或未经性能回归的推理热路径。

本基线写入源码后尚未构建 APK。下一次正式构建必须完成 R8 release、JNI、QNN、卡密、租约续期和真机全链路验收后才能发布。
