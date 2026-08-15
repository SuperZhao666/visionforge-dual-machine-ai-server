# 双机正式发布与安全验收清单

> 安全状态更新：2026-08-04
>
> 当前仓库只具备开发诊断资格，**不具备双机正式发布资格**。正式门禁必须保持失败，直到本文列出的 Host 身份、相互认证握手、认证数据面、模型密钥供应和实机攻击性证据全部落地。历史 Android-only、恒真 Host permit 和明文 UDP 方案不再是可接受的产品策略。

权威威胁映射见 `docs/DUAL_MACHINE_REVERSE_RESISTANCE_THREAT_MODEL.md`。

## 1. 三种门禁模式

本地排查只使用 diagnostic；它即使退出 0，也不能成为发布证据：

```powershell
python tools\verify_dual_machine_release_readiness.py --mode diagnostic --json
```

`development` 仅作为 `diagnostic` 的兼容别名，报告会规范化为 `mode=diagnostic`。

CI 源码与契约门禁使用 strict：

```powershell
python tools\verify_dual_machine_release_readiness.py --mode strict --json
```

正式资格必须显式使用 formal：

```powershell
python tools\verify_dual_machine_release_readiness.py --mode formal --json
```

正式消费者不能只看进程退出码。报告必须同时满足：

- `schema=visionforge-dual-machine-release-readiness-v3`
- `mode=formal`
- `diagnostic_completed=true`
- `checks_ok=true`
- `base_checks_ok=true`
- `reverse_resistance_ok=true`
- `reverse_resistance_registry_ok=true`
- `strict_ok=true`
- `formal_eligible=true`
- `formal_ok=true`
- `formal_release_ok=true`
- `bypasses=[]`
- `ok=true`

当前预期结果是：基础诊断通过，reverse-resistance 检查失败，formal 返回非零。这是安全阻断，不是工具故障。

## 2. 当前必须保持为红灯的安全边界

正式检查注册表必须逐项存在且名称唯一；删除某一项不能使剩余检查通过。当前 blocker 包括：

1. Host 视频发布必须由真实短租约 gate 控制，禁止恒真 `data_plane_permit`。
2. Host 必须拥有每机独立、不可导出的 Windows CNG/TPM 身份。
3. Android release runtime 不得创建本地假 Host alias 或本地 Host attachment。
4. Host 与 Android 必须完成相互认证的 fresh ECDHE；channel binding 来自握手 transcript/exporter，不能用 IP、端口或公开路由字段哈希替代。
5. 视频必须进入 AES-GCM 认证 envelope；`VFRG/VFRR` 不得出现在 formal 可达路径。
6. presence probe 只能依据新鲜、连续前进且已认证的视频会话状态。
7. IDR 请求必须绑定 connection、epoch、方向和包类型；裸 `IDR1` 必须拒绝。
8. 鼠标按键包必须绑定同一认证会话；裸 `VFMB` 必须拒绝。
9. nonce 唯一性、64 位 counter、counter 溢出和至少 1024 位 anti-replay window 必须有可执行边界测试。
10. formal Host/APK 构建不得自动回退 plaintext。
11. Host formal 构建必须接收公开验证 keyring 和算法/版本策略，但绝不接收服务端私钥或全局共享身份私钥。
12. release APK 中不得携带 portable ONNX 或明文业务 QNN 模型 payload。
13. 模型 key 必须是设备、会话、版本、租约和 attestation 绑定的短期可撤销能力。
14. formal 必须具备独立的 mutation/replay/artifact 行为证据，不能用源码关键词代替密码学证明。

静态字符串检查只用于 fail-fast；最终放行还必须依赖行为测试、正式产物扫描、PCAP mutation/replay 和真实硬件证据。

## 3. 正式 v2 最小密码学纵切

- Host 身份：CNG/TPM P-256 非导出签名 key，每台机器独立生成。
- Android 身份：AndroidKeyStore P-256；release 要求 secure hardware，并由服务端验证 Key Attestation 后登记。
- 控制握手：TLS 1.3 双向认证、禁用 0-RTT、临时 P-256 ECDHE。
- Channel binding：使用 TLS exporter 或完整握手 transcript；绑定 Host、Android、pair、connection 和服务端 challenge。
- 租约：Host 与 Android 分别验证同一份原始短租约；精确绑定 pair、connection、channel binding、版本、完整性、epoch、序列和 auth version。
- 数据面：按方向、包类型和 epoch 使用 HKDF 派生独立子密钥。
- Nonce：固定前缀加 64 位单调 packet counter；禁止跨 key epoch 重用。
- Anti-replay：每个 `(connection, epoch, direction, packet_type)` 维护至少 1024 位滑动窗口。
- 处理顺序：先验证 envelope、AAD、tag 和 replay，再解析长度、分配内存或改变任何业务状态。
- 断链：握手失败、route change、租约过期/撤销、key rotation 失败和 counter 状态不确定都必须立即停流并清理 gate/key，禁止 plaintext fallback。

Android legacy-alias boundary: the current
`setUnlockedDeviceRequired(true)` policy is enforced when a new AndroidKeyStore
alias is generated, but an alias created by an older build may be reopened with
its legacy key policy. The API-29 bound-session instrumentation uses a fresh
unique alias and does not prove migration of an installed legacy identity.
Formal readiness therefore remains blocked on a versioned-alias,
server-mediated rebind/revocation and recovery procedure. An
`ANDROID_BOUND_PEER_SESSION_INSTRUMENTATION_OK ... hardware_backed=false`
marker is emulator compatibility evidence only; formal device evidence must
report `hardware_backed=true` and remain bound to the production APK, physical
device and server-verified attestation. This limitation is not resolved by the
current handshake foundation.

Server pair-generation boundary: the sidecar now has a transactional,
monotonic persistence foundation for pair binding revisions, one-time
generation challenges and immutable generation allocations. Binding revisions
are allocated by the server inside `BEGIN IMMEDIATE`; allocation retries must
match the stored tuple and revalidate the live entitlement/binding state. This
foundation deliberately has no HTTP route, no proof-free `activate_pair`
operation and no caller-supplied credential field. It also does **not** yet
issue a signed generation credential. Formal readiness remains blocked until a
restricted signing service creates the credential only after the final
generation is allocated, verifies every signed claim against the committed
server state, and both Host and Android validate that same credential before
the authenticated handshake and lease state machine can advance.

## 4. 正式 bundle 的不可伪造发布边界

正式 bundle verifier report 不能只含 `{"ok": true}`。acceptance、packager 和 archive verifier 会独立复验完整 formal 字段、所有必需检查和 `source_contracts.failed=[]`。

`formal_release_manifest.json` 是 Ed25519 签名 envelope：

- 签名 payload 使用 UTF-8、排序 key、无多余空白、`allow_nan=false` 的 canonical JSON。
- `key_id` 固定为 Ed25519 raw public key 的 SHA-256。
- 验签公钥必须来自 ZIP 外部的受信输入；禁止信任 bundle 自带公钥。
- signed payload 只含 archive-local 路径、size、SHA-256、channel、release version、单调 sequence 和 revocation epoch。
- 本机绝对路径、source path、output path 和私钥路径不得进入 signed payload 或 ZIP。
- ZIP entry 必须唯一、安全且与 signed manifest 精确闭包一致；重复 entry 和任何未签名额外文件均拒绝。
- 普通 `.sha256` sidecar 只用于传输损坏检测，不能替代签名。

离线发布机显式打包示例：

```powershell
python tools\package_formal_release_bundle.py `
  --acceptance-report C:\release-staging\formal_release_acceptance.json `
  --output-dir C:\release-staging\publishable `
  --private-key C:\offline-secrets\formal-bundle-ed25519-private.pem `
  --channel stable `
  --release-version 1.0.8 `
  --bundle-sequence 8 `
  --min-supported-version 1.0.0 `
  --revocation-epoch 0
```

独立验签必须提供外部公钥和外部 high-water floor：

```powershell
python tools\verify_publishable_release_bundle.py `
  --archive C:\release-staging\publishable\formal_release_bundle.zip `
  --sha256-file C:\release-staging\publishable\formal_release_bundle.zip.sha256 `
  --public-key C:\trusted\formal-bundle-ed25519-public.pem `
  --expected-channel stable `
  --minimum-release-version 1.0.8 `
  --minimum-bundle-sequence 8 `
  --minimum-revocation-epoch 0
```

私钥必须显式提供、位于仓库和输出目录之外；工具不扫描默认密钥目录，也不把私钥路径写入 acceptance report。没有私钥或单调 sequence 时，自动 acceptance 会在 publishable packaging 阶段 fail closed。

## 5. Runtime lease 与生产完整性

- runtime lease 使用严格 v2 header/claim 契约，TTL 为 1–15 秒，`nbf` 无回拨宽限。
- 设备、登录实例、runtime instance、auth version、client version 和 manifest hash 必须全部绑定。
- production 明确拒绝 development unverified manifest sentinel。
- production 不允许“未获准 manifest + 客户端自报 EXE hash 命中”的 fallback。
- 完整性拒绝必须发生在签租约、扣余额和创建 session 之前。
- development executable fallback 只能用于非生产兼容验证，不能获得正式模型 key 或正式数据面能力。

这些规则仍不是远程证明。本地管理员可以运行官方文件完成自报后再 WPM patch 已加载进程。更强边界依赖 broker/PID 绑定、服务端 nonce、单调时间锚、TPM/CNG、Android attestation 和短期模型 CEK。

## 6. 仍需实机完成的验收

- 正式 Windows EXE 和 Host EXE 的 Authenticode signer、时间戳与证书 allowlist。
- 正式 APK 的 production signing certificate、v2/v3 scheme 和 release class graph。
- Host TPM/CNG identity 创建、不可导出属性和远端证明。
- Android hardware-backed identity 与服务端 attestation 验证。
- tag/AAD/ciphertext bit flip、截断、重复、乱序、旧 epoch、错误方向/type、wrong connection 和 cross-session mutation。
- raw `VFRG/VFRR/IDR1/VFMB` 在 formal 构建中不可达且运行时被拒绝。
- tag 失败不推进 replay window；counter 溢出、重启后 counter 不确定均 fail closed。
- Wireshark 看不到 H.264 NAL 或业务模型明文。
- CAT6 高码率长稳测试无 nonce 重用，P95/P99 延迟和丢包恢复满足验收阈值。
- 租约到期、撤销、断网、route change、应用后台和进程恢复后，旧 epoch 包不能继续被接受。
- APK/EXE/Host artifact hash、正式签名和物理输出证据全部绑定到同一 formal report。

## 7. 不构成信任边界的措施

R8、壳、Themida、反调试、字符串隐藏、客户端签名自检和本地布尔 gate只能增加分析成本。它们不能替代服务端权威、硬件非导出身份、相互认证、短租约、AEAD、anti-replay、签名模型供应和不可伪造发布清单。

项目不承诺本地管理员/root 永远无法观察运行时明文。正式安全目标是：即使客户端被完整解包、动态调试、内存 dump、WPM patch、TrustAnchor 替换或网络重定向，攻击者仍不能伪造服务端能力、横向控制另一台设备、重放关键操作、降级到明文协议或投递未签名发布组件。
