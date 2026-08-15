# VisionForge 双机逆向抵抗威胁模型与纵深加固基线

更新时间：2026-08-04

## 1. 文档目的与结论

本文把本地 `F:\逆向` 工作区中已经实际使用、记录或复现的逆向与破解手法，映射为 VisionForge 单机客户端、Windows Host、Android、sidecar、主服务端、更新、运行时供应和模型分发的安全不变量。

结论不是“客户端绝对不可破解”。在攻击者拥有本地管理员/root、可调试进程、可修改系统时间、可抓取内存和网络流量的前提下，任何最终以明文参与计算的客户端代码、模型或数据都存在被观察的理论窗口。可执行的正式目标是：

> 即使客户端、APK、Host EXE 被完整解包、反编译、Hook、补丁和运行时转储，攻击者仍不能仅凭客户端材料伪造服务端能力、冒充另一台设备、横向控制双机链路、重放关键操作、降低安全版本、投递未签名组件，或长期取得已撤销的模型/授权能力。

当前仓库尚未达到该目标。服务器权威、短租约、版本 floor、发布签名和正式发布 fail-closed 已显著加固；但双机 Host 独立身份、相互认证 ECDHE、UDP AEAD/anti-replay 和加密模型供应尚未完成。因此，当前双机正式发布必须被阻断。

## 2. 取证范围、方法与证据完整性

### 2.1 只读处理规则

- `F:\逆向` 仅作为只读取证源。
- 未运行其中任何未知 EXE、DLL、脚本、宏、调试器自动化、DMP 或网络重放工具。
- 未把私钥、账号、密码、代理 secret、设备 UUID/IP、访问令牌、完整 PCAP/ETL/DMP、登录请求或源码快照复制到仓库、测试、文档或对话。
- `_skill-staging` 中的第三方源码、虚拟环境和 Git 对象只作为工具/论文材料，不计作用户本人破解成功记录。
- 该目录是持续变化的活跃工作区，不是冻结的法证镜像；所有数量均是时间点快照，不能声称永久穷尽。

### 2.2 时间点快照

- 初始总量：34,569 个文件、5,230 个目录、11,790,006,361 字节。
- 后续快照：34,615 个文件、11,813,413,480 字节。
- 与用户案件/经验直接相关的材料约 1,240 个文件、10.55 GB。
- `_skill-staging` 约 33,375 个文件、1.262 GB，主要为第三方材料。
- `2026-08-03T17:53:34Z` 的相关文本、脚本、配置、日志和抓包瞬时清单：581 个文件、1,350,934,312 字节、读取失败 0。
- 该清单摘要 SHA-256：
  `27ed2ec780ed352fddd6ea642d470cced1d126414e9f7a65536606b5f362aa7f`
- 已完整覆盖 37 份 Markdown 和唯一相关 PDF。
- Themida mutation 研究论文 SHA-256：
  `155007984f1027cd2f35f67b2aa404790d254cbcb6815474e2afa08592e0ea53`

这些哈希用于证明本轮分析基于哪个时间点的材料集合，不意味着仓库保存了原始敏感证据。

## 3. 已证实的本地逆向能力

下表只记录有报告、脚本、日志或复现材料支持的手法。能力强度按“能否改变信任结论”而不是工具名称排序。

| 手法族 | 已观察能力 | 对 VisionForge 的直接含义 |
|---|---|---|
| PE/壳/打包识别 | 节区、熵、导入、字符串、IDA headless；PyInstaller overlay/SFX 雕刻与解包 | Python 打包和单层壳不能保护业务规则、URL、公钥、模型路径或授权分支 |
| 商业壳与虚拟化分析 | Themida/WinLicense 自动脱壳、OEP/IAT 修复、mutation 去混淆研究 | Themida/VMProtect 只能增加时间成本，不能成为授权或密钥边界 |
| 引导链动态跟踪 | cdb/WinDbg 跟踪解压与加载链 | “只在启动时短暂出现”的明文、模块和密钥仍可被定位 |
| 运行时 Hook/补丁 | Frida Hook、异常陷阱定位、函数返回与控制流补丁 | 本地签名检查、反调试、`isLicensed`、`return true` gate 均可被改写 |
| 外部进程读写 | `ReadProcessMemory`、`WriteProcessMemory`、ctypes 外部补丁 | 只检测 Frida、注入 DLL 或进程内 Hook 不足；攻击可完全在外部进程完成 |
| 运行时 dump/重建 | 手动映射 PE 发现、内存 dump、PE 重建、连续解密代码恢复 | 只要模型、代码或 key 在客户端以明文出现，就应假定最终可被观察 |
| 自定义数据解码 | XOR/RLE/LZ77/位流解码器 | 自制压缩、拆常量、简单 XOR 和私有文件格式不是密码学保护 |
| TrustAnchor/客户端信任补丁 | 内存替换证书/信任锚、证书固定绕过探索 | SPKI pin 仍有价值，但不能单独证明服务器；关键响应还需应用层签名与服务端状态 |
| 路由与假服务 | hosts、代理、loopback、URL 重定向、API/OpenAPI/端点枚举 | 客户端 URL、DNS、hosts 和代理均不可信；非幂等请求重放规则必须服务端约束 |
| 网络取证与重放 | pktmon、PCAP、ETL、请求重放、管理面探测、字典喷洒 | 裸 UDP、可重放 token、公开 probe/IDR/按键协议会被直接伪造或重放 |
| 本地接口滥用 | 本地无鉴权 API、UIAutomation、OCR、窗口消息注入 | localhost/IP/窗口来源不是身份；本地控制面必须有 capability、会话绑定和输入所有权 |

## 4. 必须保留的事实纠偏

安全设计不能把“探索到一个局部现象”升级为“完整破解成功”。本轮明确保留以下反证：

- 某游戏协议的 18 个会话中，0/18 支持“请求密文 XOR 魔数即可推出响应流”；所谓恒定 24 字节密钥流来自垃圾 Frida 输入伪影，现有 fake server 自动响应算法没有闭环。
- 约 51 MB 连续已解密代码区得到确认，但后续按需解密区没有完整恢复，不能声称已完成全量脱壳。
- 某雷达 TrustAnchor 内存写入成功，但伪造登录没有端到端闭环。
- 简单 `return 1` 补丁只隐藏了登录页面，没有建立后续必须的业务状态。
- 一个同名目标实际选错，不计作目标破解成功。
- Themida 论文证明 mutation 去混淆可系统化，不证明当前 VisionForge 已被该工具破解。

这些纠偏不降低威胁等级：它们说明局部补丁经常不足，但也证明攻击者已经具备定位、修改和转储客户端信任逻辑的能力。

## 5. 威胁主体与假设

### 5.1 纳入范围

1. 普通用户，可复制、重命名、替换 EXE/APK 和配置。
2. 本地管理员/root，可调试、注入、转储、修改系统时间、读取用户目录和进程内存。
3. 同局域网主动攻击者，可抓包、丢包、乱序、重放、伪造 UDP 源和发送控制包。
4. 被补丁的旧客户端，可自报新版本、替换 hosts/代理、调用已知 API。
5. 泄露单个客户端/单个设备材料的攻击者，尝试横向复制到其他用户、Host 或 Android。
6. 发布流程误配置或 CI 绕过，尝试把 unsigned、development、旧 floor 或 plaintext 组件标成正式成功。

### 5.2 不可承诺的边界

- 不承诺本地管理员/root 永远看不到运行时明文。
- 进程内 AEAD 只抵抗链路抓包、篡改、伪造、乱序和重放；已经完全控制某一端点进程的管理员可读取该端当前会话 key、Hook 系统密码 API 或改写状态，因此可冒充该端在当前会话中的角色。
- 纵深目标是把端点失陷的影响限制在该端、该角色、该短会话：不能仅凭一端材料伪造另一端硬件身份或服务端签名能力，撤销/过期/重握手后旧 key 与旧包必须失效。若要连被控端点的活跃进程也视为不可信，必须增加普通用户态进程之外的隔离执行边界和认证 IPC。
- 不把反调试、R8、Themida、VMProtect、字符串加密、客户端签名自检或证书 pin 单独视为授权证明。
- 不把 IP、MAC、端口、设备指纹、公开 channel 字段的哈希视为密码学身份。
- 不把“单元测试通过”替代生产证书、TPM/TEE、CAT6、真实 GPU 和真实签名产物验收。

## 6. 安全不变量

正式系统必须同时满足：

1. **服务端权威**：余额、授权、最低版本、撤销、目录、下载票据和模型 key release 都由服务端决定；客户端缓存只能提高可用性，不能延长权利。
2. **身份独立**：Host 与 Android 私钥位于不同设备、不同硬件安全边界，均不可导出；Android 不能生成“假 Host”第二私钥来满足双签。
3. **新鲜会话**：每次连接用 fresh ECDHE 和 transcript/exporter；禁用 0-RTT，不复用静态 PSK 作为长期数据面主密钥。
4. **双端验租约**：Host 和 Android 独立验证同一原始短租约及精确 claim；任何一端失败都关闭数据面。
5. **认证前最小处理**：UDP 包在认证前只允许固定上限 envelope 解析和只读 replay prefilter；任何 replay 状态推进及 frame/fragment 元数据解析都必须在 AEAD tag 成功后发生。预认证拒绝对网络侧统一 silent drop，避免形成状态 oracle。
6. **nonce 唯一**：每个方向、包类型和 epoch 独立 key；nonce 不得在同一 key 下复用。
7. **无隐式降级**：v2 pair 不因握手失败、超时、断线或更新失败自动回退 plaintext/v1。
8. **版本不可回退**：服务端 signed history 的最低版本 floor 单调不降；旧版本、wildcard 和非法版本不再获得生产完整性授权。
9. **供应链签名**：EXE/APK、更新 manifest、runtime catalog、运行时组件和模型 envelope 均有明确签名者、版本、hash 和 anti-rollback 语义。
10. **日志脱敏**：日志/bug report 不含私钥、密码、token、原始卡密、完整 attestation、内容密钥、模型或可直接重放的请求。

## 7. 已落地的加固

### 7.1 正式 Host 产物门禁

- 正式 Host 必须有 `Valid` Authenticode、可信时间戳和显式 allowlist 中的 signer certificate SHA-256。
- 使用系统 Windows PowerShell 绝对路径，避免工作目录/PATH 中的伪造 `powershell.exe`。
- 实现兼容 Windows PowerShell 5.1 的证书 SHA-256 计算。
- formal 模式拒绝任何 diagnostic/development bypass。readiness 统一使用
  `visionforge-dual-machine-release-readiness-v3`；`development` 仅作为
  `diagnostic` 的兼容输入别名。diagnostic 可以用退出码 0 完成证据采集，但报告固定
  `strict_ok=false`、`formal_ok=false`、`formal_release_ok=false`、`ok=false`，不能被下游洗成正式成功。

### 7.2 模型加载前授权

- runtime 在 `make_detector()`、ONNX 读取、ORT provider 枚举和 `InferenceSession` 构造前等待并再次验证租约。
- 第二次检查过期会作为 `RUNTIME_AUTHORIZATION_FAILED` 干净退出，不进入 `MAIN_UNHANDLED`。
- 行为测试调用真实 `main()`，证明该边界失效时 `make_detector`、`run_image`、`run_screen` 均未执行且未新增 ORT import。

### 7.3 runtime lease v2

- payload `typ=vf-runtime-lease-v2`，header 要求 `alg=RS256`、`typ=JWT`，`kid` 必须匹配内置公钥 SPKI SHA-256 标识。
- 双端严格要求并绑定：`iss/sub/sid/av/did/lid/rid/ver/manifest_hash/nonce/iat/nbf/exp/ttl`。
- 数值 claim 必须是非 bool 的 JSON integer 且不超过 signed 64-bit；文本 claim 必须是字符串、非空且有上限。
- manifest 必须是 64 位 SHA-256 hex；`sub/sid>0`、`av>=0`；`rid/ver/nonce` 必需。
- 签名段 TTL 为 1–15 秒；`exp-max(iat,nbf)==ttl`；过期宽限为 0。
- 初始 `nbf` 不再回拨 300 秒；慢钟/回拨时钟 fail closed。
- V2 runtime instance 必需，空 runtime ID 的 legacy 路径不再获得 v2 租约。
- 本地 `local_not_before/local_expires_at` 不参与授权，修改 JSON 不能提前激活或延长签名 `exp`。
- 服务端 verifier 的 runtime/version/manifest expected binding 变为必填，避免后续调用者无意跳过。
- production 缺 manifest 即拒绝；开发模式使用明确的非正式哨兵摘要，不冒充 attested manifest。

注意：本地管理员仍可修改进程或系统时钟。严格 wall-clock 只是即时止血；更好的后续方案是由在线 broker 通过 PID/一次性随机量绑定 IPC 传入 signed server-time + monotonic anchor，并把真正有价值的模型 key/能力留在服务端短期释放。

### 7.4 服务端 anti-rollback 与会话冻结

- 最低版本 floor 从同 channel 全部不可变 signed history 取最大值，非法历史 floor fail closed。
- 新签名发布不能降低或清空已存在 floor；release、floor、allowlist 更新和低版本停用在同一 `BEGIN IMMEDIATE` 事务内。
- stable floor 会停用低版本、非法版本和 wildcard allowlist。
- session-start 在计费前检查 floor；heartbeat 中途遇到 floor 提升会结束旧会话。
- client version 与 manifest 在 session-start 后冻结；heartbeat 自报不同版本返回 409、结束会话、不扣费、不续签。
- access JWT 的 `ver` 贯穿登录、改密、runtime catalog 和下载票据。

### 7.5 生产配置和运行时供应

- 显式 `ENVIRONMENT=production|development|test`；production 强制 HTTPS origin、runtime integrity、runtime instance、secure cookie，禁止不安全租约 HMAC。
- production 消费端只接受精确 client version，遗留 wildcard 即使还在数据库中也不生效。
- runtime download ticket v2 绑定用户、应用版本、active catalog hash、object key 和 expiry；实际下载重新检查 floor、用户状态和当前目录。
- floor 在票据签发后提高会立即使旧 ticket 失效。

### 7.6 Android 身份和正式发布门禁

- release AndroidKeyStore 身份要求设备解锁、`ORIGIN_GENERATED` 和 secure hardware；debug/模拟器可不强制。
- 该检查尚不是服务端验证的 Key Attestation，不能声称设备身份已远程证明。
- `verify_dual_machine_release_readiness.py --mode formal` 通过固定、不可删项的 registry
  检查 14 个逆向抵抗 blocker：Host 数据面 gate、Host 独立硬件身份、Android 禁止本地伪 Host、
  握手 channel binding、视频 AEAD、认证 presence probe、认证 IDR、认证鼠标按键、nonce/anti-replay、
  禁止明文降级、Host 公共安全输入、APK 无明文模型、加密模型 key release、密码学行为证据。
- Host CMake 与 Android Gradle 均有独立 formal fail-closed gate；在 Secure v2 尚未真实接线时，
  正式 Host candidate 和 release APK 会在构建阶段被拒绝。
- diagnostic 可完成基础诊断，但报告永远不是 formal success。

### 7.7 正式发布报告与签名归档

- `verify_formal_release_bundle.py`、formal acceptance、packager 和 publishable verifier 都会重新检查
  `mode=formal`、全部成功标志、空 bypass、必需 check 唯一性以及 source-contract 证据；不能只伪造
  子进程退出码 0 或 `{"ok": true}`。
- publishable bundle manifest 是 `visionforge-publishable-release-manifest-envelope-v1` Ed25519 envelope；
  被签名 payload 使用 canonical UTF-8 JSON，签名前不包含本机绝对路径或离线私钥路径。
- verifier 只信任 ZIP 外部提供的公钥，先验签再解析 payload；`key_id` 必须等于 Ed25519 raw public key
  的 SHA-256。ZIP entry 必须与签名清单精确闭包一致，重复、额外、路径穿越和 unsigned legacy manifest
  均被拒绝。
- 签名 payload 绑定 channel、release version、bundle sequence、published time、minimum supported version
  和 revocation epoch；verifier 还必须从 ZIP 外部取得对应最低 floor。缺少外部 floor 时可以报告
  `authenticated=true`，但必须保持 `anti_rollback_enforced=false`、`ok=false`。

### 7.8 production runtime integrity fail-closed

- production 在查询 allowlist 之前拒绝开发用未验证 manifest sentinel，即使该 sentinel 被误插入数据库也无效。
- production 只接受“精确 client version + 精确 allowlisted manifest hash”，不接受 wildcard version，
  也不再允许 executable hash fallback 把未登记 manifest 变成生产授权。
- 完整性拒绝发生在 runtime lease 签发、余额扣减和 `time_sessions` 创建之前；development 的命名
  sentinel/EXE fallback 仅保留为非正式诊断路径。

## 8. 当前双机 P0 阻断

### 8.1 Host 没有独立授权边界

- `host_runtime_service.cpp` 两条正式启动/恢复路径仍注入恒真 permit。
- Host 不持有并独立验证 Android 收到的 raw lease。
- 因此补丁 Android、伪造 presence 或断开授权后，Host 仍可继续明文推流。

### 8.2 Android 可在同一 UID 内模拟双签

- 第二个 AndroidKeyStore alias 被当作 Host 身份。
- `androidOnlyChannelBinding()` 哈希的是公开 transport/network/IP 信息，不是握手 transcript。
- 这不能抵抗已能 Hook/补丁 Android 进程的攻击者。

### 8.3 UDP 无机密性、身份和重放保护

- `VFRG/VFRR` 只有明文头和 H.264 分片。
- presence probe 只看 IP 与明文包结构，两个很小的伪造起始包即可制造“视频已到达”条件。
- `IDR1` 和 `VFMB` 无认证；后者可改变物理按键状态，风险高于普通画面污染。
- 来源 IP/端口只是路由提示，不是身份。

### 8.4 模型随 APK 明文分发

- portable ONNX 与业务 QNN `.so` 仍在 release staging/目录中。
- R8、APK 签名、自研 native hardening 和调试器检测不会加密这些文件。
- 在完成 encrypted envelope/key release 前，不得声称移动模型具备强机密性。

## 9. 双机数据面 v2 设计合同

### 9.1 身份与控制通道

- Host：Windows CNG/TPM P-256 非导出签名身份；Android：AndroidKeyStore P-256 非导出身份。
- 服务端登记 pair binding、identity generation、attestation 状态和 minimum data-plane version。
- 正式 control channel 必须只选择一个经独立审查的方案：禁用 0-RTT 的双向认证 TLS 1.3/QUIC，
  或 `AUTHENTICATED_PEER_HANDSHAKE_V1.md` 中双身份签名、fresh P-256 ECDHE、Finished 后再承载独立
  AEAD control record 的方案。两者不得同时作为运行时 fallback。
- TLS/QUIC 路径使用固定标准 exporter；自有握手路径使用 transcript-bound HKDF，并为每个方向/type
  派生独立 key、nonce prefix、counter 与 replay domain。当前仓库只有基础密码草案，尚未冻结或接线。
- 长期身份私钥只签名，不直接做 AES key 或静态 ECDH。
- sidecar 只验证 pair/签发租约，不获得数据面密钥。

### 9.2 UDP 外层

建议最大 datagram 保持在 1412 字节：

```text
32 B authenticated header
+ 0–1364 B ciphertext
+ 16 B AES-GCM tag
= 最大 1412 B UDP datagram
```

32 字节认证头固定包含：`VFA2` magic、version、header size、packet type、direction、
64-bit connection ID、32-bit key epoch、64-bit packet counter 和 32-bit ciphertext length，
所有整数均为网络字节序。frame/fragment 元数据放在 ciphertext 内，只有 tag 成功后才解析。

nonce：4 字节 HKDF 派生 prefix + 8 字节 packet counter。每个
`(connection, epoch, direction, packet_type)` 独立子密钥和 counter 空间。v2 单个 traffic key
最多处理 `2^23` 个包（counter `0..2^23-1`），随后必须 rekey；32-bit epoch 禁止回绕或回退。
provider 加密失败也必须消耗已尝试 counter。重启状态不确定、key install 失败或 counter 状态丢失时
必须建立新 connection/epoch 并派生新 key，禁止从 0 复用旧 key/nonce prefix。

### 9.3 anti-replay

- 每个 `(connection, epoch, direction, type)` 使用至少 1024-bit sliding window。
- 过旧 counter、窗口内 duplicate、错误 epoch/方向/type 均拒绝。
- 认证前允许只读 classify 以丢弃明显 duplicate/too-old 包，但不得向网络暴露细粒度原因；不得在 GCM tag 验证前推进窗口，否则伪包可消耗窗口造成 DoS。
- route change、suspend/resume、进程重启必须建立新 connection/epoch，不能沿用不确定 counter。

### 9.4 租约与数据面生命周期

- raw lease 同时交给 Host/Android，双方验证完全相同的 pair、identity hash、channel binding、session、sequence、previous-ticket hash 和 runtime version。
- 只有双方 gate 都 active 才发送/接收视频、probe、IDR 和按键。
- expiry/revocation/detach/route change 立即停止 publisher、清空输入状态、释放按键并销毁 epoch key。
- v2 pair 失败时不回退 v1；需要兼容时使用显式重新配对和服务端策略，而不是静默降级。

## 10. 模型与运行时保护

### 10.1 正式模型供应

1. 离线发布机生成随机内容密钥 CEK，加密模型/业务 QNN payload，生成带版本、目标硬件、hash、最小客户端版本和撤销 ID 的签名 envelope。
2. 服务端在用户、设备 attestation、版本 floor、完整性和租约均通过后，短期释放包装后的 CEK。
3. CEK 绑定设备/会话/model release，不能跨用户、跨设备、跨旧版本复用。
4. 尽量从受控内存加载并及时清零；不把解密模型永久写到普通用户目录。
5. 对无法避免磁盘解密的第三方 runtime，使用独立受限目录、短生命周期、ACL、启动前后 hash 校验，并明确其机密性上限。
6. 为每个客户/批次加入可追踪水印，以便泄露归因；水印不能替代加密和授权。

### 10.2 原生运行时供应

- 公钥编译进 native trust anchor；环境变量只能选择诊断策略，不能替换生产公钥或放宽目录验证。
- DLL 用绝对路径加载；不要通过前置修改 PATH 选择安全敏感 DLL。
- 每次加载前按 signed catalog 全量复验 SHA-256、PE x64、依赖闭包和版本；激活后仍要防目录替换/链接攻击。
- runtime catalog/download ticket 与 server floor、用户状态和 active catalog hash 绑定。

## 11. 逆向手法到控制的映射

| 本地手法 | 不足的旧防护 | 必须保留的纵深控制 |
|---|---|---|
| PyInstaller/壳解包 | 仅打包、Themida、字符串混淆 | 服务端权威、短期能力、签名组件、模型 envelope；客户端无长期 secret |
| Frida/返回值补丁 | 客户端 `isLicensed`、反调试 | 双端验服务端签名租约、Host gate、在线撤销、正式完整性/版本 floor |
| 外部 RPM/WPM | 只扫注入模块/Frida | 不让本地布尔值授予服务器能力；硬件非导出身份；关键操作服务端重验 |
| 内存 dump/PE 重建 | 加壳或自定义加载器 | 短期 CEK、按设备/会话 key release、水印、撤销；承认运行时明文窗口 |
| XOR/压缩解码 | 自制编码/拆常量 | 标准 AEAD、签名 envelope、HKDF domain separation |
| TrustAnchor 替换 | 仅证书 pin | SPKI rotation pin + 应用层签名 + signed floor/catalog/lease；敏感 POST 不盲目重放 |
| hosts/假服务器 | 硬编码域名或 IP | TLS、pin、应用层签名、服务端状态、不可回退版本；公钥不可由环境覆盖 |
| PCAP/请求重放 | bearer token/裸 UDP | nonce、sequence、expiry、session/identity binding、AEAD counter、anti-replay window |
| API 枚举/字典喷洒 | 隐藏 URL | 最小公网面、限流、统一错误、审计、管理面隔离、无默认凭据 |
| UIAutomation/消息注入 | 隐藏按钮/窗口名 | 输入 ownership、状态机、授权 gate、物理输出释放、敏感动作 capability |

## 12. 发布与 CI 门禁

正式流水线必须同时检查：

1. `verify_dual_machine_release_readiness.py --mode formal` 返回 0，JSON 中
   `schema=visionforge-dual-machine-release-readiness-v3`、`mode=formal`、
   `diagnostic_completed=true`、`checks_ok=true`、`strict_ok=true`、
   `reverse_resistance_ok=true`、`formal_eligible=true`、`formal_ok=true`、
   `formal_release_ok=true`、`bypasses=[]`、`ok=true`。
2. `verify_formal_release_bundle.py --mode formal` 无 bypass，Host Authenticode/APK production signing/Windows EXE/device evidence 全部通过；下游必须重验报告结构和必需 check，不能只信退出码。
3. APK/EXE secret scanner 不含私钥、PSK、CEK、测试密钥、完整 token、调试证书或 plaintext business model。
4. SBOM 锁定密码库版本；禁止自制 AES-GCM/TLS/ECC 实现。
5. Wireshark/pcap 证明看不到 H.264 NAL、IDR/按键明文语义或可重放 token。
6. mutation tests 覆盖 tag bit flip、AAD bit flip、截断、超长、重复、乱序、旧 epoch、错误方向/type、counter 边界和 connection mix-up。
7. publishable ZIP 使用 Ed25519 签名 envelope、外部受信公钥和外部 anti-rollback floor；ZIP member 与签名清单精确闭包，拒绝 unsigned legacy、重复或额外 entry。
8. 离线私钥必须由 packager 显式传入，位于仓库和发布输出之外；私钥路径、正文及本机绝对路径不得进入签名 payload、ZIP、acceptance report 或日志。
9. 正式报告不得把 diagnostic/development、模拟器、测试证书、假 inspector、源码字符串断言当作真实签名/硬件验收。

## 13. 实体机与生产证书待验收

- Windows 10/11、不同 TPM 2.0 厂商；TPM disabled/no TPM 的明确策略。
- 真实生产 Host Authenticode 证书、时间戳链、轮换/撤销和 SmartScreen 运营流程。
- Android API 29–35、TEE 与 StrongBox、锁屏/解锁/重启/KeyStore reset；服务端 Key Attestation 验证。
- CAT6 与 WLAN fallback；144 Hz/高码率一小时；每个 lease/key epoch 轮换；CPU/P95/P99/功耗/温升。
- CUDA/TensorRT/DirectML 实体 GPU 与正式 runtime catalog。
- 完整 release APK/EXE 精确 hash 的端到端 pair、撤销、断网、余额耗尽、重启和无降级验收。

未完成的硬件项必须在报告中标为 `pending_hardware_acceptance`，不能用 mock 或 debug build 写成 PASS。

## 14. 敏感材料处置建议

`F:\逆向` 中发现了私钥、明文账号/密码、代理 secret、设备/远端地址、DMP、PCAP/ETL、登录抓包、数据库测试凭据和 VisionForge 源码快照等类别。本文不列出其值。

建议在用户授权下执行独立处置：

1. 先建立只含路径、类别、owner、最后使用时间和轮换状态的脱敏资产表。
2. 将私钥和完整转储移入离线加密介质或受限 ACL 目录，禁止同步盘、仓库索引和自动 bug report 收集。
3. 轮换所有曾以明文出现的账号、代理、JWT/SMTP/数据库凭据和发布 key；旧值在服务端显式撤销。
4. 检查 DMP/PCAP 是否含访问令牌和环境变量；按最敏感等级处理。
5. 对 VisionForge 源码快照限制 ACL，并确认不被打包、索引或上传。
6. 删除任何材料前必须取得用户明确授权；本轮没有删除或移动原始证据。

## 15. 完成定义

只有下列条件全部成立，才能把“双机正式数据面具备逆向抵抗”标为完成：

- 真实 Host CNG/TPM 身份与 AndroidKeyStore 身份；
- 服务端登记和验证 pair/attestation；
- fresh ECDHE 相互认证控制通道和真实 exporter channel binding；
- Host/Android 独立验证相同 raw lease；
- AEAD video/probe/IDR/mouse，nonce 唯一和 anti-replay；
- v2 pair 无 plaintext fallback；
- expiry/detach/route change 全链 fail closed；
- release APK 无 plaintext business model；
- 正式签名、floor、catalog、模型 envelope 和下载票据 anti-rollback；
- 针对性自动回归、真实包检查、真实网络对抗和硬件验收全部有精确 artifact hash 证据。

少于这组只能称为“v2 基础设施”“成本型加固”或“开发诊断”，不能称为已完成防破解。
