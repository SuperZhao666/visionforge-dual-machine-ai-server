# VisionForge 双机认证握手 v1 合同

状态：**基础密码合同草案；P1 配对/状态机/控制记录仍待冻结；尚未接入生产；不得解除 formal gate**  
更新日期：2026-08-04

## 1. 目标与非目标

本合同为已经完成可信配对的 Windows Host 与 Android 建立一次 fresh、双身份签名、带 key confirmation
的本地会话。
它负责产生唯一 `connection_id`、transcript-derived channel binding 以及按方向/消息类型隔离的
traffic keys。长期 P-256 身份 key 只签名，不参与静态 ECDH，也不直接作为 AES key。

本合同只冻结 canonical transcript、基础 KDF 和 Finished 的密码学字节合同；它尚未冻结首次配对消息、
生产 control record、generation 持久化服务或 raw lease 三步提交的完整 wire format。任何基础类或向量
通过都不能产生 production capability。

本合同不把客户端自报的 `formal_platform_tpm`、Android hardware-backed 字符串、IP、端口、
MAC、network handle 或静态 token 当作可信身份。远端 formal assurance 必须来自服务端自己保存的
SPKI/attestation 状态。已完全控制某端点进程的管理员仍可冒充该端当前会话角色；目标是阻止其伪造
另一端身份、服务端能力、旧会话、旧 epoch 或其他方向/type 的 traffic domain。

## 2. 角色与状态机

角色固定为：

- `HOST = 1`
- `ANDROID = 2`

已绑定 pair 的会话状态严格单向：

```text
discovered
  -> hello_exchanged
  -> transcript_signed
  -> peer_identity_verified
  -> ecdh_derived
  -> finished_confirmed
  -> lease_pending
  -> lease_installed
  -> active
  -> closed
```

首次配对使用独立的 `pairing_only` 状态。空 `pair_id` 的 transcript 即使完成身份签名、ECDH 和
Finished，也只能用于受可信 UI 约束的 QR/SAS 或服务端签名 bootstrap；不得进入 `lease_pending`，
不得安装 control/data-plane key，不得产生计费或模型 key capability。pair binding 在双方持久化后，
必须使用非空 `pair_id`、新 ephemeral key、新 nonce、新 `connection_id` 和新
`session_generation` 重新握手。

已经通过当前认证通道确认的签名、key confirmation、租约、counter、route 或版本冲突进入
`closed`。来自未认证网络的格式错误、错误 connection、错误源地址、错误 tag/Finished 或新 discover
只做统一、限速、无状态丢弃，不得抢占或关闭已有 active session。不得恢复旧 traffic key，不得回退
Android-only、plaintext、VFRG/VFRR、IDR1 或 VFMB。

## 3. P-256 公钥编码

握手 ephemeral key 固定使用 SEC1 uncompressed P-256：

```text
0x04 || X[32-byte big-endian] || Y[32-byte big-endian]
```

必须验证：长度恰为 65、首字节为 `0x04`、`0 <= X,Y < p`、点位于 secp256r1 曲线上、不是无穷点，
并拒绝 compressed/hybrid、尾随字节和其他曲线。生产 private scalar 必须由平台 CSPRNG/provider
生成且位于 `[1,n-1]`；固定 scalar 只允许存在于隔离测试入口。

Windows `BCRYPT_KDF_RAW_SECRET` 的 raw ECDH 输出按 little-endian 处理，必须恰好反转为 32-byte
big-endian；JCA ECDH 结果按 unsigned big-endian 左侧补零到 32 bytes，拒绝空值、负数语义和超过
32 bytes 的结果，不得删掉有意义的前导零。长期身份公钥只接受 canonical DER SPKI：
`id-ecPublicKey + namedCurve secp256r1`，拒绝显式曲线参数、尾随数据和非 P-256 key。

## 4. Canonical transcript

transcript 是按 tag 严格递增的 TLV 串；每项为：

```text
tag: u8 || length: u32 big-endian || value[length]
```

不得出现未知、重复、乱序、尾随或缺失字段。文本为严格 ASCII 合同值，不含 NUL。版本语法固定为
三段十进制 `MAJOR.MINOR.PATCH`；每段只能是 `0` 或不带前导零的正整数，禁止 `v` 前缀、空白、
prerelease 和 build metadata。`pair_id` 为空只表示 `pairing_only`，已绑定会话必须非空。

| tag | 字段 | 长度/约束 |
|---:|---|---|
| 0 | domain | ASCII `visionforge-peer-handshake-v1` |
| 1 | protocol_version | u32 BE，固定 1 |
| 2 | host_identity_spki_sha256 | 32 bytes；与 Android 角色不同 |
| 3 | android_identity_spki_sha256 | 32 bytes；与 Host 角色不同 |
| 4 | host_ephemeral_public_key | 65-byte SEC1 |
| 5 | android_ephemeral_public_key | 65-byte SEC1 |
| 6 | host_nonce | 32-byte uniform CSPRNG output；仅拒绝全零串 |
| 7 | android_nonce | 32-byte uniform CSPRNG output；仅拒绝全零串 |
| 8 | connection_id | non-zero u64 BE；Host CSPRNG 产生 |
| 9 | session_generation | non-zero u64 BE；同 pair 持久、原子、单调递增 |
| 10 | transport_kind | u8：CAT6=1，WLAN=2 |
| 11 | host_ipv4 | 4 network-order bytes；Host-owned A→H 目标地址 |
| 12 | android_ipv4 | 4 network-order bytes；Android-owned H→A 目标地址 |
| 13 | video_port | Android-owned H→A VFA2 UDP 接收端口，non-zero u16 BE |
| 14 | control_port | Host-owned A→H 控制/IDR 接收端口，non-zero u16 BE，且与 video port 不同 |
| 15 | pair_id | 0..64 ASCII `[A-Za-z0-9._:-]` |
| 16 | host_runtime_version | 1..32 ASCII stable SemVer |
| 17 | android_runtime_version | 1..32 ASCII stable SemVer |

`transcript_hash = SHA256(canonical_transcript)`。

消息顺序必须固定为 Host/Android Hello、类型化 transcript proposal、双方 identity signature、双方
Finished；完整 wire format 仍是本草案的 P1 阻断。每端只生成自己的 ephemeral key 和 nonce，并在
签名前从类型化字段本地重建完整 transcript；禁止让安全服务签署调用方提供的任意 bytes。双方必须
核对本端 nonce、ephemeral、地址、端口和版本与本地实际值完全一致。

`connection_id` 由 Host CSPRNG 产生，Android 必须拒绝当前或 recent-ID 冲突。`session_generation`
必须由服务器或专用 Host 安全服务按 pair 原子分配，服务器和两端维护 durable high-water mark；
并发、崩溃恢复、状态回滚、Android 重装或高水位不确定均 fail closed。当前仓库尚未实现该持久服务，
因此基础 transcript/KDF 不能用于 production。

双方长期身份分别对完整 `canonical_transcript` 执行一次且仅一次 SHA-256 后的 ECDSA，签名使用
canonical low-S DER。CNG 对 `SHA256(canonical_transcript)` 做 raw ECDSA；JCA 可对原 transcript 使用
`SHA256withECDSA`，不得再次哈希 digest。DER 必须 minimal、无尾随数据、`1 <= r,s < n` 且
`s <= n/2`，验签同样拒绝 high-S。

接收方必须用服务端/本地已绑定记录中的 expected peer SPKI 验签，并同时验证 exact canonical DER
SPKI 的 SHA-256 与 transcript 中对应角色 hash 相等；本地签名 key 也必须匹配本端角色 hash。
pair record 显式映射 `(pair_id, HOST, host_hash)` 与 `(pair_id, ANDROID, android_hash)`，两个角色不得
复用同一 SPKI/hash。不得从同一握手消息自行学习“可信公钥 + formal assurance”。

### 4.1 首次配对 bootstrap（尚未实现）

服务器签名的 pair-binding credential 至少绑定：独立 domain、protocol version、`pair_id`、用户/租户、
角色化 Host/Android SPKI hash、签发/过期时间、一次性 nonce、允许/最低两端版本及服务器 key id。
nonce 必须由服务器原子单次消费；客户端自报的 assurance 不进入授权结论。

若使用 SAS，SAS 必须由完整 pairing transcript hash、角色化的两个 identity hash 和独立 domain 派生，
并由用户在两端可信 UI 明确确认；确认结果不能由远端网络消息代替。QR/SAS 或 credential 成功后，
双方先持久化同一 binding，再关闭 pairing-only 会话并用非空 `pair_id` 全新握手。首次 bootstrap 的
wire、SAS 字数/熵、用户取消/超时与账户恢复尚未冻结，是 production blocker。

## 5. ECDH 与 HKDF-SHA256

双方验完长期身份签名后执行 fresh P-256 ECDH，得到规范化 32-byte big-endian shared secret。

```text
PRK = HKDF-Extract(
    salt = transcript_hash,
    IKM  = ecdh_shared_secret_be32
)
```

HKDF-Expand 的 info 是严格 ASCII label。每个输出独立派生，禁止截取同一输出后自行复用：

| label | 输出 |
|---|---:|
| `VFDUAL/PEER-HS/V1/control/host-to-android` | 36 bytes：AES key[32] + nonce prefix[4] |
| `VFDUAL/PEER-HS/V1/control/android-to-host` | 36 bytes：AES key[32] + nonce prefix[4] |
| `VFDUAL/PEER-HS/V1/presence/host-to-android` | 36 bytes：AES key[32] + nonce prefix[4] |
| `VFDUAL/PEER-HS/V1/video/host-to-android` | 36 bytes |
| `VFDUAL/PEER-HS/V1/idr/android-to-host` | 36 bytes |
| `VFDUAL/PEER-HS/V1/mouse/host-to-android` | 36 bytes |
| `VFDUAL/PEER-HS/V1/finished/host` | 32-byte HMAC key |
| `VFDUAL/PEER-HS/V1/finished/android` | 32-byte HMAC key |
| `VFDUAL/PEER-HS/V1/channel-binding-exporter` | 32 bytes |

36-byte 输出只允许安装到对应 direction/type；不得跨 direction/type 共享 key、prefix、counter 或
replay window。v1 暂不支持 session 内 rekey，初始 `key_epoch` 固定为 `1`；达到任一 key 的
`2^23` 包上限、provider/counter 状态不确定或需要 rekey 时，必须关闭并完成全新握手，不能递增一个
尚未定义的 epoch 继续使用。

ECDH private handle、raw shared secret、PRK、HKDF 临时缓冲和所有 session key 必须在各自生命周期
结束后立即销毁/尽力清零，且不得进入日志、bug report、crash metadata 或异常文本。

## 6. Finished 与 channel binding

双方发送：

```text
finished_mac = HMAC-SHA256(
    role_finished_key,
    "VFDUAL/PEER-HS/V1/finished-proof" || role_u8 || transcript_hash
)
```

比较必须 constant-time。双方 Finished 均成功后才进入 `finished_confirmed`。

基础 API 必须把该顺序做成不可误用的类型转换：ECDH 只产生不暴露任何 traffic/control material 的
pending key-confirmation owner；它固定本端 role，只允许生成本端 Finished、验证对端 Finished。只有
本端 Finished 已生成且对端 Finished 验证成功后，pending owner 才能被一次性消费为 confirmed session
key owner。失败、关闭、重复消费或 pairing-only transcript 均不得取得 key/cbh。

```text
channel_binding_sha256 = SHA256(
    "visionforge-peer-channel-binding-v1"
    || transcript_hash
    || channel_binding_exporter
)
```

该 32-byte 值以 64 位 lowercase hex 进入现有服务端 `cbh`，并由真实 Host 与 Android 对同一
usage canonical payload 分别签名。服务器只接受与本次 start/heartbeat/lease 完全一致的 `cbh`。

## 7. Control record（production blocker）

当前合同只派生 control key/prefix，尚未定义可生产使用的 control record；因此不得用这些裸 key
传输 raw lease、ack、关闭、替换或 rekey 命令。正式实现必须且只能选择一种经过独立审查的路径：

1. 定义自有 AEAD record，将独立 domain/version、`connection_id`、`session_generation`、
   `key_epoch`、direction、control message type、u64 counter 和 ciphertext length 全部放入 AAD；或
2. 使用禁用 0-RTT 的 TLS 1.3/QUIC 标准 record，并把双方已绑定 identity 与标准 exporter 绑定。

自有 record 必须使用 key[32] + prefix[4] 与 u64 BE counter 组成 AES-256-GCM nonce。每个方向只有一个
control key/prefix 和一个共享的 counter/replay domain；control message type 必须进入 AAD，禁止在同一
key/prefix 下为不同 type 各自从 counter 0 开始。tag 成功后才提交至少 1024-bit replay window，
provider 失败仍消耗 counter，单 key 最多 `2^23` 包。错误 tag、格式、tuple、duplicate/too-old 对网络
和上层状态机只表现为 generic unauthenticated drop，不得触发 rekey、teardown 或高成本日志。

两种路径不能同时保留为运行时 fallback。完成 control record、跨语言 mutation/replay tests 和正式
产物无明文 fallback 扫描前，`finished_confirmed` 后仍不能进入 `lease_pending`。

## 8. Raw lease 三步安装边界（production blocker）

Android 通过现有 pinned HTTPS 收到 exact raw ASCII lease 后，先自行严格验证，再通过已完成
Finished 的 control channel原样发送 bytes。Host 必须用 build-pinned 服务端公钥独立验证同一 raw
bytes、claims、`cbh`、pair、两身份 hash、session、seq/pth、nbf/exp、两端 exact runtime version、
正式 manifest hash、`connection_id` 和 `session_generation`。不得发送已解析 DTO 代替 raw token。
当前服务端 lease 尚未包含全部字段，因此不得接入 production。

安装协议固定为 `LEASE_OFFER(raw bytes) -> LEASE_ACCEPT -> LEASE_COMMIT`。三个认证消息都绑定
transcript hash、connection、generation、control epoch/counter、raw lease SHA-256、`jti/sid/seq`、
`pth/nbf/exp/cbh`、pair、两身份 hash、两端版本和正式 manifest hash。首 lease 的 previous hash 使用
32-byte zero genesis sentinel，且只能由服务端签名 claim 明确授权；两端独立维护 seq/pth 高水位并
检测同 seq 不同 digest 的 fork。重复消息只能幂等返回同一结果，不能重置 key/counter/lease 状态。

Android 验证 Host accept 后才安装接收 capability；Host 只有收到并验证 Android commit 后才允许发送
video/mouse。双方到达 `nbf`、保存同一 lease digest 且三步完成后才进入 active；任一步超时或状态分歧
均保持 gate closed。

租约过期、撤销、route change、进程恢复、Finished generation 变化或任何 key/counter 状态不确定时，
双方都必须关闭 video/IDR/mouse，清空输入状态并销毁当前 key。无租约时只允许当前握手会话的
authenticated presence probe。

## 9. 错误、route 与版本语义

- active session 不因未认证 discover/hello、malformed UDP、伪造源地址、错误 connection/tag/Finished
  而关闭；这些输入静默、统一、限速丢弃。pre-auth 必须有并发/每源速率/超时上限，必要时先使用
  stateless cookie，再分配 ECDH/签名状态。
- v1 不支持 route migration。CAT6/WLAN、IP、端口或 network handle 改变必须由当前认证 peer 确认后
  关闭旧会话，再建立全新 transcript/key；未经认证的“新 route”不能 teardown。
- runtime version 是签名自报字段，不是 measured-runtime 证明。服务端 start/heartbeat/lease 必须绑定
  两端 exact version、正式签名 manifest/hash、connection、generation、pair、身份 hash 与 `cbh`，
  两端执行服务器 minimum floor/allowlist。formal assurance 仍只来自服务端保存的注册/attestation。
- 所有外部失败统一为无敏感内容的结果；详细诊断只进入脱敏、限速的本地结构化日志。

## 10. 验证与 formal 条件

至少覆盖：完整 439-byte transcript/HKDF/Finished/channel-binding 跨语言向量；Host scalar 1 / Android
scalar 379 得到 `005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a`
的 leading-zero ECDH 向量；错误 identity/SPKI binding、非法 SEC1、ephemeral、nonce、role、connection、
generation、transport、endpoint、pair、SemVer；wrong Finished、role reflection、unknown-key-share、
wrong direction/type、cross-session、旧 generation、重复/乱序、key lifetime、provider failure counter burn。

集成测试还必须覆盖 generation 并发/崩溃/回滚、首次 pairing MITM/SAS、control record AAD/tag/replay、
lease offer/accept/commit 丢失/重复/fork、伪包不能 teardown、route 变化、服务器版本 floor、正式产物
扫描，以及 API29/真实 TPM/CAT6/PCAP 重放。

只有真实 Host/Android 调用链、raw lease 双端安装、VFA2 video/presence/IDR/mouse、无 plaintext
fallback、正式产物扫描和实体 API29/TPM/CAT6 证据全部完成后，才允许修改两个 formal implementation
flag。本合同或单元测试单独存在不能构成 formal proof。
