# 双机卡密授权生命周期

本文记录双机卡密 challenge/confirmation 协议的业务语义和并发边界。服务端、Android 与 Host/C++ 必须遵守同一份 `activation_mode` 契约；任何一端新增模式或改变字段含义时，都必须同步修改三端 canonical payload golden vector、数据库约束和恢复测试。

权威实现位置：

- 服务端 canonical payload：`server/visionforge-platform/dual_machine_service/contracts.py`
- 服务端状态机：`server/visionforge-platform/dual_machine_service/card_service.py`
- 服务端原子持久化：`server/visionforge-platform/dual_machine_service/license_repository.py`
- Android canonical payload：`android_inference_benchmark/app/src/main/java/com/visionforge/inferencebenchmark/DualMachineUsageAuthorizationContract.java`
- Android challenge、确认与崩溃恢复：`DualMachineSidecarHttpClient.java`、`DualMachineCardAuthorizationCoordinator.java`、`DualMachineAuthorizationRuntime.java`
- Android 待确认加密存储：`AndroidPendingActivationStore.java`
- Host/C++ canonical payload：`dual_machine_runtime/shared/src/usage_authorization_contract.cpp`

## 1. 模式与 target 契约

| `activation_mode` | `target_entitlement_id` | 业务含义 | 成功响应 |
|---|---|---|---|
| `activate` | 必须为空 | 新卡首次为该 `pair_id` 创建授权 | `binding_updated=false`，按卡种增加新周期额度 |
| `reactivate` | 必须是非零 32 位小写十六进制 | 同一 `pair_id` 的旧时长授权完全耗尽后，用一张新卡替换授权周期 | 保留 entitlement ID，`binding_updated=false`，按新卡建立新周期额度 |
| `bind_device` | 必须是非零 32 位小写十六进制 | 已激活卡的服务端定向设备绑定流程 | `binding_updated=true`，`credited_seconds=0`，不得增加额度 |

非法组合必须在签名或业务状态改变之前拒绝：

- `activate` 携带非空 target。
- `reactivate` 或 `bind_device` 缺少 target。
- target 为全零、包含大写/非十六进制字符或长度不是 32。
- 未知 `activation_mode`。

## 2. Challenge 与双端证明

激活请求包含服务端支持的协议版本、非零 32 位小写十六进制 `request_id` 与 `pair_id`、卡密、Host/Android P-256 公钥、设备码、客户端版本和 Android 设备画像。Host 与 Android 身份必须不同。

服务端在 `BEGIN IMMEDIATE` 事务中选择卡密和模式，保存 challenge 后返回：

- `activation_mode` 与 `target_entitlement_id`。
- challenge ID、短期 token 与过期时间。
- Host/Android 身份指纹和双方必须签名的 canonical payload。

canonical payload 同时绑定：协议版本、request/pair/challenge、模式、target、challenge token 的 SHA-256、Host/Android 公钥指纹、设备码、客户端版本以及 Android 设备画像 SHA-256。Host 和 Android 必须分别使用 challenge 中声明的身份私钥签署完全相同的字节序列。

Android 在网络响应可能丢失时，只持久化同一 confirmation 所需的数据；challenge token 和已生成签名必须由 AndroidKeyStore AES-256-GCM 封装。恢复时必须完整保留 `activation_mode` 与 target，禁止把 `reactivate` 降级成 `activate` 或重新创建第二个 challenge。

## 3. 三种状态迁移

### 3.1 `activate`

仅当卡仍为可用、未过期、产品启用，而且该 `pair_id` 尚无 entitlement 时创建新授权。服务端消费卡、消费 challenge、创建 activation 与当前设备绑定；任一步失败都回滚整个事务。

### 3.2 `reactivate`

仅允许同一 `pair_id` 的既有时长 entitlement 满足全部条件时执行：

- `status=exhausted`。
- `remaining_seconds=0`。
- `total_consumed_seconds=total_credited_seconds`。
- 不存在 active usage session。
- challenge 中的 target 精确等于该 entitlement ID。
- 当前 Android 公钥指纹和设备画像与既有当前绑定一致；显式未绑定的历史记录除外。

确认事务会再次读取 challenge、卡、entitlement 和当前 Android 绑定，关闭 challenge 创建到 confirmation 之间的 TOCTOU 窗口。成功后：

- 保留原 entitlement ID，因而保留历史 usage 外键归属。
- `remaining_seconds` 与 `total_credited_seconds` 设置为新卡额度。
- `total_consumed_seconds` 归零，状态恢复为 active。
- authorization kind、product 与 source card 切换到新卡。
- `revocation_version` 递增，使旧客户端快照和旧租约失效。
- 写入新的当前设备绑定，再原子消费新卡与 challenge。

批次撤销等管理员操作必须以 entitlement 当前的 `source_license_code_id` 判断授权归属，不能按历史 `dm_license_activations` 关联撤销。历史 activation 只用于审计；否则撤销已经耗尽的旧批次会误伤由新批次续期的当前授权。旧库中 source 尚为空时，才允许回退到历史 activation 归属。

`reactivate` 不是设备换绑。Android 身份或画像不匹配时必须返回 `license_bound_to_another_device`，不得消费卡、challenge 或修改 entitlement。

### 3.3 `bind_device`

该模式由服务端针对已经激活且未撤销的卡定向返回。target 必须是该卡原 activation 所属 entitlement。Android 当前身份仍必须与现有绑定相同或处于显式未绑定状态；它不能被用来把已知 entitlement 劫持到另一台 Android。

确认成功后更新 Host/Android 绑定并递增 `revocation_version`，使旧租约失效；所有未使用的 usage-start challenge 被置为 expired，仍 active 的 usage session 以 `device_rebound` 结束。该模式绝不增加额度。

## 4. 幂等、并发与失败语义

- 同一 `request_id` 仅可复用完全相同的 request payload；卡、模式或任一签名绑定字段变化必须返回 conflict。
- confirmation 在事务外做一次快速验签，并在 `BEGIN IMMEDIATE` 后重新读取和验签；业务写入只发生在第二次验证之后。
- 首次成功 confirmation 原子完成 entitlement/binding 更新、卡消费、challenge 消费、activation 与审计事件写入。
- 同一已消费 challenge 携带相同 token 和双端签名重放时返回原模式对应的成功语义，不再次扣卡或增加额度。
- token 错误、签名错误、challenge 未知/过期或模式-target 合同不合法时，不得产生任何部分状态。
- `reactivate` 的 entitlement 状态、计数、活跃 session 或 Android 绑定在 challenge 后变化时，confirmation 必须失败并完整回滚。

## 5. 当前正式发布边界

上述生命周期解决的是卡密、授权周期、设备绑定与 confirmation 幂等性，不等于完成正式双机信任链。新 activation/reactivation/bind_device confirmation 会在同一写事务内重新验证 Host 与 Android 两份 P-256 签名，再用私有 proof capability 创建或推进 pair security state；管理员解绑会把仍有效的旧 pair 降为 `recovery_pending`，管理员撤销会把它锁成 `revoked`，换机成功后旧 pair 为 `rotated`、新 pair 为 `active`。

服务端现已注册 pair-generation challenge/credential 两个公开路由并接入生产密钥装配。challenge 和最终 credential 请求分别要求当前绑定的 Host 与 Android P-256 双签；服务端严格重解析 canonical proposal，自行推导 proposal SHA-256、server nonce commitment 与 connection authority，并在同一个 `BEGIN IMMEDIATE` 中重新核对 live entitlement/pair/binding/revocation/identity tuple，完成 challenge 消费、generation allocation、RSA-3072 签名、立即回验、不可变 journal 写入和 read-back。精确重试返回原 token 字节；当前、最多两把 previous 与最多十三把 archived 公钥组成最多十六把的 journal 验证闭包。部署脚本生成与 usage-ticket 完全独立的 pair-credential RSA 密钥，实际 SPKI 复用也会被启动门禁拒绝。

Host 与 Android 在正式握手前仍未共同验证该 credential，签名 proposal 的端点 tuple 也尚未由 network-attempt coordinator 绑定到实际 socket/direct-link 尝试。因此 `authoritative_service_wired=true`、`public_route_registered=true` 不能升级成 formal ready。正式发布必须继续 fail closed，直到双端 operation-boundary verifier、真实连接绑定、短租约、channel binding、认证数据面和发布产物证据形成完整闭包。不得使用客户端自报布尔值、公开 `pair_id`、调用方自报 proposal hash 或静态 readiness 字符串替代该凭据。

## 6. 最低回归矩阵

- Python：三种 mode 的 canonical payload 正例和所有 mode-target 负例；challenge/confirmation 幂等、并发、TOCTOU、活跃 session 与 Android 绑定变化。
- 数据库：历史 `activate + target` 迁移为 `reactivate + target`；新 CHECK 约束；子外键、索引和回滚保持。
- Android：challenge/response 解析、pending confirmation 崩溃恢复，以及 AndroidKeyStore 加密存储中的 `reactivate + target` 精确往返。
- C++：三种 mode 的 canonical JSON golden vector和空值、全零、大写、非法字符负例。
- 集成：丢失首次 confirmation 响应后重发同一 proof，不得创建第二个 challenge、重复消费卡或重复增加额度。
