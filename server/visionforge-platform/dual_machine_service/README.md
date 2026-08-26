# VisionForge 双机卡密与计时 Sidecar

该目录是同一台腾讯云服务器上的独立扩展服务，不是原单机
`app.main` 的插件。它不导入单机账号、支付或租约模块，不使用
`data/vf.db`，也不注册到单机 FastAPI 路由。

## 用户权益计费语义

- 卡密激活、双端绑定、状态查询和正式启动 challenge 均不扣时。
- APP 始终处于自动待命状态，不提供手动开始/停止入口。只有检测到 Host
  的真实视频数据、Android 数据面预检完成，并且 Host 与 Android 的 P-256
  双签名、安全通道 transcript 摘要、运行就绪状态全部通过后，才自动请求
  并原子扣除第一个短租约。
- 正式开始携带的是“授权前帧计数基线”，允许为 0；首张付费 active
  票据签发前，视频、推理和控制数据面必须保持关闭。此后每次续租要求
  Host 与 Android 的计数都严格增长，否则不签发也不扣下一段。
- 默认每段 5 秒；余额不足 5 秒时只扣剩余秒数。
- 续租必须在当前租约到期前 2 秒窗口内完成，并再次验证双端签名、
  当前票据、前序票据摘要、通道摘要、撤销版本和双方帧进度。
- 提前取得的下一段票据使用 `nbf = current.exp`，在 `nbf` 前只能暂存，
  不能启用，因此不存在重叠计费。
- Host 停止推流、断网、崩溃或停止续租后不再扣费；客户端自动关闭数据面、
  结束正式会话并恢复待命。已签发的当前短租约最多 5 秒且不退款。
- APP 打开、卡密激活或后台状态查询都不得单独触发正式 start API；缺少
  已验证的 Host 真实视频时，QNN 准备与计费启动都必须保持关闭。
- 客户端在正式 start 发出前同时生成并双签一份不可变的 start-cancel 请求。
  停止与 start 并发时先关闭本地数据面，再精确重放该取消；服务端在同一写事务内
  线性化 start/cancel，取消先到则写入墓碑并阻止后续扣费，start 先到则只结束该次
  start 对应的会话。响应丢失后的重试复用原 ID、nonce 和双签名，不生成新请求。
- 已确认的取消保存双签名认证摘要与首次响应快照，因此管理员后续撤销、解绑或换绑
  不会使旧请求永久卡在停止中。取消首次延迟到换绑之后时，仅允许历史设备双签名结束
  自己旧 pair 的会话；无会话时还必须匹配原 start challenge 的 entitlement、pair、
  start ID 与通道摘要。该只减权路径不能触碰新 pair 会话，也不会新增任何扣费。

## 一机一码设备绑定语义

- 卡密首次激活后，当前绑定保存 Host 与 Android 的 P-256 身份公钥摘要，以及
  客户端可提供时的 `device_fingerprint`；原 Android 身份再次提交仍按原绑定处理。
- Android 卸载重装导致身份私钥轮换时，仅允许在 Host 身份保持不变，并且当前
  绑定与新请求都包含相同的非空 `device_fingerprint` 时，通过完整卡密证明、
  Host 旧身份签名和 Android 新身份签名重新绑定。指纹本身不是授权凭据。
- 身份轮换时缺少指纹、指纹不一致或 Host 身份改变，均在 challenge 阶段返回
  `license_bound_to_another_device`，不得新增 challenge、审计或改变授权状态；
  历史绑定仅保存 `{}` 时只保持原 Android 身份兼容，不允许据此轮换身份。
- 真正换机或更换 Host 必须先由管理员显式解绑。解绑会关闭当前绑定并作废待处理 challenge；
  随后的并发换机请求最多只有一个能够取得待确认 challenge，其余请求失败。
- 相同 `request_id` 与相同载荷的 challenge 重放返回原 challenge；相同确认的
  并发或延迟重放返回同一激活结果，不重复建授权、消费卡密或写激活审计。

## 独立安全边界

- 传统卡密认证，无用户名、密码或单机 bearer token。
- 卡密正文只在发卡 CLI 输出一次；数据库仅保存版本化 HMAC 摘要、
  尾号和含随机批次盐的派生引用。
- Host 与 Android 长期身份均为 P-256，激活和计时操作要求双端 PoP。
- 正式 start 前还需要 30 秒服务端 challenge，客户端自选 nonce 不能
  单独启动计费。
- Host/Android 最低客户端版本由 sidecar 独立配置，可在发现已知漏洞时
  立即阻止旧版本继续 start/续租；版本字段本身仍是客户端自报，不能替代
  代码签名、Android Key Attestation 或 Windows TPM/KSP 证明。
- 使用独立 RSA 3072+ 私钥签发 5 秒 data-plane 租约；租约绑定
  entitlement、pair、session、撤销版本、两端公钥指纹、安全通道
  transcript 摘要、序列和前序票据摘要。
- RSA 轮换时仅当前私钥签发新票，可通过
  `DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON` 暂存最多 3 把旧公钥，
  只用于验完在途前序票据；客户端也必须内置当前与上一把公钥。待最长
  心跳重试窗口结束后删除旧公钥；切换完成后在线服务必须移除旧私钥，
  旧私钥只允许保留在受控离线备份中。
- pair-generation credential 使用另一套独立 RSA 3072+ 签名身份，禁止与
  usage-ticket 密钥复用文件路径或实际 SPKI。当前私钥只签发新 credential；
  最多 2 把 previous 公钥用于在线轮换，最多 13 把 archived 公钥只用于验证
  不可变 journal 中的历史 token 并精确重放。首次签发、challenge 消费、
  generation 分配、签名后立即验证和 journal 写入位于同一写事务。
- 所有扣费、账本、会话状态和当前票据摘要位于同一个
  `BEGIN IMMEDIATE` 事务；相同请求重试返回同一票据，不重复扣费。
- Sidecar 在打开 SQLite 后、执行任何建表或 WAL 变更前拒绝包含非
  `dm_*` 表的数据库，即使误配文件被改名或通过链接指向单机库。
- 生产仅监听 `127.0.0.1:8010`；Nginx 必须覆盖
  `X-Forwarded-For` 为 `$remote_addr`。
- API 响应强制 `no-store`、TraceId、HSTS、`nosniff`、`DENY` frame、
  `no-referrer`、`same-site` 资源策略和最小化 `Permissions-Policy`；Nginx
  示例也固定使用 `always` 安全头，避免错误缓存、嵌入或跨站读取授权响应。

## 本地管理

真实环境变量写入独立的、权限为 `0600` 的
`/etc/visionforge-dual-machine/service.env`。初始化和发卡示例：

```bash
python -m dual_machine_service.admin_cli init-db
python -m dual_machine_service.admin_cli issue \
  --product day --quantity 20 --channel manual
```

发卡输出含明文卡密，只允许在受控终端读取一次，不应写入日志、聊天、
工单或源码仓库。可用命令：

- `revoke-batch`：默认只撤销批次中尚未激活的卡；仅在确认整批泄露或欺诈时，
  显式增加 `--revoke-activated-entitlements`，才会同时撤销已由该批次激活的
  entitlement；
- `revoke-entitlement`：立即增加撤销版本并停止该双机授权的续租；
- `entitlement`：读取脱敏余额和绑定摘要。

单机管理员登录后可从 `/admin/dual-machine-cards` 使用完整卡密生命周期页面。
网页只通过 loopback HMAC 桥访问本 sidecar，所有写操作同时要求管理员 Cookie
与 CSRF 校验，单机业务数据库不创建任何 `dm_*` 表。页面支持：

- 天卡、周卡、月卡、永久卡批量签发，以及批次/卡密修改、停用、恢复、归档、
  解除归档和受控 CSV 导出；
- 跨批次全局搜索记录 ID、批次、卡密末四位、状态、备注、授权 ID、设备码和
  公钥指纹；列表和审计不返回卡密正文、HMAC 摘要或派生引用；
- 管理查询前把已越过兑换截止时间的 `issued` 卡可靠归一化为 `expired`，同时
  作废未完成的激活 challenge；
- 已撤销 entitlement 可在来源卡密仍为已激活、来源批次重新启用后恢复；恢复
  不补时、不重复授予，剩余为零的计时授权仍保持 `exhausted`；
- 管理员解绑当前设备会结束活跃会话、作废待用 challenge、旋转随机 pair ID、
  清除当前签名公钥并增加撤销版本；余额不变，用户必须使用原卡密重新绑定。

## 腾讯云并行部署

新增工件位于：

- `deploy/vf-dual-machine.service`
- `deploy/vf-dual-machine.env.example`
- `deploy/bootstrap_dual_machine_sidecar.sh`
- `deploy/nginx/dual_machine_http.conf.example`
- `deploy/nginx/dual_machine_api_location.conf.example`

安装时创建专用系统用户 `vf-dual-machine`，独立数据目录、配置目录、
两套互不复用的 RSA-3072 密钥和 journal。usage-ticket 与 pair-generation
credential 的私钥、公钥均由首次部署脚本分别生成，归属专用系统用户且权限
固定为 `0600`；若任一目标密钥已存在，首次部署会拒绝覆盖。原 `vf.service`、
端口 8000、`app.main`、单机
数据库、支付回调和原路由均保持不变。Nginx 只新增
`/api/dual-machine/v1/` 到 `127.0.0.1:8010` 的精确分流。

部署前必须先运行：

```bash
python -m pytest -q dual_machine_service/tests
python -m pytest -q tests
```

部署后的健康检查仅从服务器本机执行：

```bash
curl -fsS http://127.0.0.1:8010/healthz
```

`/healthz` 不应经公网 Nginx 暴露。2026-07-26 已以独立
`vf-dual-machine.service` 部署到现有腾讯云服务器：仅监听
`127.0.0.1:8010`，公网只分流 `/api/dual-machine/v1/`，部署检查确认原
`vf.service` PID、端口 8000、首页状态和单机数据库均未变化。部署备份位于
`/var/backups/visionforge-dual-machine/20260726T124811Z`。

服务端上线不等于客户端已完成生产验收。Android Secure v2 peer、Host
生产 socket 生命周期、Host 本地配对向导和导出失败指引源码已接入；Host/APK
也已具备缺失或无效发布公钥、TLS SPKI pin 的构建门禁。Android APP
不提供人工开始入口，只有在重新确认当前 Host 真实视频和通道绑定后才会自动
调用正式 start API。在离线发布流程注入真实生产公钥/pin、完成正式签名构建
和 Host/Android 实体双机故障测试前，
不得宣称卡密已能阻止被完全修改的本机客户端绕过运行。
