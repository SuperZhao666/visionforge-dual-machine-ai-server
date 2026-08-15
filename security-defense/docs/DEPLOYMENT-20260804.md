# 2026-08-04 腾讯云与生产主机安全加固记录

## 1. 范围与结论

本次变更以 `F:\逆向` 中已经实际使用或复现的静态分析、脱壳、补丁、抓包、重放、凭据提取、进程转储和部署材料搜集经验为攻击者视角，对 VisionForge 的腾讯云控制面、Linux 主机、Web 服务、签名密钥文件边界、日志保留、发布静态资源和运维入口进行生产加固。

权威生产对象不是 CVM，而是腾讯云轻量应用服务器：

- 实例：`lhins-4qvxagy6`，名称 `Ubuntu22.04-Docker26-c073`。
- 地域：北京，北京六区。
- 公网地址：`81.70.189.154`；内网地址：`10.2.0.6`。
- 系统：Ubuntu 22.04.5 LTS，4 vCPU / 4 GB，40 GB SSD 系统盘。
- 业务：`vf.service`、`vf-dual-machine.service`、Nginx。
- 域名：`visionforge.cloud`、`www.visionforge.cloud`。

本轮已经显著降低公网 SSH、Web RCE 后持久化、代码/静态资源替换、密文私钥文件替换、日志填满系统盘和危险管理路由造成的风险。它不等价于“客户端不可逆向”，也没有完成 KMS/HSM signer、设备 PoP、EdgeOne/WAF 源站隐藏或 CloudAudit 180 天长期投递。

## 2. 恢复点与审计证据

### 2.1 主机内回滚包

变更前 root-only 回滚包：

```text
/var/backups/visionforge-security/20260804T040040Z_pre_hardening
```

目录为 `0700 root:root`，文件为 `0600 root:root`。其中包含 SSH、Nginx、UFW、systemd、iptables、包清单、SQLite 在线备份、关键 journal 导出、各阶段旧文件、权限元数据和 `SHA256SUMS`。已写入的校验值均通过验证。

该目录只能处理同机配置和 SQLite 短时回退，不能抵抗系统盘损坏，也不能完整回滚内核、Docker 或软件包升级。

### 2.2 云盘恢复点

已创建并确认状态为“正常”的轻量实例系统盘快照：

```text
ID:   lhsnap-bdw98rnu
名称: vf-security-baseline-20260804-1458-cst
时间: 2026-08-04 14:59:16 CST
```

这是本轮主机加固完成后的安全基线快照，不是所有变更之前的原始镜像。回滚到该快照会丢失快照之后产生的数据库、订单、日志和发布数据，执行前必须另做 SQLite 在线备份并确认业务窗口。

### 2.3 腾讯云操作审计

CloudAudit 已记录本轮关键控制面事件，包括：

- `ConsoleLogin`；
- `StartAutoLoginSession`；
- `CreateInstanceSnapshot`；
- `DeleteFirewallRules`；
- `CreateFirewallRules`。

当前没有 CloudAudit 跟踪集。默认控制面记录仅保留近三个月；若要满足 180 天以上留存，需要创建跟踪集并投递到 COS 或 CLS。该操作会产生持续存储费用，本轮未在未获费用授权时创建。

## 3. 腾讯云边界变更

### 3.1 公网 SSH

原规则允许全部 IPv4 地址访问 TCP/22。短暂关闭该规则后，从主机安全历史告警确认 `vf-runner` 曾从固定来源 `101.82.186.252` 进行受控自动登录。最终规则为：

```text
来源: 101.82.186.252/32
协议: TCP
端口: 22
策略: 允许
备注: vf-runner 固定来源（强制 relay）
```

不再存在 `0.0.0.0/0 -> TCP/22`。管理员公网 SSH 默认不可用；管理回退使用腾讯云 OrcaTerm TAT 和 VNC。两条回退路径均已在控制台确认，TAT 已实际登录并在关闭公网 22 后验证可用。

主机内 `vf-runner` 仍由 key-level 强制 relay command、无 TTY、无转发约束；云防火墙 `/32` 只负责来源限制，不能替代账号级契约。

### 3.2 Web 与 ICMP

保留以下轻量防火墙规则：

- 全部 IPv4 -> TCP/80；
- 全部 IPv4 -> TCP/443；
- 全部 IPv6 -> TCP/443（实例当前未启用 IPv6）；
- 全部 IPv4 -> ICMP ALL。

源站仍由公网 EIP 直接承载，没有 EdgeOne/WAF/CDN 回源隔离。80/443 必须继续由 Nginx、应用限流、CrowdSec 和主机防火墙纵深保护。

### 3.3 主机安全结果

腾讯云主机安全基础版在线。控制台显示的 85 个风险全部属于历史“异常登录”：

- 来源：`101.82.186.252`，上海；
- 账号：`vf-runner`；
- 可见样本集中在 2026-08-01，约每分钟一次；
- 文件查杀、恶意文件、异常进程、密码破解、恶意请求、高危命令、本地提权和反弹 Shell 均为 0；
- 漏洞、基线和网络风险均为 0。

这些记录与受控 runner 账号相符，但本轮没有未经逐条审阅就批量标记“已处理”。若固定来源、runner owner 或业务用途改变，应删除云防火墙 `/32` 规则并撤销对应公钥。

## 4. 主机与服务加固

### 4.1 磁盘与日志容量

根盘初始 100% 使用、仅余约 235 MiB。已清理可重新下载或再生成的 APT 缓存、无引用 Docker builder cache 和悬空元数据；没有删除运行中容器、命名镜像、数据库、发布物或历史工作区备份。

当前根盘约 72% 使用、约 11 GB 可用。journald 已限制为：

```ini
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SystemMaxUse=512M
SystemKeepFree=3G
SystemMaxFileSize=64M
MaxRetentionSec=14day
SyncIntervalSec=5m
RateLimitIntervalSec=30s
RateLimitBurst=10000
```

journal 从约 2.1 GB 降至约 536 MiB；收缩前的关键安全服务日志已保存到回滚包。

### 4.2 上传日志保留执行器

原 `retention_days` 只保存策略，没有实际删除执行器。现已部署 `vf-log-retention.timer`，每日运行并具有 `Persistent=true`。保留服务：

- 按 `uploaded_at` 批处理；
- 先安全删除文件，再删除数据库行；
- 文件删除失败时保留数据库记录；
- 缺失文件可收敛数据库记录；
- 拒绝越界路径、symlink、非普通文件和存储根 identity 变化；
- dry-run 零副作用；
- 清理过期空会话；
- 只输出结构化、脱敏统计。

生产保留期由 30 天调整为 7 天。首次执行结果：

```text
候选 ZIP:       591
删除字节:       7,148,502,321
删除空旧会话:   131
错误:           0
执行后文件:     93（数据库与磁盘一致）
执行后字节:     2,307,975,174
```

删除的 591 个旧 ZIP 与 131 个空旧会话不可恢复；最近 7 天诊断包保留。SSH、auditd 和 CrowdSec 审计日志不在该目录，未被此策略删除。

### 4.3 应用树权限与 systemd 只读根

发现 `routes/`、`services/`、`repositories/`、`templates/`、`static/css` 等 12 个应用目录为 `0707`。因为 Nginx 位于可穿过上层目录的共享组，这些目录允许 Web 进程删除或替换 Python 模块，属于潜在持久化/RCE 放大器。

已保存 289 个节点的权限元数据到 root-only 回滚清单，并完成：

- `app/` 所有目录为 `0750`，组为 `visionforge-runtime`；
- 二维码图片目录为 setgid `2750`；
- 应用文件无组写和世界权限；
- 静态文件保留共享组读取；
- `www-data` 不可写 `routes/`、`services/` 或 `static/css`；
- Nginx 仍可读取全部 68 个静态文件；
- `vf-dual-machine` 仍可读取其运行代码。

`vf.service` 现在使用：

```ini
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
ReadOnlyPaths=/home/ubuntu/vf-platform
ReadWritePaths=/home/ubuntu/vf-platform/data
ReadWritePaths=/home/ubuntu/vf-platform/log_storage
ReadWritePaths=/home/ubuntu/vf-platform/app/static/img
```

生产挂载命名空间实测：

- 仓库根为 `ro,nosuid,relatime`；
- `data` 为嵌套 `rw,nosuid,relatime`；
- 仓库根、`app/services`、`owner_keys`、`static/releases`、`venv` 的 5 个创建文件探针均被拒绝；
- `data`、`log_storage`、`static/img`、`/home/ubuntu/server_logs` 的 4 个创建/删除探针均成功；
- 密文签名私钥仍可只读加载；
- `data` 与 `/home/ubuntu/server_logs` 均收紧为 `0700`。

配置曾因对尚不存在的 `runtime_artifacts` 目录执行 `test -d` 而触发自动回滚；确认原因后移除该错误探针并重新部署成功。父级只读挂载仍覆盖未来创建的该目录。

### 4.4 支付二维码与公开静态文件

`vf.service` 的 `UMask=0077` 会使新二维码临时文件成为 `0600`，导致 Nginx 403。现已在原子替换前显式设置 POSIX `0640`，目录使用 `visionforge-runtime` setgid 共享组。

生产验证：19 个二维码/教程图片全部可由 Nginx 读取、世界权限为 0，并通过公网 GET。权限设置失败时临时文件会在 `finally` 中清理，不会替换原图。

### 4.5 密文私钥文件边界

生产私钥材料没有被打印、复制、导出、重生成或轮换。加载器新增：

- `lstat` 拒绝 symlink；
- `O_NOFOLLOW`（可用时）；
- `fstat` 与 `(st_dev, st_ino)` identity 二次校验；
- 仅允许普通文件、单硬链接、最大 64 KiB；
- POSIX 下要求当前服务 UID 拥有且 group/other 权限为 0；
- `init_platform_keys()` 默认拒绝覆盖已存在密文 key；
- 部署脚本在已有 key 时只验证，不重新生成。

生产密文文件为 `0600 ubuntu:ubuntu`、单硬链接普通文件，加载预检与服务重启均成功。服务代码文件由 `0664` 收紧到 `0644`，随后应用树权限统一收紧为组只读。

这只是文件边界加固。Web 服务仍能读取解密密码和密文私钥，因此 Web RCE 仍等价于获得在线 RSA signer；最终方案必须迁移到独立 signer + KMS/Cloud HSM。

本地 `tools/keygen_gui/dist/owner_secrets/` 中仍存在一份不可在当前兼容期直接删除或轮换的未加密私钥。它已被 Git 忽略，但原 ACL 允许 `Authenticated Users: Modify` 和 `Users: ReadAndExecute`。本轮没有读取其内容，已将目录和文件 ACL 收紧为仅当前用户 `taoya`、SYSTEM 与本机 Administrators 三条显式 FullControl，并关闭继承。原 ACL 元数据备份位于：

```text
%LOCALAPPDATA%\VisionForge\security_acl_backups\20260804_owner_secrets\owner_secrets_acl.txt
```

ACL 只是紧急暴露面收敛，不能替代 key ring、过渡客户端和 KMS/HSM 轮换顺序。

### 4.6 SSH 与危险管理路由

OpenSSH 已拒绝 `ssh-rsa`/SHA-1，现有 RSA 管理公钥通过 `rsa-sha2-512` 验证继续可用。root、密码、键盘交互、X11 和 agent forwarding 均禁用。

危险的 `GET /admin/wx-qr` 已从服务端移除，并由 Nginx 精确返回 404。公开 `wx_login_qr.png` 已删除；该文件可重新生成但危险生成链路不应恢复。原路径曾包含 GET 状态变更、Docker restart、阻塞事件循环、第三方二维码服务和 bearer-like nonce 暴露。

## 5. 逆向经验到本轮控制的映射

| 已观察到的攻击经验 | 本轮控制 | 尚未解决的边界 |
|---|---|---|
| 从部署目录、备份、脚本和错误路径搜集私钥/密码 | 私钥 no-follow/owner/mode/hardlink/size/identity 门禁；仓库只读；root-only 备份 | Web 进程仍可在线解密并签名，必须迁 KMS/HSM signer |
| 修改 Python/静态文件实现持久化或钓鱼 | 清除 `0707`；共享组只读；systemd 仓库只读；Nginx 无写权限 | 部署仍使用通用 `ubuntu`，尚未拆 runtime/deploy 用户 |
| 抓取 URL、二维码、日志中的 bearer 材料 | 下线微信 QR 路由；Nginx query-redacted；禁 Uvicorn access log；日志脱敏 | 仍需系统性 SPKI pin、设备 PoP、ticket v2 |
| 重放旧凭据、旧目录、旧签名制品 | 现有短租约、版本 floor、签名更新；CloudAudit 留痕 | 仍缺完整 active/next/previous key ring 和 `kid` 选钥 |
| 通过公网 SSH、爆破和异常来源建立入口 | 云防火墙从全网 22 收敛到 runner `/32`；主机 key-only；CrowdSec | runner 来源变化需同步撤销；管理员应长期迁堡垒机/零信任 |
| 日志/转储填满磁盘使监控和服务失效 | journald 容量门禁；7 天上传日志执行器；磁盘从 100% 恢复 | `/home/ubuntu/server_logs/server.log` 仍需轮转或只写 journald |
| 利用可写公开静态树投放同源脚本/伪页面 | 应用树移除世界/组写；Nginx 共享组只读；公开写区仅 `static/img` | `static/img` 仍是同源通用公开目录，长期应迁到独立状态目录和精确 allowlist |

## 6. 验证结果

生产验证：

- `vf.service`、`vf-dual-machine.service`、Nginx active；
- 本机应用健康检查通过；
- 公网 HTTPS 首页 200；HTTP -> HTTPS 301；二维码 200；
- TLS 1.0/1.1 拒绝，TLS 1.2/1.3 可用；
- 危险微信 QR 路径和静态文件均为 404；
- 主服务只读/可写路径探针 5/5 与 4/4 通过；
- CloudAudit 可见本轮控制面事件；
- 快照状态为“正常”。

本地验证：

```text
主平台 tests/: 346 passed, 4 skipped, 45 subtests passed
支付二维码针对性: 20 passed, 2 skipped
本轮安全用例此前合计: 69 passed, 2 skipped, 4 subtests passed
Ruff: All checks passed
git diff --check: passed
```

仓库级 `pytest` 还收集了完全未跟踪的 `server/visionforge-platform/dual_machine_service/` 实验目录。该目录的新运行时 key 契约与自身 fixture 不同步，产生 82 failed / 36 errors；整目录均为用户未跟踪文件，本轮没有修改，也不计为本轮回归。

## 7. 不可恢复或有意保留的变更

不可恢复：

- 删除 591 个超过 7 天的旧日志 ZIP；
- 删除 131 个空旧会话；
- 删除旧 `wx_login_qr.png`；
- 清理约 4.089 GB 可再生成 Docker builder cache。

有意保留：

- 未删除历史 5.4 GB 工作区备份、运行中容器、命名镜像、数据库和发布物；
- 未重启到待用新内核；
- 未执行 Docker/containerd 大版本升级；
- 未修改 `ubuntu` 的重复 `NOPASSWD: ALL`，因为需要先完成专用账号和发布流程迁移；
- 未删除、移动或轮换生产签名 key；
- 未批量关闭 85 个历史异常登录告警；
- 未创建会产生持续费用的 CloudAudit 跟踪集、CLS/COS 长期投递或 EdgeOne/WAF。

## 8. 剩余优先级

### P0：签名根信任

1. 实现 `active/next/previous` key ring 和真正参与选钥的 `kid`。
2. 先发布同时信任旧/新 key 的过渡客户端。
3. 在腾讯云 KMS 或 Cloud HSM 生成不可导出的新 signer key。
4. 将 Web -> typed signer request -> 私网 mTLS/Unix socket -> 独立 signer -> KMS/HSM。
5. 切换签名、强制最低客户端版本、撤销旧会话，最后才移除旧公钥并清理泄漏材料。

在 key ring 和过渡客户端完成前，禁止直接删除、移动、重生成或轮换现有生产 key。

### P1：云边界与长期审计

1. 为 CloudAudit 创建 180 天以上 COS/CLS 跟踪集并配置访问/删除告警，需要费用授权。
2. 设计 EdgeOne/WAF/CLB 回源架构，源站仅接受可信回源；当前 EIP 仍可直达。
3. 将管理员操作迁移到独立 CAM 子用户、抗钓鱼 MFA 和最小权限角色，避免长期使用主账号 `root`。
4. 将 SSH 管理迁到堡垒机、VPN 或零信任；云防火墙只保留已验证 runner `/32`。
5. 为自动备份、异机恢复和恢复演练确定成本与 RPO/RTO；轻量系统盘页面没有原地 KMS 加密入口。

### P1：主机与服务隔离

1. 拆分 `vf-runtime` 与 `vf-deploy` 用户，消除应用与部署共用 `ubuntu`。
2. 迁移数据库、上传日志、二维码和应用日志到 `StateDirectory`、`LogsDirectory`、`RuntimeDirectory`。
3. 让仓库不再需要任何嵌套写例外，并升级到更严格的 `ProtectSystem`/`ProtectHome`。
4. 核对并启用 `vf_signing_keys`、`vf_secret_config` auditd 规则。
5. 为 `/home/ubuntu/server_logs/server.log` 配置轮转或迁到 journald。

### P2：应用与发布

1. 逐步移除 CSP 的 `script-src 'unsafe-inline'` 和 `style-src 'unsafe-inline'`，采用 nonce/hash。
2. 将支付二维码迁出通用同源静态树，Nginx 只允许固定命名规则。
3. 在创建云盘快照并安排维护窗口后，重启到已安装的新内核并验证 Docker 大版本升级。
4. 完成设备 PoP、SPKI active/backup pin、runtime ticket v2、目录反回滚和模型最小秘密下发。

## 9. 回滚入口

- 云盘级：腾讯云轻量实例快照 `lhsnap-bdw98rnu`。
- 主机配置级：`/var/backups/visionforge-security/20260804T040040Z_pre_hardening`。
- systemd 只读根旧文件：`vf-security.conf.before-read-only-root`。
- 应用权限旧清单：`app-permissions.before-runtime-group.json` 与 `restore-app-permissions.py`。
- 支付二维码旧代码与目录快照：`payment_qr_service.py.before-shared-group`、`payment_qr_img.before-shared-group.tar.gz`。
- 私钥加载器旧代码：`license_service.py.before-file-boundary`。

任何回滚都必须先验证目标文件 SHA-256、SQLite 在线备份和当前业务数据窗口；不得用 `git reset --hard`、整仓覆盖或重生成密钥代替精确回滚。
