# 生产发布门禁与回滚

## 变更前必须满足

- 另一任务的 QQ Steward 部署已结束，并记录容器、回环端口和 Docker 网络。
- 至少有两条独立管理通道：已验证的新 SSH 公钥会话，以及已实际测试的腾讯云控制台/VNC 回退。
- 记录系统、软件包、监听端口、Nginx、Docker、防火墙和 systemd 当前状态。
- SQLite 在线备份通过 `PRAGMA integrity_check`；关键配置有权限受限的带时间戳备份。
- 业务主页、OpenAPI、关键未授权响应和机器人健康检查形成基线。

## 分阶段门禁

1. 更新阶段：首次基线修复可在评审后应用 Ubuntu 支持更新全集，同时单独 hold Docker；后续无人值守仅应用 `jammy-security`。重启前检查服务和维护窗口。
2. SSH 阶段：先追加公钥，以公钥建立并保持第二条会话，旧会话也保持打开；通过 `scripts/apply-ssh-hardening.sh config/ssh/00-visionforge-security.conf config/ssh/05-visionforge-crypto.conf` 在同一事务安装访问与密码算法两个 drop-in；reload 后必须从新终端再建公钥会话，成功前不得关闭前两条会话。
3. 防火墙阶段：先添加明确允许规则，再设置默认拒绝；同时检查 Docker 转发路径。
4. CrowdSec 阶段：先检测、后封禁；先 SSH/已知恶意来源，再逐步开启 Web/AppSec。
5. systemd 阶段：使用 drop-in 小步添加沙箱项，每次都验证服务启动和写目录。
6. journald 阶段：通过 `scripts/apply-journald-retention.sh config/systemd/journald.conf.d/60-visionforge-retention.conf` 安装容量与保留策略；不手工复制配置，不执行 vacuum 或删除任何历史日志。

## 每阶段验证

- `sshd -t`、`nginx -t`、systemd 单元校验通过；`sshd -T -C user=ubuntu,host=localhost,addr=127.0.0.1` 的有效 `PubkeyAcceptedAlgorithms` 不含 SHA-1 `ssh-rsa` 或 `ssh-rsa-cert-v01@openssh.com`。
- 旧 SSH 会话保持打开，新密钥会话可登录。
- 公网只有预期端口；HTTP 跳转 HTTPS；TLS 1.0/1.1 拒绝、1.2/1.3 成功。
- `vf.service`、主页、关键 API 合约、数据库完整性与 QQ Steward 均正常。
- CrowdSec 指标、日志采集和 bouncer 状态正常，白名单未误伤管理地址。
- `systemd-analyze cat-config systemd/journald.conf` 显示受管 drop-in 及 `SystemMaxUse=512M`、`SystemKeepFree=3G`、`MaxRetentionSec=14day`；`systemd-journald` 为 active，`journalctl --disk-usage` 与文件系统可用容量检查成功。

## 回滚

- 每次只回滚本阶段，不覆盖业务树。
- SSH/Nginx/systemd 配置从带时间戳备份恢复后先做语法校验，再 reload。SSH 脚本的自动回滚会按 `security-config.state` 和 `crypto-config.state` 同时恢复或移除两个受管 drop-in，不留下半套配置。
- journald 脚本使用 `managed-config.state` 精确恢复原 `60-visionforge-retention.conf` 或移除本次新建文件，再 restart 并检查 active。自动与手工回滚都不得执行 `journalctl --vacuum-*`、`rm -rf /var/log/journal` 或任何历史日志删除。
- 防火墙保留控制台回退脚本和自动超时恢复机制。
- CrowdSec 可先停 bouncer、保留 Engine 观察，避免为恢复业务丢失证据。
- auditd、CrowdSec 等新软件的卸载只能回退其配置和执行层，不能保证依赖包与系统二进制恢复到旧状态。
- `/var/backups/visionforge-security` 和 SQLite 在线副本是配置/数据回退证据，不是操作系统镜像；内核及全量包升级必须依赖变更前腾讯云轻量实例系统盘快照或 CVM/云盘快照才能完整回退。
