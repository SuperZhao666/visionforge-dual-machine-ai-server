# 安全运维手册

## 日常检查

每次系统、Docker、Nginx 或 QQ 模块维护后至少检查：

```bash
systemctl is-active ssh nginx vf docker auditd crowdsec crowdsec-firewall-bouncer ufw visionforge-docker-firewall
systemctl is-active systemd-journald
sudo ufw status verbose
sudo iptables -L DOCKER-USER -n --line-numbers
sudo cscli metrics show acquisition parsers
sudo cscli bouncers list
sudo nginx -t
sudo sshd -t
sudo systemd-analyze cat-config systemd/journald.conf
sudo journalctl --disk-usage
docker ps
```

预期公网仅有 TCP 22/80/443；`vf`、NapCat、AstrBot 分别只监听 `127.0.0.1:8000/6099/6185`。`qq-steward_default` 不得删除或重建。

## SSH 与 journald 标准变更

一律通过受管脚本部署，不得手工只复制其中一个文件。在 `security-defense/` 目录执行：

```bash
# 先以公钥建立并保持第二条会话，两条会话都不要关闭。
sudo bash scripts/apply-ssh-hardening.sh \
  config/ssh/00-visionforge-security.conf \
  config/ssh/05-visionforge-crypto.conf

sudo bash scripts/apply-journald-retention.sh \
  config/systemd/journald.conf.d/60-visionforge-retention.conf
```

SSH 成功标准是 `sshd -t` 通过、`ssh` 仍为 active，且 `sshd -T -C user=ubuntu,host=localhost,addr=127.0.0.1` 的 `pubkeyacceptedalgorithms` 列表不含独立的 `ssh-rsa` 或 `ssh-rsa-cert-v01@openssh.com`；`rsa-sha2-256/512` 仍可使用。必须在脚本执行前已用公钥建立第二条会话并保留；reload 后再从新终端建立公钥会话，该验证成功前不得关闭前两条会话。

journald 成功标准是 `systemd-analyze cat-config systemd/journald.conf` 显示 `/etc/systemd/journald.conf.d/60-visionforge-retention.conf` 且关键值为 `SystemMaxUse=512M`、`SystemKeepFree=3G`、`SystemMaxFileSize=64M`、`MaxRetentionSec=14day`，`systemd-journald` 为 active，`journalctl --disk-usage` 和日志所在文件系统容量检查成功。安装脚本可幂等重复执行，不执行 vacuum，不主动删除历史日志。

两个脚本都会先备份并输出 `rollback_path`。安装、语法/有效值、reload/restart、active 或容量检查任一失败时，会自动仅恢复本脚本管理的路径：SSH 同时恢复 `00-visionforge-security.conf` 和 `05-visionforge-crypto.conf` 并在 `sshd -t` 通过后 reload；journald 恢复 `60-visionforge-retention.conf` 并 restart。如果自动回滚报告 `*-rollback-incomplete`，保持当前 SSH 会话，根据备份目录中的 `.state` 恢复原文件（`present` 时复制备份，`absent` 时只删除该受管 drop-in），再执行对应的语法检查和 reload/restart。手工回滚 journald 也禁止使用 `journalctl --vacuum-*` 或删除 `/var/log/journal`。

## 版本更新

- Ubuntu 无人值守更新只跟随 `jammy-security`，自动重启关闭；维护窗口人工确认 `/var/run/reboot-required`。
- Docker、CrowdSec `1.7.8` 和 nftables bouncer `0.0.34` 当前被 hold。升级必须先阅读官方安全公告，更新固定版本、完整 GPG 指纹和 SHA-256，再在短时自动回滚门禁下上线。
- CrowdSec 默认与 Central API 交换社区威胁情报，但本机未注册 CrowdSec Console。合规环境如需禁止此外连，应作为独立变更评审。
- 不直接在生产机安装 `latest`、未经签名的脚本或高负载扫描器；不得执行 `curl | bash`。

## 误封与故障

优先只停执行层、保留检测证据：

```bash
sudo systemctl disable --now crowdsec-firewall-bouncer
sudo cscli bouncers list
sudo cscli decisions list
```

恢复时只删除已确认的单个错误 decision，不使用 `decisions delete --all`。管理员来源变化后先更新 `admin-access` allowlist，再切换网络出口。不得整体 `nft flush ruleset`、`iptables -F`、`ufw reset` 或恢复包含 Docker 动态链的整份规则快照。

## 凭据与日志

- Nginx 访问日志不记录查询串或 Referer；`/appPush` 因旧协议把签名放在查询串中，精确 location 关闭 Nginx access/error log，由应用层完成验签、限流和脱敏业务日志。
- 长期根治方案是把支付回调迁移到 POST body 或签名 Header，并在迁移兼容期结束后删除 GET 查询签名协议。
- 聊天、工单或日志中出现过的 PAT、密码、API Key 必须从其发行平台撤销并重建，不能只依赖文件权限。

## 备份与恢复

`/var/backups/visionforge-security` 只用于同机配置/SQLite 短时回退，不是灾备，也不能回滚 Ubuntu 软件包和内核。生产必须另行启用腾讯云轻量实例系统盘快照或 CVM/云盘快照，或启用加密 COS 异机备份，并定期做隔离恢复演练。
