# VisionForge Security Defense

该目录是生产服务器的独立蓝队防御工作区，与 `server/`、客户端运行时、QQ 机器人模块和业务数据完全隔离。

## 目标

- 公网只保留必要入口，内部服务仅监听回环或 Unix Socket。
- 互联网到 Nginx 使用 TLS 1.2/1.3；跨主机上游必须使用经校验的 TLS/mTLS。
- SSH 使用密钥、限制来源并关闭 root/密码登录；切换前必须验证回退会话。
- CrowdSec 是唯一动态封禁规则所有者；UFW 与 `DOCKER-USER` 只承担静态边界策略。
- 所有变更先备份、再校验并明确回滚边界；不得覆盖数据库、密钥、日志、发布文件或 QQ 机器人目录。
- 审计结果和运行态数据写入本目录的忽略目录，不进入业务仓库。

## 当前边界

```text
公网 80/443 -> Nginx -> 127.0.0.1:8000 -> FastAPI/SQLite
公网 22     -> OpenSSH（仅公钥；root、密码和键盘交互登录关闭）
本机 Docker -> QQ Steward（由另一任务维护；管理端口只允许 127.0.0.1）
```

本目录不会修改 `server/visionforge-platform/app/`、`.claude/worktrees/`、`vf.service` 主单元、生产数据库或机器人业务代码。

## 选型

- CrowdSec `v1.7.8`：日志行为检测、SSH/Web 攻击识别及统一封禁。
- Lynis `3.1.6`：无代理主机安全基线审计，用于变更前后对比。
- Nginx：保留现有边缘入口，不另建重复反向代理。
- Ubuntu 原生能力：安全更新、systemd 沙箱、journald/auditd、nftables/UFW 和自动证书续期。

Wazuh 仅在具备独立中心节点后安装 Agent；生产机不部署 Wazuh 全套。WAF 在真实流量观察和误报调优后再开启阻断。Trivy 因近期供应链事件不直接安装到生产机，若未来使用必须固定版本与摘要并验证签名。

## 实施顺序

1. `scripts/audit-host.sh` 只读采集系统、端口、补丁、SSH、Nginx、TLS、Docker 和备份状态。
2. 创建带时间戳的配置/数据库/密钥元数据备份并验证可读性；生产更新前另建腾讯云轻量实例系统盘快照或 CVM/云盘快照，备份内容不得进入 Git。
3. 修补系统与 OpenSSH；先安装公钥并保持第二条 SSH 会话，再关闭密码登录。当前首次加固执行了 Ubuntu 支持更新全集并单独保留 Docker 版本；后续无人值守仅应用安全更新。
4. 收敛腾讯云安全组和主机防火墙；验证 Docker 转发链不会绕过策略。
5. 安装 CrowdSec，先检测模式观察，再启用 firewall bouncer；Nginx AppSec 需通过兼容性检查。
6. 验证 TLS、业务接口、机器人容器、数据库完整性、日志、封禁和回滚路径。

## 标准受管安装入口

不得只把 drop-in 复制到仓库而不部署。在 `security-defense/` 目录中使用以下标准入口：

```bash
# 先以公钥建立并保持第二条 SSH 会话，两条会话都不要关闭。
sudo bash scripts/apply-ssh-hardening.sh \
  config/ssh/00-visionforge-security.conf \
  config/ssh/05-visionforge-crypto.conf
# reload 后从新终端再建公钥会话；成功前仍保留前两条会话。

sudo bash scripts/apply-journald-retention.sh \
  config/systemd/journald.conf.d/60-visionforge-retention.conf
```

SSH 入口在同一事务中备份并安装 `00-visionforge-security.conf` 与 `05-visionforge-crypto.conf`，执行 `sshd -t`、有效值检查和 `reload`；任一步失败都精确恢复这两个路径。journald 入口备份并安装 `60-visionforge-retention.conf`，通过 `systemd-analyze cat-config`、服务存活和容量检查后才成功。两个脚本都输出 `rollback_path`，可重复执行，不会在成功后留下待确认的临时文件。

详细边界见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，威胁与控制见 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)，发布门禁见 [docs/ROLLOUT.md](docs/ROLLOUT.md)，日常操作见 [docs/OPERATIONS.md](docs/OPERATIONS.md)，当前生产证据见 [docs/DEPLOYMENT-20260804.md](docs/DEPLOYMENT-20260804.md)。

## 凭据规则

本目录禁止保存 SSH 密码、GitHub Token、API Key、私钥或生产 `.env`。聊天中出现过的凭据必须轮换；GitHub 公共项目下载不需要 Token。

## 回滚边界

带时间戳备份可恢复 Nginx、SSH、systemd、journald、auditd、UFW/CrowdSec 配置和 SQLite 数据，但不能把已升级的 Ubuntu 软件包、内核或二进制整体降级。SSH 或 journald 安装失败时，脚本会按 `.state` 记录恢复原文件或删除本次新建的受管 drop-in，然后重新加载对应的原配置。journald 的应用和回滚都不执行 `journalctl --vacuum-*`、不删除 `/var/log/journal` 中的历史日志。系统级回退必须依赖变更前的腾讯云轻量实例系统盘快照或 CVM/云盘快照；同机 `/var/backups` 只用于短时配置与数据恢复，不算异机灾备。
