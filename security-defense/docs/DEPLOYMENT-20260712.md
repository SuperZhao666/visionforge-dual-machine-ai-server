# 2026-07-12 生产安全加固记录

## 结果摘要

- Ubuntu 22.04.5 已完成支持更新全集，Docker 六个包单独 hold；运行内核为 `5.15.0-185-generic`，无需再次重启。
- OpenSSH 为 Ubuntu `8.9p1-3ubuntu0.15`：仅公钥、禁止 root/密码/键盘交互、仅允许 `ubuntu`、TCP 转发仅限本地用途。
- UFW 为 `deny incoming / allow outgoing / deny routed`；公网仅 TCP 22/80/443。`DOCKER-USER` 在公网接口先允许已建立返回流量，再拒绝所有新建转发。
- CrowdSec Engine `1.7.8` 与 nftables bouncer `0.0.34` 固定版本并 hold；本地 API 仅监听 `127.0.0.1:8080`，管理员来源已加入 allowlist。
- CrowdSec 采集 SSH、Nginx access、syslog、kernel 与 auditd；TEST-NET 地址完成 decision 加入、nft 命中、精确删除和消失验证。
- Nginx 仅允许 TLS 1.2/1.3，启用 HSTS、CSP、请求 ID、限速/连接限制和默认 444；未知 Host 不进入业务。
- Nginx 日志不记录查询串或 Referer；历史日志中 20 条 `/appPush` 查询串已原位脱敏，没有复制敏感内容。该回调精确 location 关闭 Nginx access/error log，应用层继续验签、限流和脱敏业务日志。
- `vf.service` 通过 systemd drop-in 收敛权限，安全评分从 9.2/UNSAFE 降至 4.0/OK；应用、数据库与机器人代码未改动。
- SQLite、签名密钥和日志目录权限已收敛；数据库 `PRAGMA integrity_check=ok`。
- auditd、内核网络/进程保护、无人值守安全更新已启用；root 账户已锁定，Apport/自动崩溃转发关闭，`fs.suid_dumpable=0`。

## 外部与重启验证

- 公网 TCP 22/80/443 可达；6099/6185/8000 不可达；UDP 123 无响应。
- `https://www.visionforge.cloud/` 返回 200，HTTP 返回 301 到 HTTPS；TLS 1.0 拒绝，1.2/1.3 成功。
- Let’s Encrypt 证书有效期为 2026-07-06 至 2026-10-04，`certbot.timer` active/enabled。
- 主机启动时间：2026-07-12 22:58:52 CST。重启后所有安全服务 active/enabled，systemd 无 failed unit。
- `vf-qq-napcat` 与 `vf-qq-steward` 均 healthy，仍仅绑定 `127.0.0.1:6099/6185`，并保留 `qq-steward_default`；AstrBot SSH 隧道返回 200。
- 已向 QQ 模块任务回传准确重启时间线；安全任务未修改、重建容器或 Docker 网络，且不会再执行重启。

## 备份与审计证据

- 变更前根权限备份：`/var/backups/visionforge-security/security-20260712T135350Z`，校验和已复核；SQLite 在线备份完整性通过。
- 每个 SSH、Nginx、systemd、sysctl、auditd、UFW、CrowdSec、root/Apport 变更另有带时间戳备份。
- 完整 Lynis `3.1.6` 扫描硬化指数为 72、1 个 warning、44 个 suggestions；唯一 warning 是 root 当时为 `NP`，扫描后已改为 `L` 并验证公钥 SSH/sudo 正常。
- 原始主机审计与 Lynis 报告保存在本目录的忽略目录 `reports/`，不会进入业务仓库。

本地备份只能恢复配置和数据，不能回滚已升级的内核/软件包，也不能防止云盘整体损坏。完整系统回退必须依赖腾讯云 CVM/云盘快照。

## 有意保留的兼容例外

- `net.ipv4.ip_forward=1` 与 loose `rp_filter=2` 为腾讯云/Docker 路由所需，不能机械套用单机 CIS 值。
- `AllowTcpForwarding local` 为回环管理端口的 SSH 隧道所需；外部仍无法直接访问 6099/6185。
- 现有 UI 仍需要 CSP 的 `unsafe-inline`；移除它需要业务前端改为 nonce/hash，不能在边缘配置中强删。
- 未安装 Nginx Lua/AppSec：Ubuntu 22 默认 Nginx 的 Lua 兼容路径会扩大生产变更面。当前使用日志行为检测与主机防火墙，不把它误称为完整实时 WAF。
- 未在 3.3 GiB 主机部署 Wazuh Manager、SafeLine、Suricata 全流量检测或全盘高负载扫描；Wazuh Agent 需先有独立 Manager。
- 未安装 Trivy；未来使用必须在供应链事件处置后重新评审、固定版本并验证签名/摘要。

## 仍需账户所有者完成

1. 立即撤销聊天中暴露的 GitHub PAT，创建最小权限新 Token；本次公共项目下载未使用该 PAT。
2. 通过腾讯云控制台或当前公钥会话修改已暴露的 `ubuntu` 密码；SSH 密码登录虽已关闭，但控制台凭据仍应轮换。
3. 在腾讯云安全组把 22 收窄到固定管理 IP、VPN 或堡垒机；保留 80/443 公网。
4. 创建加密 CVM/云盘快照，并配置 KMS/COS 异机加密备份及恢复演练。
5. 将 `/appPush` 迁移到 POST body 或签名 Header；兼容期结束后删除 GET 查询签名协议。

## 选型依据

- [CrowdSec 官方仓库与发布](https://github.com/crowdsecurity/crowdsec)、[Linux 安装](https://docs.crowdsec.net/u/getting_started/installation/linux/)、[firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall/)
- [Lynis 官方仓库](https://github.com/CISOfy/lynis)
- [Docker 防火墙与 UFW](https://docs.docker.com/engine/network/packet-filtering-firewalls/)、[DOCKER-USER](https://docs.docker.com/engine/network/firewall-iptables/)
- [Nginx HTTPS 配置](https://nginx.org/en/docs/http/configuring_https_servers.html)
- [Trivy 供应链安全公告](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
