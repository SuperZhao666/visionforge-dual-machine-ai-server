# VisionForge CAT6 点对点网络调优验收

> Current migration note (2026-07-27): this network tuning record contains historical 320x320 application throughput measurements. The current model and host capture contract is 416x416; new CAT6 throughput must be re-measured once the wired link is physically restored.

验收日期：2026-07-23  
Windows 主机：暗影精灵 8 Pro  
手机：小米 14 Pro + RTL8153 USB 千兆网卡（未 root）

本文按“改动清单 → 验收表 → 失败项原因 → 回滚步骤”记录。状态只依据已归档实测，不把程序内部质量探针当成独立网络压测。

## 1. 拓扑与隔离目标

```text
Windows 默认上网：WLAN -> 192.168.1.1
Android 默认上网：wlan0 -> 192.168.1.1

VisionForge 数据面：10.57.23.1/24 <-> 10.57.23.2/24
                   CAT6 + RTL8153，MTU 1500，无网关、无 DNS
```

WiFi/WLAN 仅保留日常互联网连接。生产视频、探针、手机公告和 IDR 恢复均绑定 CAT6 固定地址；有线不可用时明确失败，不回退无线视频链路。

## 2. 改动清单

### 2.1 Windows 有线接口

1. CAT6 接口固定 `10.57.23.1/24`，不配置默认网关或 DNS；
2. IPv4 forwarding、WeakHostSend、WeakHostReceive、NetBIOS 关闭；
3. 关闭该接口上的 Microsoft 客户端/文件共享、LLDP/LLTD、QoS、VMware Bridge 等非必要绑定；
4. 保留 IPv4、IPv6 与 MTU 1500，不改 WLAN 配置；
5. Host 视频、探针与监听套接字显式绑定 `10.57.23.1`，避免依赖系统自动选路。

这些本机级变更已有备份。正式 Host 的自动能力只应管理自身直连地址、隔离 DHCP 和程序专属防火墙规则；不能在未知用户机器上静默套用本机的全部协议裁剪。

### 2.1.1 Host 自动配置的事务与恢复边界

Host 自动配置在修改选中的物理以太网接口前，会先写入
`%LOCALAPPDATA%\VisionForge\DualMachine\host-direct-link-restore-v1.conf`。
快照包含接口 GUID、InterfaceIndex、原地址模式、IPv4 DNS 和被修改的
IPv4 接口策略，并附带 SHA-256 完整性值。地址、DNS、接口策略三步按事务
执行；任一步或最终就绪校验失败，立即使用快照回滚。快照校验或回滚时都
必须再次确认目标仍是同一个物理 Ethernet、没有默认网关，WiFi/WLAN
不在允许目标内。

自动变更只覆盖两类可精确恢复的初始状态：默认 DHCP 接口，以及原来作为
ICS private 端的 `192.168.137.1/24` 接口。其他未知静态地址不会被自动
覆盖。若接口在启动前已经由用户正确配置为 `10.57.23.1/24`，Host 只读
复用，不生成“由 Host 所有”的恢复快照。

GUI 正常关闭时先停止视频、质量监视和隔离 DHCP，再对尚未清理的 Host
快照执行窄范围恢复；非管理员进程只为该恢复 worker 请求 UAC。异常退出
时快照保留，下一次正常关闭仍可恢复。运行中连续心跳失败达到不可达判据
后，Host 先停止 UDP 视频发布，再重新执行固定 CAT6 bootstrap（接口、
防火墙、DHCP、手机就绪心跳），成功后才重启采集/编码；始终没有 WiFi
视频回退。Host JSONL 的每条事件同时写入本次进程 `trace_id` 和实际运行
EXE 的 `build_sha256`，网络快照事件另带快照 SHA-256，便于把恢复证据绑定
到具体二进制和配置事务。

### 2.2 手机有线接口

- `eth0` 通过隔离 DHCP 获得 `10.57.23.2/24`；
- DHCP 回复只包含地址、子网掩码、租期、续租/重绑定时间和服务器标识；不发送 Router option 3、DNS option 6、域名、代理、NTP；
- Android `eth0` 路由表只有 `10.57.23.0/24` 直连路由，没有默认路由；
- 应用使用 Android Network 绑定将 CAT6 数据面固定到 `eth0`，不需要 root。

隔离 DHCP 是“单进程生命周期、单租约”模型：第一个通过格式校验的 DHCP DISCOVER 会锁定客户端 MAC，之后拒绝其他 MAC；完成 DORA 后允许同一 MAC 续租。它**不是预先认证到目标手机 MAC**，不能把它描述为设备身份认证。若同一物理网段接入不可信设备，应增加预配置设备身份或配对凭据，而不是依赖“第一个请求者”。

### 2.3 Windows 防火墙最小放行

final7 Host 只维护以下三条启用的入站 UDP Allow 规则；三条均限制 `InterfaceAlias=以太网`、`InterfaceType=Wired`、`EdgeTraversal=Block`，并绑定当前 final7 EXE 的绝对路径。

| 规则 | 本地 | 远端 | 地址限制 | 必要性 |
|---|---|---|---|---|
| CAT6 DHCP Inbound | UDP 67 | UDP 68 | `Any -> Any` | 手机拿到地址前没有 `10.57.23.2`，因此不能提前锁远端 IP；仍受程序、接口和端口限制 |
| CAT6 Announcement Inbound | `10.57.23.1:5003` | `10.57.23.2:5004` | 固定两端地址 | 手机就绪心跳 |
| CAT6 IDR Inbound | `10.57.23.1:5001` | `10.57.23.2:5000` | 固定两端地址 | 关键帧恢复请求 |

final7 重复启动时事件记录 `checked_rules=3 changed_rules=0 result=rules_current`，证明规则收敛是幂等的。没有整体关闭 Windows 防火墙，也没有修改其他规则。

### 2.4 备份

备份目录：`analysis_output/wired_network_tuning_backup_20260722_195100`

关键内容：

- `windows_firewall.wfw`
- `firewall_rules.xml`
- `ethernet_bindings.xml`
- `ipv4_interfaces.xml`
- `ipv4_routes.xml`
- `ip_addresses.xml`
- `dns_servers.xml`
- `ip_configuration.xml`
- `ethernet_wmi.xml`
- `ics_state.csv`
- `sharedaccess_service.xml`
- `netsh_ipv4_dump.txt`

`windows_firewall.wfw` SHA256：`E997CF7B11C23088B56D3A04AF59ABBB2383143FB15C9D3C168D31D1BB8333D4`。

## 3. 验收表

| 指标 | 达标线 | 实测值 | 结论 |
|---|---|---|---|
| Windows 默认路由 | 仅 WLAN 一条 IPv4 默认路由 | `0.0.0.0/0 -> 192.168.1.1`, Interface `WLAN`；CAT6 只有 `10.57.23.0/24 on-link` | **PASS** |
| Android 默认路由 | WiFi 保持默认；eth0 无默认 | table 1025：IPv4/IPv6 默认走 wlan0；table 1034：无默认；main：eth0 仅 `10.57.23.0/24` | **PASS** |
| CAT6 地址/MTU | Host `.1/24`、手机 `.2/24`、MTU 1500 | `10.57.23.1/24 <-> 10.57.23.2/24`，手机 eth0 MTU 1500 | **PASS** |
| 防火墙最小放行 | 只新增程序专属必要 UDP 入站 | 3 条规则，重复启动 `changed_rules=0` | **PASS** |
| Host 配置事务代码门禁 | 地址/DNS/接口任一步失败都回滚 | mock 注入 DNS 失败、最终校验失败、回滚失败；`vfdual_host_direct_link_policy_tests` 全通过 | **PASS（代码级）** |
| 运行中 CAT6 自动恢复 | 拔线/地址丢失后停止发布并重跑固定有线 bootstrap | 状态选择与 Host 发布构建已通过；尚未执行本轮实体拔线与地址破坏验收 | **NOT VERIFIED（实体）** |
| Host -> 手机 TCP | >900 Mbps | 4 streams / 15 s：发送 947.870、接收 **942.153 Mbps** | **PASS** |
| 手机 -> Host TCP | >900 Mbps | 4 streams **816.532 Mbps**；8 streams 816.716 Mbps | **FAIL** |
| 点对点 ping | 平均 <0.3 ms | 100 包：`0.423/1.435/7.557/1.248 ms` | **FAIL** |
| 独立 UDP 丢包 | 50/100/200 Mbps 均 0%，同时报告乱序/重复/抖动 | Windows iperf3 3.21 与 Android iperf3 3.6 控制连接成功，但数据 0/0 后 reset | **NOT VERIFIED** |
| Windows 空闲出站噪声 | 5 分钟约 0 | 300.245 s：TxBroadcast 0、TxMulticast 0 | **PASS（仅 Windows 出站）** |
| 完整空闲链路纯净度 | 除链路层外约 0 | 同窗口 RxBroadcast 1,200、RxMulticast 60 | **FAIL** |
| final5 十分钟应用吞吐 | 10 分钟、无新增手机 drop/QNN failure | 610 s：Host 143.903 FPS、Mobile 143.902 FPS；手机窗口内 drop/QNN failure `+0` | **PASS（当前硬件）** |
| final7 真实视频应用吞吐 | 320x320、约 120 FPS、稳态无新增 drop/failure | Host 119.971 FPS / 50.062 s；Mobile 119.982 FPS / 49.999 s；稳态全类 drop/QNN failure `+0` | **PASS（短时应用层）** |
| 手机接收连续性 | 完成计数连续、硬解与 QNN 正常 | `c2.qti.avc.decoder` hardware=true；5,999 次连续 QNN，0 failure | **PASS（选定窗口）** |
| 输出安全门 | 网络验收期间不驱动 MAKCU | `output_requested=0`、`output_enabled=0`；候选移动全部被 suppressed | **PASS** |

原始网络证据：

- `analysis_output/wired_network_tuning_runtime/iperf_tcp_forward.json`
- `analysis_output/wired_network_tuning_runtime/iperf_tcp_reverse.json`
- `analysis_output/wired_network_tuning_runtime/iperf_tcp_reverse_p8.json`
- `analysis_output/wired_network_tuning_runtime/phone_ping_100.txt`
- `analysis_output/wired_network_tuning_runtime/iperf_udp_50m_server.txt`
- `analysis_output/wired_network_tuning_runtime/idle_final_host_clean_5min.json`
- `analysis_output/final7-live-120fps-20260723/final7-firewall-and-routes.txt`
- `analysis_output/final7-live-120fps-20260723/metrics.md`

应用内探针在 final7 稳态窗口两端显示 `loss=0`，但每个窗口只有少量 probe 样本，只能说明控制探针获得响应，**不能替代独立、带序号的 UDP 50/100/200 Mbps 验收**。

## 4. 失败项原因分析

### 4.1 手机 -> Host TCP 只有约 816.5 Mbps

这不是应用视频吞吐瓶颈：当前 320x320 H.264 实际吞吐远低于千兆链路上限，final5/final7 应用层均稳定。但它没有达到工程目标的 900 Mbps，可能受 Android/Termux iperf3 版本、RTL8153 USB 调度、扩展坞共享 USB 总线、TCP window/offload 或手机节能策略影响。未取得分项证据前不能锁定单一原因。

### 4.2 ping 平均 1.435 ms，高于 0.3 ms

Android 用户态 ping 会受到 USB 网卡中断合并、内核调度、CPU 休眠与前后台负载影响；目标 `0.3 ms` 对手机 USB 以太网路径非常苛刻。当前最小值 0.423 ms 已高于门槛，因此应评估该门槛是否与实际控制时延需求一致，但在门槛未变更前状态仍为 FAIL。

### 4.3 UDP 0% 丢包未验证

两端 iperf3 主版本不一致，控制连接建立后数据面 0/0 并被 reset。不能把“程序内探针 loss=0”或“手机 access-unit drop 未新增”写成网络层 50/100/200 Mbps 0% 丢包。应使用同版本 iperf3，或自带 sequence/timestamp/CRC 的独立双向 harness。

### 4.4 空闲接收广播/组播不为零

Windows 有线接口出站已经清洁，但手机/扩展坞/Android 网络栈仍向链路发送广播或组播，Windows 计数器在 5 分钟内收到 1,260 个相关帧。现有证据没有逐包解码，无法判断 ARP、IPv6 ND/RA、mDNS/LLMNR 或厂商探测各占多少。需要在不 root 的前提下从 Windows 侧进行定向抓包分类，再决定是否能通过接口绑定、服务配置或防火墙进一步降低；不能靠整体关闭防火墙解决。

### 4.5 Android DHCP 身份边界

微型 DHCP 会锁定首个有效 DISCOVER 的 MAC，但没有预认证。物理点对点拓扑下风险较低；若扩展为共享交换网络，攻击者可能先于手机抢占租约。共享网络不是当前支持拓扑，若未来支持必须增加显式配对身份。

## 5. 回滚步骤

回滚必须在 Host 正常退出、确认没有推流或 DHCP 客户端事务后，由管理员执行。先记录当前接口 GUID、名称和 MAC，再与备份中的 `ethernet_wmi.xml`、`ip_configuration.xml` 对照，禁止仅凭“以太网”名称猜测目标。

1. 导出回滚前的新快照，保留本次状态和时间戳；
2. 按 final7 EXE 绝对路径和以下精确名称删除三条 VisionForge 专属规则：
   - `VisionForge Host CAT6 DHCP Inbound`
   - `VisionForge Host CAT6 Announcement Inbound`
   - `VisionForge Host CAT6 IDR Inbound`
3. 依据 `ethernet_bindings.xml` 恢复原接口绑定；依据 `ip_configuration.xml`、`ipv4_interfaces.xml`、`ipv4_routes.xml`、`dns_servers.xml` 恢复原 DHCP/静态地址、网关、DNS、metric、forwarding 与 WeakHost 设置；
4. 依据 `ics_state.csv` 与 `sharedaccess_service.xml` 恢复原共享服务状态，不猜测旧 ICS 拓扑；
5. 只有在需要整体防火墙回滚且确认不会覆盖回滚后新增的合法规则时，才使用 `windows_firewall.wfw`；优先只删除三条专属规则；
6. 重新枚举路由，确认 WLAN 默认路由、原有线配置和 WiFi 上网均恢复；
7. 手机侧无需 root 持久化改动。退出应用、拔掉 RTL8153/扩展坞后 Android 会移除临时 eth0 地址与网络；重新插入时应重新验证默认网络仍走 WiFi。

回滚不是本次验收的一部分，当前未执行。
