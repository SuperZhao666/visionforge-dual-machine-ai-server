# 闲鱼自动发货与 VisionForge 即时取码

这套部署直接使用固定版本的开源闲鱼管理系统。账号登录、商品发布、商品管理、套餐规格、订单监听、卡券、自动发货规则和发货日志都在闲鱼系统里完成；VisionForge Platform 不再维护第二套闲鱼后台。

唯一连接点是一个无状态私网适配器：闲鱼确认订单满足发货规则后，API 卡把固定的 `product_key` 和动态 `{order_id}` 交给适配器。适配器把订单信息变成不可逆幂等令牌，向 Platform 即时申请一张兑换码，再把“商品名 + 兑换码 + 下载地址 + 使用说明”返回给闲鱼系统发送。

```text
买家付款
  -> 闲鱼系统命中商品/规格与 API 卡
  -> 私网适配器生成 opaque request_id
  -> Platform 按 product_key 即时生成一张码
  -> 闲鱼系统私聊发货并记录结果
  -> 买家在客户端登录后兑换
```

系统没有预生成码池。同一个订单的网络重试或并发回调始终返回同一张码；Platform 不接收闲鱼订单号、买家、商品 ID 或规格。

## 管理边界

| 操作 | 去哪里 |
|---|---|
| 登录闲鱼账号、扫码、保活 | 闲鱼管理系统 `/admin` 的“账号管理” |
| 五套餐发布、同步绑定、Dry-run 与启停 | 闲鱼管理系统“商品发布”页顶部的 VisionForge 五套餐运营向导 |
| 其他商品发布、同步与维护 | 闲鱼管理系统原有的“商品发布 / 商品管理” |
| 套餐规格、API 卡、自动发货规则、订单和发货日志 | 闲鱼管理系统 |
| 配置 `1h/5h/10h/50h/100h` 对应时长 | VisionForge `/admin/growth` 的“时长权益” |
| 手工给代理批量拿卡、废止未兑换批次 | VisionForge `/admin/growth` |
| 邀请奖励、邀请历史 | VisionForge `/admin/growth` |

## 重要能力边界

- VisionForge 补丁可以按闲鱼网页当前协议构造五套餐 SKU，但只在账号能力接口明确返回 `supportSkuOrInventory=true` 时允许真实发布；能力不满足时服务端会在上传图片和发布前阻断。
- 当前生产账号的只读能力探测结果为“不支持 API 多规格发布”。因此部署后应在向导选择“绑定已同步官方商品”：先在闲鱼官方端创建带“套餐”规格的商品，再同步并精确绑定五张 API 卡。如果官方端也不给该账号创建多规格，当前就无法可靠实现“一个商品页五套餐”，应申请账号能力或更换合规连接器，不能伪造成功。
- 每个套餐值对应一张 API 卡，卡内静态填写 `product_key`。商品与规格如何命中由闲鱼系统负责，Platform 不做映射。
- SKU 的 `quantity` 是总库存，不是单笔限购。托管链路会在任何取码动作前强制校验订单购买数量恰好为 1；数量缺失或大于 1 都阻断，但仍需在闲鱼官方能力中设置单笔限购 1 件以减少买家失败体验。
- 上游固定为 `GuDong2003/xianyu-auto-reply-fix` 提交 `837497d576b1b864a7294b8565348531a6ce7039`。仓库许可与镜像“禁止商业用途”声明存在冲突；取得权利人明确授权或换用合规连接器前，只能影子测试，不能承接真实商业订单。

### 托管模式

- `off`：只读。允许查看目录、账号能力和同步商品，禁止发布、绑定和启用；紧急停用始终可用。
- `shadow`：默认。允许创建保持禁用的精确绑定并执行 Dry-run，禁止真实发布和启用自动发货。
- `live`：允许真实发布和在 Dry-run 通过后二次确认启用。只有取得商业授权并完成自有小额订单验收后才能切换。

模式由服务端环境变量 `VISIONFORGE_MANAGED_FULFILLMENT_MODE` 强制执行，前端按钮状态不是安全边界。

## 1. 部署与登录

1. 先备份 Platform SQLite，执行 `PRAGMA integrity_check`。Xianyu 数据库由下面的激活脚本在停止写入进程后单独生成一致性快照，不能用普通文件复制代替。
2. 复制 `.env.example` 为 `.env`，设置独立随机管理密码、JWT、桥接 Token、取码服务身份和 HMAC 密钥；文件权限设为 `600`，不得提交。示例占位值会被激活脚本和容器入口同时拒绝。
3. Platform 配置同一套 `CODE_ISSUANCE_SERVICE_ID`、`CODE_ISSUANCE_HMAC_SECRET`，并设置独立 `REDEMPTION_CODE_SECRET`。Xianyu 服务按 `.env.example` 配置 `VISIONFORGE_MANAGED_BRIDGE_URL`、`VISIONFORGE_PACKAGE_PRODUCT_KEYS` 和 `BRIDGE_INTERNAL_TOKEN`；Token 只注入容器且不得回显。`XIANYU_AUTO_DELIVERY_ENABLED` 必须始终为 `false`。
4. 构建固定镜像，再用安全激活脚本启动候选版本：

```bash
chmod +x prepare.sh
./prepare.sh
chmod +x activate_hardened_image.sh
./activate_hardened_image.sh
```

激活脚本会依次完成以下操作：检查 Docker/Compose、磁盘、DNS、回环端口和 `fulfillment_internal` 子网；保存完整旧 `.env` 与旧运行状态；停止 Xianyu 写入进程；用 SQLite Backup API 生成并校验 `runtime/backups/xianyu-pre-activation-*.db`；固定候选为 `shadow` 且关闭上游通用自动发货；最后检查两个容器健康、数据库迁移、运行态卡片契约、托管规则保存的卡片配置指纹，以及镜像内真实通用发货运行时闸门。全新数据库允许暂时为零张 VisionForge API 卡，但一旦存在 VisionForge 卡片就必须是完整且精确的五张；其他上游普通卡不计入这五张。任何已绑定托管规则缺少配置指纹，或其指纹与当前 API 卡配置不一致，运行态与就绪检查都会失败，且不会输出 Token 或卡片配置。

候选失败时，脚本先停止候选，再恢复数据库、完整旧 `.env` 和旧镜像；只有升级前正在运行的服务才会重启。所有恢复检查通过才会报告 `activation_failed_rollback=verified`；如果报告 `activation_failed_rollback=failed`，不得继续启动或手工启用规则，应保留现场并使用受限的环境快照做人工恢复。数据库快照包含业务敏感数据，目录保持 `700`、文件保持 `600`，按备份保留策略安全清理，禁止外传。

当前 `rotate_bridge_token.sh` 会明确拒绝执行：管理校验和 API 卡现在都依赖同一个桥接 Token，只重建桥接器会造成两边配置分裂。完成“停止发货、数据库快照、卡片与 `.env` 原子更新、两服务受控重建、失败完整回滚”的轮换事务前，不得手工绕过。

5. 管理端只监听宿主回环。请通过 SSH 隧道访问，不能开放公网：

```bash
ssh -L 6202:127.0.0.1:6202 your-server
```

浏览器打开 `http://127.0.0.1:6202/admin`，用部署时设置的管理员密码登录。进入“账号管理”选择“扫码登录”，由闲鱼手机 App 确认。不要复制 Cookie、二维码内容、密码或 Token 到聊天、日志和工单。

### 从 shadow 安全晋级

`activate_hardened_image.sh` 激活 `shadow` 候选，自动进入真实发货。先完成账号登录、官方商品同步、五张 API 卡和五条禁用规则的配置，再执行严格就绪检查：

```bash
docker exec -i visionforge-xianyu-fulfillment python - --mode readiness \
  < verify_xianyu_state.py
```

把 `.env` 中 `VISIONFORGE_MANAGED_FULFILLMENT_MODE` 改为 `live`；`XIANYU_AUTO_DELIVERY_ENABLED=false` 不得修改。该变量只有与镜像内 `VISIONFORGE_GENERIC_AUTO_DELIVERY_RUNTIME_GUARD_V1` 运行时闸门同时存在才构成安全边界，不能只凭环境变量判断。随后只重建 Xianyu 服务、再次运行就绪检查，并在运营向导完成 Dry-run 与二次确认后启用五条托管规则。任何一步失败都保持规则禁用并退回 `shadow`，不能通过上游通用自动发货开关绕过托管工作流。

## 2. 配置时长权益

在 VisionForge `/admin/growth` 只做三件事：

1. 核对 `1h/5h/10h/50h/100h` 等权益标识与实际小时数。
2. 配置兑换码有效期和客户端下载地址。
3. 保持需要销售的权益为“允许未来发码”；停用某项权益会立即阻止该套餐产生新码，但不影响历史已发行码。

闲鱼账号、商品 ID、规格映射、发货开关和发货日志不在这个页面配置。

## 3. 使用五套餐运营向导

当前生产环境已经建立 `1h/5h/10h/50h/100h` 五张 VisionForge API 卡。先在闲鱼系统“卡券管理”检查并直接使用它们，不要重复创建。API 卡是“付款时向 Platform 即时取一张码”的可重复调用模板，不是预存兑换码库存。

全新部署或确有卡片缺失时，才参照 `api-card.example.json` 补建。以 10 小时套餐为例：

- URL：`http://fulfillment-bridge:8080/issue`
- 方法：`GET`
- Header：内部 Bearer Token
- 动态参数：`order_id={order_id}`
- 静态参数：`product_key=10h`、`unit_index=1`

其他套餐只改静态 `product_key`：`1h`、`5h`、`50h`、`100h`。不要把时长秒数、兑换码或闲鱼 Cookie 写进 API 卡。

登录 `/admin` 后进入“商品发布”，优先使用页面顶部的 VisionForge 五套餐运营向导：

1. 选择闲鱼账号，查看“账号多规格能力”和当前托管模式。
2. 当前账号能力不支持新发布时，选择“绑定已同步官方商品”，再选择已经同步且标记为多规格的商品。
3. 向导会从现有五张 API 卡自动形成 `1/5/10/50/100 小时` 的精确映射；不要手工创建标题关键字兜底规则。
4. 点击“校验发布方案”。校验不上传图片、不发布、不取码。
5. 点击“建立禁用规则”。此时五条规则必须全部保持停用。
6. 点击“规则 Dry-run”，确认覆盖率为 `5/5`、没有缺失/歧义/规格漂移。
7. 仅在 `live` 模式下，二次确认“启用五套餐自动发货”。失败时先看 TraceId 和错误码，不要重复发布商品。

若账号以后获得 API 多规格能力，可在同一向导选择“新发布”：填写标题、描述、1–9 张图片、五档售价和总库存。服务端以最低套餐价作为商品顶层展示价，发布成功后仍只创建禁用规则，必须经过相同 Dry-run 与二次确认才能启用。

## 4. 验收顺序

1. 先连接自有测试账号，只开启影子监听，观察至少 30 分钟连接、内存、CPU 和错误日志。
2. 建一个 1 小时、每单 1 件的测试商品或测试规格，并绑定 `product_key=1h` 的 API 卡。
3. 用模拟请求验收：首次取码成功，同订单重复/并发请求返回同一码，未知或停用权益拒绝发码。
4. 在得到商业使用授权后，才执行一笔自有账号真实小额订单；确认闲鱼发货日志成功、买家收到下载与使用说明。
5. 用测试用户兑换：首次只增加 1 小时；本人重试不重复增加；另一账号不能使用同一码。
6. 检查 Platform 数据库、日志、管理页和审计中不存在闲鱼订单号、买家、商品规格及完整兑换码。

紧急停止只需在闲鱼系统关闭对应自动发货规则或停止 `xianyu-app`；Platform 没有第二个闲鱼发货开关。

## 资源与安全

- `xianyu-app`：并发固定为 1，限制 1 CPU / 1 GiB / 256 PIDs；浏览器空闲通常约 350–550 MiB，峰值按 1 GiB 封顶。
- 私网适配器：限制 0.25 CPU / 128 MiB / 64 PIDs，不映射宿主端口。
- 两个容器只加入固定子网 `fulfillment_internal`（`172.29.47.0/28`），桥接器固定为 `172.29.47.2`，不加入 `qq-steward_default`。宿主防火墙只允许该地址访问宿主 `172.29.47.1:443`；Nginx 对取码路径只放行该子网与回环地址，公网请求直接拒绝。
- 管理端只映射 `127.0.0.1:6202`；两个容器均固定版本、非特权、`no-new-privileges` 并启用日志轮转，桥接器额外使用只读根文件系统。
- 闲鱼浏览器与 FFmpeg/大模型等重任务不得无界同时运行。
- 当前生产采样中闲鱼 Chrome 会持续占满约 1 个 CPU 核；正式接单前必须继续观察连接与发货延迟，若忙循环持续则先排障，不提高并发或资源上限掩盖问题。

常用检查：

```bash
docker compose --profile live ps
docker compose --profile live logs --tail=200 xianyu-app fulfillment-bridge
docker stats --no-stream visionforge-xianyu-fulfillment visionforge-fulfillment-bridge
docker exec -i visionforge-xianyu-fulfillment python - < verify_xianyu_state.py
```

不要把 Cookie、Token、HMAC 密钥、订单明文或兑换码粘贴到外部聊天、AI 上下文或公开工单。
