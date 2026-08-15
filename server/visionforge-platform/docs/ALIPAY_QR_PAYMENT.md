# 支付宝定额收款码接入设计

## 1. 方案结论

采用“现有 V免签协议 + 支付宝通知监听 + 管理员上传定额收款码”的旁路扩展：

- 微信继续使用 `type=1`，支付宝使用 V免签标准 `type=2`；
- 订单、充值、余额和幂等事务继续复用 `payment_service`；
- 支付渠道目录、二维码存储和后台上传各自独立，不复制一套订单业务；
- 匹配键从“金额”收紧为“支付渠道 + 金额”，相同套餐可同时存在一笔微信订单和一笔支付宝订单；
- 未配置二维码的渠道不会出现在购买页面，避免用户进入不可支付状态。

这条路径不需要支付宝商户应用、RSA 证书或按笔支付接口费用，改动和运维成本最低。代价是支付宝通知监听端必须在 Android 真机或稳定模拟器上持续运行，因此只适合当前低并发、固定金额场景。业务量上升后，应迁移到支付宝开放平台当面付，并保留现有渠道接口作为适配层。

## 2. 方案对比

| 方案 | 资质与费用 | 改造量 | 自动到账 | 结论 |
|---|---:|---:|---:|---|
| V免签支付宝通知监听 | 无新增商户接口成本 | 小 | 是 | 当前采用 |
| 支付宝开放平台当面付 | 需要开通官方商户产品 | 中 | 是，官方回调 | 后续正规扩展 |
| 独立易支付/聚合网关 | 需要另行部署、维护密钥和数据库 | 大 | 取决于上游 | 当前不采用 |
| 纯人工审核 | 无接入成本 | 小 | 否 | 用户体验和误操作风险不可接受 |

调研参考：

- `szvone/vmqApk`：原版 MIT 监控端，依赖面最小，支持支付宝/微信通知与 V免签 `type=1/2` 协议；版本较旧，必须在目标设备上做真实通知验收；
- `shinian-a/Vmq-App`：较活跃的免 Root 分支，修复了部分新版通知匹配问题，但当前源码仍写死 HTTP 并包含与支付无关的外部请求，因此不直接把未审计发布包作为生产基线；
- `szvone/vmqphp`：原始 V免签服务端设计，核心流程是通知监听、按金额匹配与回调；
- `jeequan/jeepay`：高质量企业级多渠道支付架构，但技术栈和部署规模远超当前需求；
- `F:\支付网关+卡网\1.6安装包.zip`：核心支付文件使用 SourceGuardian 保护，不适合作为可审计源码复用；
- `F:\支付网关+卡网\acg-faka-main.zip`：支付适配器分层可参考，但完整发卡/插件系统不应引入当前服务。

## 3. 服务端与客户端契约

### V免签回调

```text
GET /appPush?t=<timestamp>&type=<1|2>&price=<amount>&sign=<md5>
sign = MD5(type + price + t + VMQ_WEBHOOK_SECRET)
GET /appHeart?t=<timestamp>&sign=<md5>
heartbeat sign = MD5(t + VMQ_WEBHOOK_SECRET)
type=1 -> wechat
type=2 -> alipay
```

`t` 优先使用原版监听端的 13 位毫秒时间戳，同时兼容 10 位秒时间戳。服务端拒绝超过 15 分钟的旧请求和超前 60 秒以上的请求；`appHeart` 同样验签和校验时间。只有已签名的 `t/type/price` 与服务端派生的 `payment_method` 会进入支付事件，额外查询参数不会影响订单匹配或事件幂等键。

服务端先按回调中的 `type` 验签，再把标准化后的 `payment_method` 传入支付事件。按金额回调时，只查询同渠道的活动订单。

### 客户端接口

- `POST /api/client/purchase-link` 增加 `payment_methods: string[]`、`reused`、`status` 和 `order_id`；同一账号的重复请求返回同一个活动 token；
- `GET /api/client/purchase-status/{token}` 增加 `payment_method`、`expires_at` 和 `remaining_seconds`；
- `GET /api/client/purchase-history` 的每一项增加 `payment_method`；
- 旧客户端忽略新增字段即可，原路径、认证和已有字段不变。

### 浏览器支付页状态同步

套餐选择页和订单页每 2 秒读取 `GET /client/purchase/{token}/status`。该接口以购买会话随机令牌作为访问边界，只返回 `status`、`status_text`、`terminal`、`order_id`、`expires_at` 和 `remaining_seconds`，不返回用户、余额或支付凭据，并强制 `Cache-Control: no-store`。任一标签页创建订单后，其他标签页会导航到同一订单；订单进入 `delivered`、`cancelled` 或 `expired` 终态后，页面使用 `location.replace` 导航到规范 GET 页面并重新渲染，避免刷新创建订单的 POST 响应而重复提交。

状态查询遵循“订单已到账优先于会话旧状态”的规则，因此即使通知与取消动作并发，已成功结算的订单也会显示为“已到账”。关闭浏览器不再修改业务状态；兼容路径 `/client/purchase/{token}/abandon` 保留，但只记录结构化日志。只有“取消本次支付”会将订单和会话改为 `cancelled`，可信迟到回调仍可幂等转换为 `delivered`。

### 结账领域边界与状态机

- 接入层路由只负责认证、HTTP 参数和 HTML/JSON 响应；
- `PurchaseCheckoutService` 负责获取或创建、状态流转、槽位规则和链路日志；
- `SqlitePurchaseCheckoutRepository` 独占购买会话、订单状态和异常事件查询 SQL；
- 数据库部分唯一索引保证每个用户最多一条 `open/pending` 会话，服务层使用 `BEGIN IMMEDIATE` 保证并发 20 次请求仍只创建一个 token；
- 启动迁移会优先保留带待支付订单的活动会话，否则保留最新 open，会话和订单历史不删除。

状态主路径为 `open -> pending -> delivered`；超时进入 `expired`，明确取消进入 `cancelled`。`cancelled/expired` 在原 15 分钟金额匹配窗口内仍属于可结算状态，以承接真实的迟到通知，但充值唯一索引保证余额只增加一次。

## 4. 二维码上传

管理员登录后访问 `/admin/payment-qr`，分别上传每个套餐的 PNG 定额收款码。服务端校验 PNG 结构、CRC、尺寸和文件大小，并以原子替换方式保存。当前套餐金额如下：

| 套餐 | 固定金额 | 支付宝文件名 |
|---|---:|---|
| 1 小时 | ¥0.75 | `alipay_qr_1h.png` |
| 5 小时 | ¥3.00 | `alipay_qr_5h.png` |
| 10 小时 | ¥5.00 | `alipay_qr_10h.png` |
| 50 小时 | ¥20.00 | `alipay_qr_50h.png` |
| 100 小时 | ¥35.00 | `alipay_qr_100h.png` |

上传行为写入 `admin_audit`。部署同步必须继续保留服务器上的 `app/static/img`，不能用空目录覆盖线上二维码。

## 5. 监听端启用步骤

1. 优先从 `https://github.com/szvone/vmqApk/releases` 获取原版开源监控端，安装到不承载其他敏感通知的专用 Android 真机或模拟器；
2. 设备上的支付宝登录必须与所上传收款码的收款账户一致；
3. 在支付宝中开启收款消息提醒；
4. 给监听端授予通知读取权限，并开启自启动、后台运行和电池白名单；
5. 管理员访问 `/admin/payment-qr`，通过“查看监听端一次性配置”取得通知地址与通讯密钥；普通页面、审计日志和聊天记录都不会展示密钥；
6. 先用一个已配置的最低金额套餐做真实小额验证，确认后台订单渠道为 `alipay`、状态为 `delivered`，且用户余额只增加一次。

这一方案不要求网页登录或扫码登录服务端。若 Android 设备上的支付宝尚未登录，支付宝自身可能要求账号登录或设备验证，需要由账户持有人在设备上完成。

## 6. 运行边界与告警

- 同一渠道、同一套餐在 15 分钟匹配窗口内仅允许一个金额槽；到账后该金额槽仍从到账时刻保留 15 分钟，避免原版监听端用新 `t` 重发同一通知时误交付下一笔订单；
- 同一账号只保留一个活动结账单：open 会话 5 分钟，创建订单后重置为 15 分钟；
- 微信和支付宝同额订单互不占用对方槽位；
- 监听端离线时订单保持待支付，通知恢复后仍可在窗口内安全到账；
- 重复回调由 `payment_events.event_id` 和 `time_recharges.order_id` 双重幂等；
- 日志只记录渠道、金额、事件号和结果，不记录通讯密钥或二维码内容。
- 管理后台只读展示最近的 `unmatched`、`ambiguous`、`order_not_found`、`payment_method_mismatch` 和 `possible_duplicate` 摘要，不展示原始回调载荷，也不提供手工入账按钮。
- 原版监听协议只支持 HTTP。Nginx 的服务器 IP 默认虚拟主机仅放行精确路径 `/appHeart` 和 `/appPush`，其他路径继续返回 444；回调由 MD5 签名、15 分钟新鲜度窗口、FastAPI 限流和事件幂等保护。这是低成本过渡方案，不替代官方 HTTPS 支付回调。
