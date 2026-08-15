# VisionForge 客户端-服务器通信协议 v2.0

> 当前桌面客户端使用账号 JWT + 按实际运行时长计费。下方卡密接口属于兼容协议；新功能以本节为准。

## 0. 当前账号与时长购买协议

| 能力 | 方法与路径 | 认证 |
|------|------------|------|
| 注册验证码 | `POST /api/client/register-code` | 匿名、按规范化邮箱冷却 |
| 注册 | `POST /api/client/register` | 匿名、一次性邮箱验证码 |
| 登录 | `POST /api/client/login` | 匿名、IP 防爆破 |
| 余额 | `GET /api/client/balance` | Bearer JWT |
| 时长兑换 | `POST /api/client/redemptions` | Bearer JWT |
| 邀请汇总/历史 | `GET /api/client/referrals/summary`、`GET /api/client/referrals` | Bearer JWT |
| 时长入账历史 | `GET /api/client/time/entries` | Bearer JWT |
| 修改密码 | `POST /api/client/account/password` | Bearer JWT + 当前密码 |
| 修改邮箱验证码 | `POST /api/client/account/email-code` | Bearer JWT |
| 修改绑定邮箱 | `POST /api/client/account/email` | Bearer JWT + 当前密码 + 新邮箱验证码 |
| 购买会话 | `POST /api/client/purchase-link` | Bearer JWT |
| 购买状态/历史 | `GET /api/client/purchase-status/{token}`、`GET /api/client/purchase-history` | Bearer JWT |
| 使用计费 | `POST /api/client/session-start`、`session-heartbeat`、`session-end` | Bearer JWT |
| 支付回调 | `GET /appPush`、`POST /api/payment/webhook` | 服务商签名/HMAC |

购买订单使用管理员上传的定额微信/支付宝收款码。相同支付渠道、相同套餐在 15 分钟匹配窗口内只允许一个活动金额槽；到账后该槽从到账时刻继续保留 15 分钟，防止没有交易号的旧 VMQ 通知以新时间戳重发并误交付下一单。疑似重发记为 `possible_duplicate` 并停止自动交付。不同渠道按 `payment_method` 隔离，可同时存在同额订单。客户端不得覆盖服务端返回的 `amount`。同一账号重复请求购买链接会复用唯一活动 token：open 会话有效 5 分钟，创建订单后有效期重置为 15 分钟。选择页和订单页通过只读接口 `GET /client/purchase/{token}/status` 每 2 秒同步一次状态，接口只返回最小字段且禁止缓存。关闭浏览器没有业务副作用，兼容 `/client/purchase/{token}/abandon` 为无副作用响应；只有明确取消才将订单和会话置为 `cancelled`，可信迟到回调仍可一次性到账。

V免签回调使用 `sign = MD5(type + price + t + VMQ_WEBHOOK_SECRET)`，心跳使用 `sign = MD5(t + VMQ_WEBHOOK_SECRET)`。`t` 支持原版 13 位毫秒时间戳和兼容的 10 位秒时间戳；服务端拒绝超过 15 分钟的旧请求及超前 60 秒以上的请求。只有签名覆盖的 `t/type/price` 会进入事件身份和订单匹配，其他查询字段一律忽略。`type=1` 标准化为 `wechat`，`type=2` 标准化为 `alipay`，不支持的类型或跨渠道订单回调会被拒绝。`purchase-link` 响应增加 `payment_methods`、`reused`、`status`、`order_id`；购买状态增加 `payment_method`、`expires_at`、`remaining_seconds`，历史订单增加 `payment_method`。这些均为向下兼容的新增字段。

JSON 支付回调以服务端 `VMQ_WEBHOOK_SECRET` 对原始 JSON 请求体计算 HMAC-SHA256，并通过 `X-VisionForge-Signature` 传入。订单到账、充值记录和余额更新在同一 `BEGIN IMMEDIATE` 事务内完成，重复回调由 `payment_events.event_id` 与 `time_recharges.order_id` 双重幂等。

`session-start` 成功响应以向下兼容字段 `billing_capabilities.heartbeat_idempotency="v1"` 声明心跳幂等能力。客户端只有确认该能力后，才可在瞬时失败时复用相同的 `heartbeat_id + heartbeat_sequence` 重试；服务端返回首次响应且不重复扣时、不续发 lease。同一 sequence 的不同 ID 或旧 sequence 会被拒绝。未携带心跳身份的旧客户端继续按原协议工作；部署必须先升级服务端，再发布使用幂等重试的新客户端。

修改密码请求体为 `current_password` 与 `new_password`。成功响应返回新 `token`；
旧令牌因 `auth_version` 递增立即失效。修改邮箱先向 `email-code` 提交
`new_email`，再向 `account/email` 提交 `current_password`、`new_email`、
`email_code`。验证码消费与邮箱唯一性检查、邮箱更新位于同一事务，验证码只可使用一次。

注册验证码的常规限流主体是规范化邮箱，默认冷却 60 秒；不同邮箱之间不共享应用级
额度。SMTP 投递失败时，服务端删除本次未送达验证码并返回
`503 email_delivery_failed`，不会用失败记录触发邮箱冷却；同一邮箱在冷却期内重试
返回 `429 email_code_cooldown` 和 `Retry-After`。反向代理仅保留高阈值的异常流量保护。
注册提交不使用共享 IP 业务配额；服务端通过邮箱验证码的一次性消费、用户名/邮箱
唯一约束和事务写入保证每个注册主体相互隔离。

### 0.1 注册邀请码

`POST /api/client/register` 在原请求体上增加可选字段 `invite_code`。不传或传空字符串时行为与旧客户端相同；传入无效、停用或不可用邀请码时，整个注册事务回滚，邮箱验证码不会被消费。

有效邀请码只在注册事务中绑定一次。服务端数据库同时阻断自邀、老用户补绑、一个被邀请人绑定多个邀请人和注册事件重放。邀请人奖励即时入账且无每日上限；奖励秒数由 `/admin/growth` 配置，客户端不能提交奖励数值。

### 0.2 时长兑换码

```http
POST /api/client/redemptions
Authorization: Bearer <account-jwt>
Content-Type: application/json

{"code":"VF1-...."}
```

成功响应包含 `credited`、`product_name`、`credited_seconds`、`balance_seconds` 和 `redeemed_at`。同一账号因网络重试再次提交同一码时返回成功但 `credited=false`；其他账号提交已用码统一返回 `CODE_INVALID_OR_USED`，不会泄露原兑换者。过期和已废止分别返回 `CODE_EXPIRED`、`CODE_REVOKED`。

服务端不保存完整兑换码明文。兑换码状态从 `issued` 到 `redeemed` 的条件更新、唯一时长来源写入和余额增加在同一 `BEGIN IMMEDIATE` 事务完成；任一步失败都会整体回滚。

### 0.3 邀请信息

- `GET /api/client/referrals/summary`：返回专属 `invite_code`、单次奖励、邀请人数和累计奖励，不含明细。
- `GET /api/client/referrals?limit=50`：在汇总基础上返回最近邀请历史，用户名已脱敏，最多 100 条。
- 规范落地页为 `GET /i/{invite_code}`，客户端下载入口为 `GET /download`。

### 0.4 外部订单即时取码

`POST /api/integrations/code-issuances/issue` 不接受客户端 JWT 或静态公网 Bearer Token。调用方使用独立服务身份，并发送以下请求头：

```text
X-VF-Service: xianyu-code-bridge
X-VF-Timestamp: <unix-seconds>
X-VF-Nonce: <one-time-random-value>
X-VF-Signature: <hex-hmac-sha256>
```

签名原文为五行：`HTTP_METHOD`、`PATH`、`TIMESTAMP`、`NONCE`、`SHA256(raw_body)`。服务端校验 HMAC、最大时间偏差和 nonce 唯一性；nonce 重放会被拒绝。请求体只有服务端时长权益标识和不透明幂等令牌：

```json
{"product_key":"10h","request_id":"xi1_<opaque-hmac>"}
```

闲鱼桥接器在私网中根据账号、订单号和单元序号生成不可逆 `request_id`；Platform 不接收也不保存闲鱼订单号、买家、商品或规格。相同 `request_id` 首次调用即时生成一张码，网络或并发重试返回同一张码；若同一令牌改传其他 `product_key`，服务端返回 `IDEMPOTENCY_CONFLICT`。完整码只出现在私有取码响应，日志、管理页面和普通查询 API 不显示明文。

## 1. 概述

| 项目 | 值 |
|------|------|
| 协议 | HTTPS (生产) / HTTP (开发) |
| 数据格式 | JSON |
| 编码 | UTF-8 |
| 认证方式 | 账号 JWT（当前）/ 卡密自证（兼容） |
| 签名算法 | RSA-2048 PKCS#1 v1.5 SHA-256 |
| 基础URL | `https://your-domain.com` (生产) / `http://81.70.189.154` (测试) |

## 2. 认证模型

客户端**不需要**单独的API Key。卡密本身就是认证凭据：

- 卡密 = `VFG-<RSA签名的payload>.<RSA签名>`
- 服务端用公钥验签 → 签名有效则卡密真实 → 请求可信
- 日志上传类请求: 附加 `license_id` 即可，由服务端验证卡密归属

**安全特性：**
- 私钥仅存服务端（AES-256-GCM加密存储）
- 公钥验签不暴露私钥
- 所有API均有速率限制
- 激活操作有竞态保护（rowcount检查）

## 3. API 端点

### 3.1 卡密激活

首次使用卡密绑定机器码。

```
POST /api/license/activate
Content-Type: application/json

请求:
{
    "key_text": "VFG-eyJ2IjoxLCJwcm9kd...",   // 完整卡密串
    "machine_code": "A1B2C3D4E5F6...",         // 32位大写hex机器码
    "client_version": "v17.8.47"               // 客户端版本号 (可选)
}

成功响应 (200):
{
    "success": true,
    "message": "激活成功",
    "plan": "week",
    "expires_at": "2026-07-13T15:57:54Z",
    "features": "[\"aim\"]"
}

错误响应:
400 - 卡密无效/格式错误
403 - 卡密已绑定其他机器/已吊销
404 - 卡密未找到
409 - 并发激活冲突（已被他人抢先）
```

### 3.2 卡密验证

每次客户端启动时调用，确认卡密仍然有效。

```
POST /api/license/verify
Content-Type: application/json

请求:
{
    "key_text": "VFG-eyJ2IjoxLCJwcm9kd...",
    "machine_code": "A1B2C3D4E5F6..."
}

成功响应 (200):
{
    "valid": true,
    "reason": "OK",
    "plan": "week",
    "days_left": 5          // 剩余天数，永久卡为null
}

失败响应:
{
    "valid": false,
    "reason": "卡密已过期"   // 机器码不匹配 / 已被吊销 / etc
}
```

### 3.3 客户端版本检查

```
GET /api/client/version

响应 (200):
{
    "latest_version": "v17.8.81_update_lease_bridge_hardened",
    "download_url": "https://github.com/SuperZhao666/VisionForge/releases/latest",
    "release_notes": "修复参数重载输入异常，并增强移动目标连续跟踪"
}
```

### 3.4 客户端心跳

定期上报客户端运行状态。

```
POST /api/client/heartbeat
Content-Type: application/json
频率: 每 5 分钟

请求:
{
    "license_id": "90FED560AEB04C6E",      // 卡密ID
    "machine_code": "A1B2C3D4...",          // 本机机器码
    "client_version": "v17.8.47",
    "session_id": "20260706_143000",        // 客户端日志session
    "status": {
        "gpu_available": true,
        "inference_fps": 120.5,
        "uptime_seconds": 3600
    }
}

响应 (200):
{
    "ok": true,
    "server_time": "2026-07-06T14:30:00Z"
}
```

### 3.5 日志批量上传

定期上传运行日志增量。

```
POST /api/logs/upload
Content-Type: multipart/form-data

表单字段:
- file: 日志文件 (gzip压缩, 最大50MB)
- session_id: 客户端日志session ID
- file_type: 类型 (txt / jsonl / db / dump)
- license_id: 卡密ID (可选，用于关联)

响应 (200):
{
    "ok": true,
    "message": "Uploaded",
    "data": {
        "file_type": "jsonl",
        "original_name": "events_20260706.jsonl",
        "file_size": 1048576
    }
}
```

### 3.6 崩溃实时上报

异常发生时立即上报。

```
POST /api/logs/crash
Content-Type: application/json

请求:
{
    "session_id": "20260706_143000",
    "machine_info": "{\"cpu\":\"...\",\"gpu\":\"...\"}",
    "crash_type": "unhandled_exception",
    "crash_data": "{...异常上下文JSON...}",
    "license_id": "90FED560AEB04C6E"
}

响应 (200):
{
    "ok": true,
    "message": "Crash reported"
}
```

## 4. 错误码

| HTTP | 含义 |
|------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 403 | 权限不足/卡密状态异常 |
| 404 | 资源不存在 |
| 409 | 并发冲突 |
| 413 | 文件过大 |
| 429 | 当前限流主体请求过于频繁；验证码接口同时返回 `Retry-After` |
| 503 | 外部服务暂时不可用（如 SMTP 投递被拒） |
| 500 | 服务器内部错误 |

## 5. 安全措施

| 层级 | 措施 |
|------|------|
| 传输层 | HTTPS (TLS 1.2+) |
| 认证层 | RSA-2048卡密签名自证 |
| 应用层 | 全端点速率限制 |
| 数据层 | 激活操作行级锁(rowcount)防并发 |
| 存储层 | 私钥AES-256-GCM加密，密码环境变量注入 |
| 日志层 | PII脱敏 (用户名/IP在日志中自动遮蔽) |

## 6. 客户端集成清单

客户端需要新增的代码（不修改现有离线验证逻辑）：

| 文件 | 内容 | 行数 |
|------|------|------|
| `src/online_license.py` | 在线激活 + 启动验证 | ~150 |
| `src/log_uploader.py` | 日志增量扫描 + gzip + 定时上传 | ~200 |
| `src/heartbeat.py` | 定期心跳上报 | ~60 |
| `config.yaml` | 新增 `platform.api_url` | 3 |
| `app_gui.py` | 集成上述模块的调用点 | ~30 |
