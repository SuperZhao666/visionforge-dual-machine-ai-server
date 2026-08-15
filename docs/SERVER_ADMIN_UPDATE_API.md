# VisionForge Server Admin, Billing, Update and Announcement API

本文档是服务器后台必须实现的接口契约。当前仓库是客户端/打包工程，没有 Admin Web 后台源码；客户端和 `tools/admin_console.py` 会按本文档调用服务器。

## 基本约束

- Base URL: `https://www.visionforge.cloud`
- 禁止在客户端、日志、配置文件中保存 SSH 密码或数据库密码。
- Admin 接口必须使用 `Authorization: Bearer <admin_token>`，并按角色授权。
- 所有 Admin 写操作必须写入审计日志：管理员、IP、目标对象、变更前后、reason、时间。
- 客户端接口允许普通用户 token；公告读取可支持匿名。
- 更新时间、余额等金额/时长字段统一用秒，字段名为 `balance_seconds` / `delta_seconds`。

## 用户与计费

### Client

- `POST /api/client/register`
- `POST /api/client/login`
- `GET /api/client/balance`
- `POST /api/client/session-start`
- `POST /api/client/session-heartbeat`
- `POST /api/client/session-end`
- `POST /api/client/purchase-link`
- `GET /api/client/purchase-status/{purchase_token}`
- `GET /api/client/purchase-history?limit=5`

### 购买状态机与支付安全

- `POST /api/client/purchase-link` 只创建一次性购买会话；购买页创建订单后，服务端返回该订单的精确应付金额。
- 同套餐并发订单使用数据库事务分配不同的“分”金额（基础价至基础价 + 0.99 元），客户端和购买页必须展示服务端返回金额，不能自行重算。
- 购买状态包括 `open`、`pending`、`abandoned`、`cancelled`、`delivered`。浏览器关闭会话后客户端应在下一次 1 秒轮询内显示“已关闭/已取消等待”，但订单仍保留迟到支付结算能力。
- 可信支付回调可将 `pending`、`cancelled` 或 `expired` 订单结算为 `delivered`；`time_recharges.order_id` 唯一约束与事务共同保证只到账一次。
- `POST /api/payment/webhook` 必须携带 `X-VisionForge-Signature`，值为 `HMAC-SHA256(VMQ_WEBHOOK_SECRET, 原始请求体)` 的十六进制摘要，可带 `sha256=` 前缀。未配置密钥时接口返回 503，签名错误返回 401。
- V免签 `/appPush` 继续按既有 MD5 协议验签；签名密钥只允许保存在服务端环境变量中。
- 客户端只接受 HTTPS 购买地址；仅开发环境允许 `http://localhost` 或 `http://127.0.0.1`。

`GET /api/client/balance` 至少返回：

```json
{
  "ok": true,
  "balance_seconds": 3600,
  "heartbeat_interval": 30,
  "account_status": "active",
  "ban_reason": ""
}
```

封禁用户返回：

```json
{
  "ok": true,
  "balance_seconds": 3600,
  "account_status": "banned",
  "ban_reason": "违规封禁"
}
```

客户端会立即视为不可启动。

### Admin

- `GET /api/admin/users?limit=50`
- `POST /api/admin/users`
- `GET /api/admin/users/{user_id}`
- `PATCH /api/admin/users/{user_id}`
- `DELETE /api/admin/users/{user_id}`
- `POST /api/admin/users/{user_id}/adjust-time`
- `POST /api/admin/users/{user_id}/ban`
- `POST /api/admin/users/{user_id}/unban`

调整时长请求：

```json
{
  "delta_seconds": 3600,
  "reason": "manual compensation"
}
```

封禁请求：

```json
{
  "reason": "abuse"
}
```

## 日志管理

客户端日志上传接口应与本地日志目录保持一致，服务端按用户、设备、版本和时间索引。

- `POST /api/client/log-bundles`
- `GET /api/admin/logs?user_id=7&limit=50`
- `GET /api/admin/logs/{log_id}`
- `DELETE /api/admin/logs/{log_id}`

`POST /api/client/log-bundles` 必须使用 HTTPS multipart/form-data，并携带普通用户登录 token：

```http
Authorization: Bearer <client_account_token>
```

表单字段：

```text
file          日志文件二进制
client_id     客户端本地匿名 ID
session_id    本次客户端运行会话 ID
file_type     run/events/traces/gui/crash/runtime_inv/runtime_proc/bootstrap/tensorrt/log
filename      原始文件名
size          客户端看到的文件大小
mtime_ns      客户端看到的 mtime_ns
machine_info  JSON，包含 device_profile、client_id、file 元信息
```

成功响应：

```json
{
  "ok": true,
  "message": "Uploaded",
  "data": {
    "file_type": "run",
    "original_name": "run_20260707.txt",
    "file_size": 1234
  }
}
```

客户端不得携带 SSH 密码；当前默认使用账号登录 token，专用上传 token 需要服务端另行实现校验。

日志删除必须保留审计记录，不直接抹除审计证据。

## 系统公告

### Client

- `GET /api/client/announcements?limit=3`

响应：

```json
{
  "ok": true,
  "items": [
    {
      "id": "ann_001",
      "title": "维护通知",
      "body": "今晚 23:00-23:30 进行服务器维护。",
      "level": "info",
      "created_at": "2026-07-06T12:00:00+08:00",
      "starts_at": "2026-07-06T12:00:00+08:00",
      "ends_at": "2026-07-07T12:00:00+08:00",
      "url": ""
    }
  ]
}
```

### Admin

- `GET /api/admin/announcements?limit=50`
- `POST /api/admin/announcements`
- `PATCH /api/admin/announcements/{announcement_id}`
- `DELETE /api/admin/announcements/{announcement_id}`

## 自动更新

客户端只信任 HTTPS manifest。更新包必须提供 SHA256。非强制更新只提示/下载；强制更新会在启动后自动下载、校验、调用外部更新脚本替换当前 EXE 并重启。

- `GET /update/stable.json`
- `GET /api/admin/releases?channel=stable`
- `POST /api/admin/releases`
- `POST /api/admin/releases/{version}/rollback`

manifest 示例见 `packaging/update_manifest.example.json`。核心字段：

```json
{
  "version": "v17.8.61_protected_release_ops",
  "channel": "stable",
  "mandatory": true,
  "min_supported_version": "v17.8.61",
  "notes": "release notes",
  "url": "https://example.com/VisionForge.exe",
  "sha256": "64-char-sha256",
  "installer_url": "https://example.com/VisionForge_Setup.exe",
  "installer_sha256": "64-char-sha256"
}
```

## 管理员 CLI

本仓库提供 `tools/admin_console.py`：

```powershell
$env:VISIONFORGE_ADMIN_TOKEN = "<admin token>"
python tools\admin_console.py users adjust-time 7 --delta-seconds 3600 --reason "manual compensation"
python tools\admin_console.py users ban 7 --reason "abuse"
python tools\admin_console.py announcements create --title "维护通知" --body "今晚维护"
python tools\admin_console.py releases publish --version v17.8.61_protected_release_ops --url https://example.com/VisionForge.exe --sha256 <sha256>
python tools\admin_console.py logs list --user-id 7
```

## 服务器实现注意点

- 不要把云服务器 SSH 密码下发给客户端。
- Admin token 必须可轮换，建议放在服务器环境变量或密钥管理服务。
- 所有 release artifact 应先上传、计算 SHA256、再发布 manifest。
- 强制 HTTPS；公网 HTTP 只允许重定向到 HTTPS。
- 对登录、心跳、购买、日志上传做限流。
- 数据库表至少包括 users、billing_sessions、orders、announcements、releases、log_bundles、admin_audit。
