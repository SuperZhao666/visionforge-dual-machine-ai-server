# VisionForge Platform 业务加固决策

## 分层边界

```text
FastAPI route
  -> domain service
    -> SQLite transaction / storage adapter
```

Route 负责认证、CSRF、请求体上限和协议映射；service 负责业务状态机与事务；数据库和文件系统只在 service/基础设施层被操作。管理员 API、支付和日志上传均遵守该方向。

## 支付状态机

- 回调事件先按来源和事件标识去重，再校验订单、金额与候选状态。
- 金额统一转换为整数分，禁止浮点比较。
- `received`、`unmatched`、`ambiguous`、`order_not_found` 是可重试状态；后续回调可重新匹配。
- `delivered` 是终态，同一事件只能完成一次充值与交付。
- 相同事件标识若来源或金额冲突，必须拒绝，不能复用历史成功结果。
- 回调重处理与交付在 `BEGIN IMMEDIATE` 事务中完成，保证并发下只有一次交付。

## 管理员业务

- `admin_api` 只暴露控制台需要的稳定契约，用户、公告、发布、日志和审计逻辑下沉到 `admin_service`。
- 删除用户采用软删除和匿名化，保留支付、充值及审计历史。
- 角色、状态或封禁变化必须提升 `auth_version`，使旧令牌失效。
- 管理员权限每次从数据库读取当前角色和状态，不信任 JWT 中可能过期的角色声明。

## 日志上传

- 所有上传接口必须认证；停用用户令牌无效。
- 请求体、ZIP 条目数、单条解压大小和总解压大小均有上限，并拒绝路径穿越。
- 文件先写 staging，数据库事务成功后原子改名；失败时清理 staging。
- 所有者和会话标识具有唯一约束，内容 SHA 相同的重试保持幂等。
- 删除日志先提交数据库状态，再执行受限目录中的物理删除。

## Web 安全

- 登录启用速率限制、失败计数、账户状态检查和可选 TOTP。
- 状态修改表单要求签名 CSRF cookie 与表单 token 一致。
- Cookie 使用 HttpOnly、SameSite=Strict，并按部署环境启用 Secure。
- 支付回调先验证原始请求体签名，再解析 JSON。

## 并发与验证

- SQLite 连接启用 WAL，并按数据库路径缓存初始化。
- 支付、日志会话和管理员修改的并发测试必须证明唯一交付、唯一文件及一致审计结果。

```powershell
python -m pytest -q
python -m ruff check .
```
