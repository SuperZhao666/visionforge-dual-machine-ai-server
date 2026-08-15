# VisionForge Platform

VisionForge 产品官网 + 卡密商城 + 管理后台 + 日志收集平台。

## 技术栈

FastAPI + Jinja2 + SQLite，单文件数据库，无需额外运维。

## 快速开始

### 1. 安装依赖

python -m venv venv
venv\Scripts\pip install -r requirements.txt

### 2. 配置环境变量

copy config.example.py config.py

编辑 config.py 填入真实值（YunGouOS商户号/密钥等）。

邮箱验证码必须由部署环境注入 `SMTP_HOST`、`SMTP_PORT`、`SMTP_USER`、
`SMTP_PASSWORD`、`SMTP_USE_TLS`。`EMAIL_CODE_SEND_COOLDOWN_SECONDS` 控制同一
规范化邮箱的发送冷却，默认 60 秒。不同邮箱不共享应用级注册验证码或注册提交
额度；注册提交由一次性邮箱验证码约束，Nginx 仅保留高阈值的异常流量保护。仓库
内不保存 SMTP 账号或密码；更换既有凭据后应同步轮换部署环境中的旧密码。

### 3. 生成RSA密钥对

venv\Scripts\python -c "from app.services.license_service import init_platform_keys; init_platform_keys()"

### 4. 启动开发服务器

venv\Scripts\python run.py

打开 http://127.0.0.1:8000

## 创建管理员

venv\Scripts\python -c "
from app.database import get_connection
from app.security import hash_password
conn = get_connection()
conn.execute('INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)',
    ('admin', 'admin@example.com', hash_password('your-admin-password')))
conn.commit()
conn.close()
print('Admin created')
"

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/client/register | 客户端账号注册 |
| POST | /api/client/login | 客户端账号登录 |
| GET | /api/client/balance | 查询时长余额 |
| POST | /api/client/redemptions | 当前账号兑换一次性时长码 |
| GET | /api/client/referrals | 查询专属邀请码、奖励汇总与邀请历史 |
| GET | /api/client/referrals/summary | 查询邀请汇总（不含历史明细） |
| GET | /api/client/time/entries | 查询购买、兑换、邀请等时长入账记录 |
| POST | /api/client/account/password | 验证当前密码并修改密码、轮换 JWT |
| POST | /api/client/account/email-code | 向新邮箱发送修改验证码 |
| POST | /api/client/account/email | 验证当前密码与验证码后修改绑定邮箱 |
| POST | /api/client/purchase-link | 创建一次性购买会话 |
| GET | /api/client/purchase-status/{token} | 查询购买状态 |
| GET | /api/client/purchase-history | 查询历史订单 |
| POST | /api/client/session-start | 开始计费会话 |
| POST | /api/client/session-heartbeat | 运行时扣费心跳 |
| POST | /api/client/session-end | 结束计费会话 |
| GET | /api/client/runtime/catalog | 获取离线签名的运行时目录（只需登录，不检查余额） |
| POST | /api/client/runtime/download-ticket | 为当前已发布组件签发 CDN 短时票据 |
| POST | /api/client/runtime/events | 幂等上传最小安装事件 |
| POST | /api/license/activate | 客户端激活卡密 |
| POST | /api/license/verify | 客户端启动验证 |
| POST | /api/client/log-bundles | 已登录客户端日志包上传 |
| GET | /appPush | V免签支付回调（`type=1` 微信，`type=2` 支付宝） |
| POST | /api/payment/webhook | HMAC 签名 JSON 支付回调 |
| GET/POST | /admin/payment-qr | 管理员查看并上传微信/支付宝定额收款码 |
| GET/POST | /admin/growth* | 管理兑换、邀请奖励与时长权益 |
| POST | /api/integrations/code-issuances/issue | HMAC 服务身份按不透明幂等令牌即时取一张码 |

支付宝定额收款码的设计、监听端配置和验证步骤见 [docs/ALIPAY_QR_PAYMENT.md](docs/ALIPAY_QR_PAYMENT.md)。

兑换码不会预生成入库：管理员、外部订单或后续代理请求发生时才按数量生成。数据库只保存兑换码 HMAC 摘要、尾号和可恢复的服务端派生引用；完整码只在生成 CSV 或私有取码响应中出现。兑换状态与时长入账在同一 SQLite `BEGIN IMMEDIATE` 事务完成，数据库唯一约束确保一张码只能给一个账号增加一次时长。

注册接口新增可选 `invite_code`，不传时保持旧客户端行为。有效邀请码在注册事务内唯一绑定新用户并即时给邀请人增加管理员配置的时长；禁止老用户补绑、一个新用户绑定多人、自邀和同一注册事件重复奖励。用户端历史只返回脱敏用户名。

闲鱼账号、商品、套餐、订单、卡券、自动发货规则和发货日志全部归独立闲鱼系统管理；Platform 不再复制这些功能。内网取码桥接、API 卡配置和单 SKU 验收见 [deploy/xianyu-fulfillment/README.md](deploy/xianyu-fulfillment/README.md)。

## 部署

本次 EXE 更新不需要 CDN、对象存储或第三方发布平台：签名清单和 `.exe`/`.vfdiff` 均由当前 Platform 与 Nginx 从 `app/static/releases/` 提供。可选的运行时组件目录是另一套能力；只有启用该能力时才需要阅读项目根目录 `docs/RUNTIME_PROVISIONING.md`，它不属于 EXE 更新链路。

### 服务器配置

git clone <repo> /home/ubuntu/vf-platform
cd /home/ubuntu/vf-platform
python -m venv venv
venv/bin/pip install -r requirements.txt

### 配置Nginx

sudo bash deploy/final_setup.sh

### 配置systemd

`deploy/final_setup.sh` 会安装并启动 `vf.service`，在覆盖 Nginx 站点前保留备份，且只有 `nginx -t` 成功后才 reload。

### SSL证书

sudo apt install certbot python3-certbot-nginx
sudo certbot certonly --nginx -d visionforge.cloud -d www.visionforge.cloud

证书就绪后运行 `sudo bash deploy/final_setup.sh`。生产配置固定使用现有域名 `www.visionforge.cloud`，更新文件只保存在当前服务器 `/home/ubuntu/vf-platform/app/static/releases/`。

## 安全注意事项

- 私钥以 AES-256-GCM 加密存储，密码通过环境变量注入
- 修改密码会递增账号认证版本，使旧 JWT 立即失效
- 邮箱验证码以 HMAC-SHA256 保存；日志只记录邮箱的 HMAC 标识、TraceId 和脱敏 SMTP 状态码，不记录邮箱、验证码、密码或令牌
- 配置文件 .gitignore 排除，永不提交
- 以非 root 用户运行
- UFW仅开放80/443端口
- 生产环境单独配置 `REDEMPTION_CODE_SECRET`、`CODE_ISSUANCE_HMAC_SECRET` 与 `CODE_ISSUANCE_SERVICE_ID`；密钥不得写入日志或管理页面
