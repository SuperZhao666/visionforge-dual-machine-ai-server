# 临时 IP HTTPS 运维说明

## 目的与边界

域名备案期间，客户端通过 `https://81.70.189.154` 访问平台。客户端只内置信任 `assets/visionforge_ip_root_ca.pem`，不修改 Windows 系统证书库，也不分发 SSH 账户、密码或私钥。

IP 默认站点只代理 `/api/client/` 与 `/update/<channel>.json`。管理端、支付回调、静态文件和其他路径均返回 404；正式域名站点继续使用公网 CA 证书和原有路由。

## 密钥与证书位置

- 离线根 CA 私钥（仅所有者 Windows 账户与 SYSTEM 可读）：`%LOCALAPPDATA%\\VisionForgeOwner\\pki\\visionforge_ip_root_ca.key`
- 客户端公有根证书：`assets/visionforge_ip_root_ca.pem`
- 服务器叶证书：`/etc/nginx/ssl/visionforge-ip/server.pem`
- 服务器叶私钥：`/etc/nginx/ssl/visionforge-ip/server.key`，权限必须为 `0600 root:root`

根 CA 私钥不得上传服务器、进入仓库、进入安装包或出现在日志中。

## 部署门禁

变更前备份 `/etc/nginx/sites-available/00-default-deny`，然后依次执行：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

使用仓库中的 CA 验证 IP 更新接口和客户端接口；同时验证 `/api/admin/`、`/openapi.json` 返回 404，并复测正式域名 HTTPS。

## 备案完成后的撤销

发布一个把 `platform.api_url` 和更新清单迁回正式域名的客户端版本。确认活跃版本完成迁移后，恢复默认 443 的 `return 444` 配置，执行 `nginx -t` 和 reload，再删除服务器叶私钥与叶证书。离线根 CA 私钥按密钥销毁流程处理，客户端后续版本移除公有根证书。
