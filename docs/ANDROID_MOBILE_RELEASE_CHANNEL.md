# 双机安卓正式发布通道

安卓 APK 使用独立静态目录，不复用也不修改单机 Windows 的
`/static/releases/` 与 `/update/stable.json`：

- 清单：`/static/dual-machine-mobile/latest.json`，始终 `no-store`；
- 制品：`/static/dual-machine-mobile/<sha256>.apk`，内容寻址且长期不可变缓存；
- 其他 APK 文件名、嵌套路径与未知文件一律返回 404；
- 发布工具拒绝版本号回退，也拒绝同一 `versionCode` 对应不同 APK；已有清单字段损坏时失败关闭，不允许覆盖；
- 远端目录必须是规范化的 `.../app/static/dual-machine-mobile` 路径；客户端与远端提交脚本都会复核，禁止指向单机发布目录、根目录或遍历路径；
- 远端先校验 APK 哈希，再原子切换清单；清单始终最后提交，仅清理移动发布目录内由本工具管理的旧内容寻址 APK；
- APK 必须通过正式签名、包名、QNN 运行时和模型静态校验，签名证书还必须与指定生产证书一致。

将
`server/visionforge-platform/deploy/nginx/dual_machine_mobile_release_location.conf.example`
安装到现有 `visionforge.cloud` HTTPS `server {}` 内并通过 `nginx -t` 后，执行：

```powershell
$env:VISIONFORGE_ANDROID_EXPECTED_SIGNER_SHA256 = '<production-certificate-sha256>'
python tools\publish_android_mobile_release.py `
  --apk C:\path\VFMobile.apk `
  --output-dir .\_release_staging\android-online-current `
  --ssh-target ubuntu@81.70.189.154 `
  --remote-dir /home/ubuntu/vf-platform/app/static/dual-machine-mobile
```

发布后必须从公网重新下载 `latest.json` 与清单中的 APK，并独立计算 SHA256；
本地源 APK、线上 APK 与实体机 `installed-base.apk` 三者必须完全相同。
