# 最终包内容边界

本 ZIP 不是轻量示例、补丁包或文档包，而是以已验证 complete-repair 源码包为骨架，再覆盖最终 App/Host/E2E 重建提交的完整可分发工程树。

包内保留：Android App、Windows Host、Server、Sidecar、Shared Protocol、JNI/QNN 预构建运行资产、模型共享库、离线安全依赖、managed-fulfillment 上游源码、部署文件、测试、CI、中文架构文档、原始审计与恢复证据、完整 Git bundle、基线到最终 HEAD 的二进制 patch、逐文件哈希和验证日志。

包内有意不放入：`.git` 内部目录、构建缓存、Python/Gradle/CMake 临时产物、真实 `.env`、私钥、keystore、本机 SDK 绝对路径和字体二进制。`.env.example` 是无凭据的部署模板；安全厂商源码中的 testdata 仅为上游测试夹具。

原三小时工作树的完整字节已经随旧容器回收而丢失；本包是从最后一个可逐字节验证的完整基线进行的确定性重新实现与加强，不冒充旧工作树的逐字节还原。
