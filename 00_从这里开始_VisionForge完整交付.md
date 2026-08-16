# VisionForge / MINGSIM 完整工程交付入口

本源码树以已验证的 `VisionForge_DualMachineAI_Server_complete_repair.zip` 为完整基线，按照恢复出的两轮审计指南、机器修复账本、三小时 App/Host 工作记录、已知路径和协议片段，重新实现并再次审查丢失的 Android App、Windows Host、截图/视频推流与移动控制改造。

这不是把几 MB 的示例工程包装成“完整项目”。当前树保留完整 Android、Host、Server、Sidecar、Shared Protocol、QNN/JNI 运行资产、测试、部署、CI 和历史修复材料。原始三小时工作树的完整字节已经丢失，因此本交付的准确性质是：**从最后一个可逐字节验证的完整源码基线进行确定性重建、加强和重新验证**。

建议按以下顺序阅读：

1. `APP_HOST_E2E_RECONSTRUCTION/docs/00_从这里开始_维护人员阅读顺序.md`
2. `APP_HOST_E2E_RECONSTRUCTION/docs/FINAL_REPAIR_REPORT_zh-CN.md`
3. `docs/APP_HOST_ARCHITECTURE_zh-CN.md`
4. `docs/HOST_APP_E2E_STREAMING_zh-CN.md`
5. `docs/MOBILE_CONTROL_STATE_zh-CN.md`
6. `APP_HOST_E2E_RECONSTRUCTION/docs/TEST_MATRIX.md`
7. ZIP 根目录中的 `FINAL_STATUS.json`、`MANIFEST_SHA256.json` 与 `SHA256SUMS.txt`

可移植验证入口：

```bash
tools/run_app_host_e2e_portable_checks.sh
```

已执行通过的范围包括 C++20 Release CTest、ASan/UBSan、随机丢包/乱序/重复/冲突仿真、完整纯 Java 回归、关键 Java 严格编译、协议漂移门禁、架构边界门禁、Python compileall、发布清单与结构化文件检查。

真实 Windows DXGI/NVENC/Media Foundation、Android Gradle/SDK/NDK/MediaCodec/QNN、MAKCU、Bluetooth、物理网络长稳、支付、SMTP、生产签名和灾备恢复必须在目标设备或生产环境执行，包内明确标记为 `NOT_RUN_ENVIRONMENT` 或 `NOT_RUN_EXTERNAL`，没有伪报为 PASS。
