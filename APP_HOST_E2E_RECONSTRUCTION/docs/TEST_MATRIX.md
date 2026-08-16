# 最终验证矩阵

| 层 | 验证 | 当前结果 | 证据 |
|---|---|---:|---|
| Baseline | 完整源码 ZIP SHA-256 / CRC / 2865 条目 | PASS | `evidence/INPUT_ARCHIVES_PROVENANCE.json` |
| C++20 | 全新 Release 配置、构建、CTest | **23/23 PASS** | `logs/cmake_final_release_v2_*`、`logs/ctest_final_release_v2.log` |
| C++20 | 256 组成功随机矩阵 + 128 组丢片/冲突矩阵 | PASS | `vfdual_video_transport_simulation_tests`，包含于 CTest 日志 |
| Native safety | ASan + UBSan + leak check | **23/23 PASS** | `logs/ctest_sanitized.log` |
| Java broad | 210 个纯 Java 生产/测试源文件 | 零警告编译，回归 PASS | `logs/java_full_compile_final.log`、`java_full_regression_final.log` |
| Java strict | 35 个新/关键分层源文件 | `-Xlint:all -Werror` PASS | `logs/java_strict_compile_final.log`、`java_strict_regression_final.log` |
| Architecture | Android/Host 依赖方向与复杂度预算 | PASS | `logs/app_host_architecture_audit_final.json` |
| Protocol | Java/C++ magic、20 字节头、epoch、1498 分片、IDR/retired epoch | PASS | `logs/video_transport_contract_audit_final.json` |
| Checker | 门禁工具自测 | 2/2 PASS | `logs/architecture_checker_selftests_final.log` |
| Portable gate | 聚合 App/Host 可移植门禁 | PASS | `logs/app_host_portable_gate_final.log` |
| Python | `compileall`（Server 与工具） | PASS | `logs/python_compileall_final.log` |
| Release identity | 发布 manifest 一致性 | PASS | `logs/release_manifest_consistency_final.log` |
| Release identity | 篡改/未发布状态测试 | 3/3 PASS | `logs/release_manifest_consistency_selftest_final.log` |
| Shell | 项目自有 `.sh` 语法 | 32 个 PASS | `logs/shell_syntax_final.log` |
| Structured files | JSON/YAML 解析 | JSON 16，YAML 14 文件/17 文档 PASS | `logs/structured_file_parse_final.log` |
| Android Gradle | `:app:compileDebugJavaWithJavac` | `NOT_RUN_ENVIRONMENT` | wrapper 需要未缓存的 Gradle 9.2.1，隔离环境无网络；见 `logs/gradle_compile_debug_java.log` |
| Server pytest | Platform/Sidecar 全量 pytest | `NOT_RUN_ENVIRONMENT` | 当前解释器缺少锁定的 bcrypt/slowapi/limits；联网安装失败日志见 `logs/server_dependency_install.log` |
| Windows adapters | DXGI/NVENC/MF production build | `NOT_RUN_EXTERNAL` | 已新增 Windows CI lane；仍需 Windows 2022/目标 GPU |
| Physical Android | MediaCodec/QNN/HTP/USB/Bluetooth | `NOT_RUN_EXTERNAL` | 见 `EXTERNAL_ACCEPTANCE.md` |
| Physical network | CAT6/Wi-Fi 切换与长稳 | `NOT_RUN_EXTERNAL` | 见 `EXTERNAL_ACCEPTANCE.md` |

`PASS` 仅代表证据中实际执行的命令。缺少运行时或硬件的项目不会从静态代码推断为通过。
