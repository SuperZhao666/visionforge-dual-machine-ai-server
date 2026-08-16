# 源码重建来源与真实性边界

## 1. 最高可信源码基线

本次重建直接从当前运行区中真实存在的完整源码包开始：

```text
VisionForge_DualMachineAI_Server_complete_repair.zip
SHA-256: 015ec5fcc8a019f8afc33dbc6f00e6ffb6d6c4e05c6e4d518246c5aa8e50f052
ZIP entries: 2865
```

该包先通过整体 SHA-256、ZIP CRC 和内部文件清单核验，再完整解压为独立 Git 工作树。原始 ZIP 不被覆盖或就地修改。

## 2. 后续三小时任务的可恢复证据

恢复总包保留了：

- App / Host 架构重构的最终交付说明；
- 旧工作树的已修改路径和新增路径；
- 真实执行过的测试结果；
- 两份关键协议源码片段；
- 两轮审查指南与机器修复账本；
- 打包失败路径和事故上下文。

它没有保留丢失工作树的全部文件字节、完整 Git commit 或原最终 ZIP。因此本次成果是以完整旧基线为底、按证据进行的**确定性重新实现和再次审查**，不是对已经不存在的工作树作“逐字节找回”的虚假声明。

## 3. 重建方法

1. 将完整基线提交并打标签 `verified-complete-repair-baseline`；
2. 把历史修改/新增路径转为回放清单；
3. 先恢复线协议、帧身份、分片重组和 IDR 发布不变量；
4. 再恢复 Android UI/Service 边界、Host facade/DTO 和组合根；
5. 将纯领域实现与生产适配器同时纳入 CMake/Javac 构建图；
6. 对 Java/C++ 常量、帧身份和分片上限做自动漂移检查；
7. 运行 Release、随机仿真、ASan/UBSan、Java 全量与严格回归；
8. 将原始审计文档、账本、输入归档哈希和全部验证日志固化到交付包；
9. 从干净暂存目录生成单根 ZIP，解压回读并逐文件复核；
10. 上传 Drive 后再次下载原始二进制，比较大小、SHA-256、CRC 和内部清单。

## 4. 不做的伪装

- 不把原先 3.77 MB 的轻量重建包当作完整源码；
- 不把“文档描述存在”当作“源码已恢复”；
- 不把无法联网下载 Gradle/Server 依赖写成 PASS；
- 不把 Linux 上通过的纯协议测试写成 Windows DXGI/NVENC 真机通过；
- 不把 Java 自测写成 Android MediaCodec/QNN/USB/Bluetooth 真机通过；
- 不把 ZIP 上传请求成功写成 Drive 回读成功，必须下载回读并重新计算。
