# ADR-005：候选 epoch 两阶段提交

- **状态**：Accepted
- **问题**：若接收端在看到一个更高 epoch 的首个分片时立即推进高水位，单个残缺、冲突或非 IDR 访问单元就能退休仍然健康的当前流，形成远程会话抢占与预测链断裂。
- **决策**：接收端只允许一个有界 candidate epoch。candidate 与当前流按 `(stream_epoch, frame_sequence)` 完全隔离；完成重组后仍不自动提交。只有 H.264 预检确认访问单元完整、可用、为新鲜 IDR，组合根才调用 `commitCandidateEpoch` 推进高水位。
- **失败语义**：candidate 的冲突、超时、资源超限、malformed 或非 IDR 只清理 candidate、请求 IDR 并保留当前流。当前流自身出现缺口时仍 fail-closed。
- **后果**：新会话切换多一个显式确认步骤，但消除了高 epoch 半帧抢占；C++ 与 Java 都必须通过同一组候选冲突、超时、非 IDR 和有效 IDR 提交测试。
