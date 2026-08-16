# App/Host 端到端契约核心

本目录保存从三小时遗失任务说明与后续检查点中重新固化的、可在 Linux/Windows 上独立编译的纯 C++20 领域核心。它不是示例代码：根 CMake 已将其纳入 `vfdual_test_build`，并由 CTest 执行协议、epoch、候选会话、IDR 完整交付、虚拟桌面负坐标、控制 ticket 与运行门面的回归测试。

平台相关 DXGI/NVENC/UDP/MediaCodec 仍位于原有 Host 与 Android 模块；本目录只承载跨平台不变量，防止平台适配器把业务语义重新复制成彼此漂移的实现。
