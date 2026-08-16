package com.visionforge.inferencebenchmark.runtime;

/**
 * Android 运行时对 UI 暴露的稳定生命周期阶段。
 *
 * <p>该枚举刻意独立于 {@code Service}，防止界面层依赖服务内部实现。
 * 新增基础设施状态时，应先映射到这组业务阶段，再交给 UI 展示。</p>
 */
public enum MobileRuntimePhase {
    READY,
    STARTING,
    RUNNING,
    FAILED,
    STOPPED
}
