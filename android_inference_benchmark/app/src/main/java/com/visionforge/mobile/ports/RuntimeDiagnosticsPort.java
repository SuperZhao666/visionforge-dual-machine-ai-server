package com.visionforge.mobile.ports;

/** 低基数诊断事件端口；生产适配器负责脱敏日志与指标，domain/application 不依赖日志框架。 */
@FunctionalInterface
public interface RuntimeDiagnosticsPort {
    void record(String code, String detail);

    static RuntimeDiagnosticsPort noop() {
        return (code, detail) -> { };
    }
}
