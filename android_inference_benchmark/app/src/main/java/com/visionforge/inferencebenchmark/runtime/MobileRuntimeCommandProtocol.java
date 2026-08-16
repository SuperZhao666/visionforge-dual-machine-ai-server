package com.visionforge.inferencebenchmark.runtime;

/**
 * 前台 Service 的集中命令协议。
 *
 * <p>所有 action 在这里定义和解析；未知 action 映射为 {@link Command#UNKNOWN}，
 * 调用方必须保持无副作用，避免拼写错误意外启动或改变运行时。</p>
 */
public final class MobileRuntimeCommandProtocol {
    public static final String ACTION_ENSURE =
            "com.visionforge.mobile.runtime.ENSURE";
    public static final String ACTION_REFRESH_POWER_POLICY =
            "com.visionforge.mobile.runtime.REFRESH_POWER_POLICY";

    public enum Command {
        ENSURE,
        REFRESH_POWER_POLICY,
        UNKNOWN
    }

    private MobileRuntimeCommandProtocol() {}

    public static Command parse(String action, boolean nullMeansEnsure) {
        if (action == null) {
            return nullMeansEnsure ? Command.ENSURE : Command.UNKNOWN;
        }
        if (ACTION_ENSURE.equals(action)) return Command.ENSURE;
        if (ACTION_REFRESH_POWER_POLICY.equals(action)) {
            return Command.REFRESH_POWER_POLICY;
        }
        return Command.UNKNOWN;
    }
}
