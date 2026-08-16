package com.visionforge.inferencebenchmark.runtime;

import java.util.Objects;

/**
 * Service 对外能力的显式组合根。
 *
 * <p>Android {@code Service} 负责生命周期和基础设施装配；本对象只冻结对 UI
 * 的绑定端口，并集中发布不可变读模型。这样 UI 永远不需要访问 Service 私有
 * 枚举、线程、JNI、MediaCodec、USB 或 Bluetooth 具体实现。</p>
 */
public final class MobileRuntimeCompositionRoot {
    private final MobileRuntimeBinding binding;

    public MobileRuntimeCompositionRoot(MobileRuntimeBinding binding) {
        this.binding = Objects.requireNonNull(binding, "binding");
    }

    public MobileRuntimeBinding binding() {
        return binding;
    }

    public void publish(MobileRuntimeReadModel model) {
        MobileRuntimeReadModelStore.publish(model);
    }

    public void publishEthernetDiagnostics(String diagnostics) {
        MobileRuntimeReadModelStore.publishEthernetDiagnostics(diagnostics);
    }
}
