package com.visionforge.inferencebenchmark.runtime;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** Process-local, immutable read-model publication point. */
public final class MobileRuntimeReadModelStore {
    private static final AtomicReference<MobileRuntimeReadModel> CURRENT =
            new AtomicReference<>(new MobileRuntimeReadModel(
                    MobileRuntimePhase.STOPPED,
                    "runtime_not_started",
                    0L));
    private static final AtomicReference<String> ETHERNET_DIAGNOSTICS =
            new AtomicReference<>("ethernet_not_observed");

    private MobileRuntimeReadModelStore() {}

    public static MobileRuntimeReadModel snapshot() {
        return CURRENT.get();
    }

    public static void publish(MobileRuntimeReadModel model) {
        CURRENT.set(Objects.requireNonNull(model, "model"));
    }

    public static String ethernetDiagnostics() {
        return ETHERNET_DIAGNOSTICS.get();
    }

    public static void publishEthernetDiagnostics(String diagnostics) {
        if (diagnostics != null && !diagnostics.isBlank()) {
            ETHERNET_DIAGNOSTICS.set(diagnostics);
        }
    }
}
