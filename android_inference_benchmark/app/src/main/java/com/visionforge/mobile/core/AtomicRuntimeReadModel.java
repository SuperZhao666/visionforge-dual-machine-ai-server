package com.visionforge.mobile.core;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/** Thread-safe state publication without exposing mutable service internals. */
public final class AtomicRuntimeReadModel implements RuntimeReadModel {
    private final AtomicReference<RuntimeSnapshot> snapshot;

    public AtomicRuntimeReadModel(String correlationId) {
        Objects.requireNonNull(correlationId, "correlationId");
        if (correlationId.isBlank() || correlationId.length() > 128) {
            throw new IllegalArgumentException("correlationId must be non-blank and at most 128 characters");
        }
        snapshot = new AtomicReference<>(new RuntimeSnapshot(
                RuntimeSnapshot.Lifecycle.STOPPED,
                RuntimeSnapshot.VideoState.IDLE,
                RuntimeSnapshot.TransportState.DISCONNECTED,
                RuntimeSnapshot.ControlBlocker.TRANSPORT_NOT_READY,
                0L,
                0L,
                0L,
                Duration.ZERO,
                correlationId));
    }

    @Override
    public RuntimeSnapshot snapshot() {
        return snapshot.get();
    }

    public void publish(RuntimeSnapshot next) {
        snapshot.set(Objects.requireNonNull(next, "next"));
    }
}
