package com.visionforge.inferencebenchmark.runtime;

import java.util.Objects;

/**
 * Immutable UI-facing runtime state.
 *
 * <p>The Activity consumes this value object instead of reading private Service
 * fields or reconstructing state from unrelated booleans.</p>
 */
public final class MobileRuntimeReadModel {
    public final MobileRuntimePhase phase;
    public final String detail;
    public final String failureCode;
    public final long revision;

    public MobileRuntimeReadModel(
            MobileRuntimePhase phase,
            String detail,
            long revision) {
        this(phase, detail, "none", revision);
    }

    public MobileRuntimeReadModel(
            MobileRuntimePhase phase,
            String detail,
            String failureCode,
            long revision) {
        this.phase = Objects.requireNonNull(phase, "phase");
        this.detail = normalize(detail, "unspecified");
        this.failureCode = normalize(failureCode, "unknown");
        this.revision = Math.max(0L, revision);
    }

    private static String normalize(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
