package com.visionforge.inferencebenchmark;

/** Separates recoverable timing stalls from evidence that the vendor codec is unusable. */
final class DecoderFallbackPolicy {
    enum FailureKind {
        WATCHDOG_STALL,
        CODEC_EXCEPTION,
        STATE_EXCEPTION,
        CODEC_CONTRACT
    }

    private DecoderFallbackPolicy() {
    }

    static boolean permitsSoftwareFallback(FailureKind kind) {
        return kind != FailureKind.WATCHDOG_STALL;
    }
}
