package com.visionforge.inferencebenchmark.ui;

/**
 * Pure mapping from UI state transitions to bounded visual effects.
 *
 * <p>Every effect is strictly time-bounded so screens settle back to a fully
 * idle accessibility tree. Durations are constants of the design system and
 * covered by the dependency-free self test.</p>
 */
public final class FxTransitionPolicy {
    /** No visual effect; the state did not change or does not deserve one. */
    public static final int EFFECT_NONE = 0;
    /** Single expanding pulse ring around the affected component. */
    public static final int EFFECT_PULSE_RING = 1;
    /** One-shot particle burst from the component centre. */
    public static final int EFFECT_PARTICLE_BURST = 2;
    /** Cross-fade of the component surface/accent colours. */
    public static final int EFFECT_COLOR_SWEEP = 4;

    public static final long PULSE_DURATION_MS = 550L;
    public static final long BURST_DURATION_MS = 800L;
    public static final long SWEEP_DURATION_MS = 350L;
    /** Bounded fade for semantic decorations (stage bar, icon glow plate). */
    public static final long SEMANTIC_FADE_MS = 200L;
    public static final int BURST_PARTICLE_COUNT = 36;
    /** Hard ceiling for any single effect; guards the idle contract. */
    public static final long MAX_EFFECT_DURATION_MS = 1_200L;

    private FxTransitionPolicy() {
    }

    /**
     * Stage health transition on the unified inference screen. Becoming ready/running is a
     * celebration (pulse + burst + colour); losing health is a quiet colour
     * sweep only; unchanged states produce nothing.
     */
    public static int forStageChange(boolean wasHealthy, boolean nowHealthy) {
        if (wasHealthy == nowHealthy) return EFFECT_NONE;
        return nowHealthy
                ? EFFECT_PULSE_RING | EFFECT_PARTICLE_BURST | EFFECT_COLOR_SWEEP
                : EFFECT_COLOR_SWEEP;
    }

    /** Hero/connection level transition; identical semantics, one level up. */
    public static int forConnectionChange(boolean wasLive, boolean nowLive) {
        return forStageChange(wasLive, nowLive);
    }

    /** Total bounded duration for an effect bitmask. */
    public static long boundedDurationMs(int effects) {
        long duration = 0L;
        if ((effects & EFFECT_PULSE_RING) != 0) duration = Math.max(duration, PULSE_DURATION_MS);
        if ((effects & EFFECT_PARTICLE_BURST) != 0) duration = Math.max(duration, BURST_DURATION_MS);
        if ((effects & EFFECT_COLOR_SWEEP) != 0) duration = Math.max(duration, SWEEP_DURATION_MS);
        return duration;
    }
}
