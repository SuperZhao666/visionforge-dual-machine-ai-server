package com.visionforge.inferencebenchmark.ui;

/** Dependency-free contract for bounded state-transition effects. */
public final class FxTransitionPolicySelfTest {
    private FxTransitionPolicySelfTest() {
    }

    public static void run() {
        upgradesCelebrateAndDowngradesStayQuiet();
        unchangedStatesProduceNoEffect();
        everyEffectIsStrictlyBounded();
    }

    private static void upgradesCelebrateAndDowngradesStayQuiet() {
        int stageUp = FxTransitionPolicy.forStageChange(false, true);
        require((stageUp & FxTransitionPolicy.EFFECT_PULSE_RING) != 0);
        require((stageUp & FxTransitionPolicy.EFFECT_PARTICLE_BURST) != 0);
        require((stageUp & FxTransitionPolicy.EFFECT_COLOR_SWEEP) != 0);
        int stageDown = FxTransitionPolicy.forStageChange(true, false);
        require(stageDown == FxTransitionPolicy.EFFECT_COLOR_SWEEP);
        require(FxTransitionPolicy.forConnectionChange(false, true)
                == FxTransitionPolicy.forStageChange(false, true));
    }

    private static void unchangedStatesProduceNoEffect() {
        require(FxTransitionPolicy.forStageChange(false, false) == FxTransitionPolicy.EFFECT_NONE);
        require(FxTransitionPolicy.forStageChange(true, true) == FxTransitionPolicy.EFFECT_NONE);
        require(FxTransitionPolicy.forConnectionChange(true, true) == FxTransitionPolicy.EFFECT_NONE);
    }

    private static void everyEffectIsStrictlyBounded() {
        // The accessibility tree must return to idle: no effect may exceed the
        // design-system ceiling, and combined effects stay bounded too.
        require(FxTransitionPolicy.PULSE_DURATION_MS
                <= FxTransitionPolicy.MAX_EFFECT_DURATION_MS);
        require(FxTransitionPolicy.BURST_DURATION_MS
                <= FxTransitionPolicy.MAX_EFFECT_DURATION_MS);
        require(FxTransitionPolicy.SWEEP_DURATION_MS
                <= FxTransitionPolicy.MAX_EFFECT_DURATION_MS);
        require(FxTransitionPolicy.SEMANTIC_FADE_MS
                <= FxTransitionPolicy.MAX_EFFECT_DURATION_MS);
        int everything = FxTransitionPolicy.EFFECT_PULSE_RING
                | FxTransitionPolicy.EFFECT_PARTICLE_BURST
                | FxTransitionPolicy.EFFECT_COLOR_SWEEP;
        require(FxTransitionPolicy.boundedDurationMs(everything)
                <= FxTransitionPolicy.MAX_EFFECT_DURATION_MS);
        require(FxTransitionPolicy.boundedDurationMs(FxTransitionPolicy.EFFECT_NONE) == 0L);
        require(FxTransitionPolicy.BURST_PARTICLE_COUNT > 0
                && FxTransitionPolicy.BURST_PARTICLE_COUNT <= 64);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("FX transition policy contract failed");
    }
}
