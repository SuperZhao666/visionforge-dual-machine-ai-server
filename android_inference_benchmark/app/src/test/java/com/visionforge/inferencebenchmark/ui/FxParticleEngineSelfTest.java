package com.visionforge.inferencebenchmark.ui;

/** Dependency-free contract for the bounded particle burst engine. */
public final class FxParticleEngineSelfTest {
    private FxParticleEngineSelfTest() {
    }

    public static void run() {
        burstIsDeterministicPerSeed();
        simulationAlwaysSettles();
        deadEngineReportsIdle();
    }

    private static void burstIsDeterministicPerSeed() {
        FxParticleEngine first = new FxParticleEngine(16, 42L);
        FxParticleEngine second = new FxParticleEngine(16, 42L);
        first.burst(100.0f, 200.0f, 16, 240.0f, 6.0f, 700.0f);
        second.burst(100.0f, 200.0f, 16, 240.0f, 6.0f, 700.0f);
        for (int i = 0; i < 16; i++) {
            require(first.particles()[i].vx == second.particles()[i].vx);
            require(first.particles()[i].vy == second.particles()[i].vy);
            require(first.particles()[i].maxAgeMillis == second.particles()[i].maxAgeMillis);
        }
        require(first.aliveCount() == 16);
    }

    private static void simulationAlwaysSettles() {
        FxParticleEngine engine = new FxParticleEngine(36, 7L);
        engine.burst(50.0f, 50.0f, 36, 320.0f, 8.0f, 800.0f);
        // Step generously past the longest possible particle life.
        boolean alive = true;
        for (int i = 0; i < 200 && alive; i++) alive = engine.advance(16.0f);
        require(!alive);
        require(engine.aliveCount() == 0);
        // Every particle must report a fully decayed life fraction.
        for (FxParticleEngine.Particle p : engine.particles()) {
            require(p.lifeFraction() == 0.0f);
        }
    }

    private static void deadEngineReportsIdle() {
        FxParticleEngine engine = new FxParticleEngine(4, 1L);
        require(!engine.advance(16.0f));
        engine.burst(0.0f, 0.0f, 0, 100.0f, 4.0f, 500.0f);
        require(engine.aliveCount() == 0);
        require(!engine.advance(16.0f));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("FX particle engine contract failed");
    }
}
