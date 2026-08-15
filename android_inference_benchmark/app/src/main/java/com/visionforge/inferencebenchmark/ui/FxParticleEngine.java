package com.visionforge.inferencebenchmark.ui;

/**
 * Dependency-free particle burst engine for UI state-transition effects.
 *
 * <p>Deterministic (seeded) so the behaviour is unit-testable and identical
 * across devices. Bursts are strictly bounded: particles decay and the engine
 * reports when nothing is alive anymore, so the hosting view can stop
 * invalidating and the accessibility tree can return to idle. No perpetual
 * ambient animation is ever produced here.</p>
 */
public final class FxParticleEngine {
    /** A single burst particle in view-local pixel space. */
    public static final class Particle {
        public float x;
        public float y;
        public float vx;
        public float vy;
        public float size;
        public float ageMillis;
        public float maxAgeMillis;

        /** Remaining life fraction in [0,1]; 0 means dead. */
        public float lifeFraction() {
            if (maxAgeMillis <= 0.0f) return 0.0f;
            float remaining = 1.0f - ageMillis / maxAgeMillis;
            return remaining < 0.0f ? 0.0f : remaining;
        }
    }

    private final Particle[] particles;
    private final long[] state = new long[1];
    private int aliveCount;

    public FxParticleEngine(int capacity, long seed) {
        if (capacity <= 0) throw new IllegalArgumentException("capacity");
        particles = new Particle[capacity];
        for (int i = 0; i < capacity; i++) particles[i] = new Particle();
        state[0] = seed == 0L ? 0x9E3779B97F4A7C15L : seed;
        aliveCount = 0;
    }

    /** Spawns a radial burst centred at (cx, cy); resets any previous burst. */
    public void burst(float cx, float cy, int count, float maxSpeedPxPerSec,
                      float maxSizePx, float maxAgeMillis) {
        int spawned = Math.min(count, particles.length);
        aliveCount = spawned;
        for (int i = 0; i < particles.length; i++) {
            Particle p = particles[i];
            if (i >= spawned) {
                p.ageMillis = 0.0f;
                p.maxAgeMillis = 0.0f;
                continue;
            }
            double angle = nextDouble() * Math.PI * 2.0;
            double speed = (0.25 + 0.75 * nextDouble()) * maxSpeedPxPerSec;
            p.x = cx;
            p.y = cy;
            p.vx = (float) (Math.cos(angle) * speed);
            p.vy = (float) (Math.sin(angle) * speed);
            p.size = 1.5f + (float) nextDouble() * maxSizePx;
            p.ageMillis = 0.0f;
            p.maxAgeMillis = maxAgeMillis * (0.55f + 0.45f * (float) nextDouble());
        }
    }

    /**
     * Advances the simulation; returns true while at least one particle lives.
     * The host stops the animation loop as soon as this returns false.
     */
    public boolean advance(float dtMillis) {
        if (aliveCount == 0) return false;
        float dtSec = dtMillis / 1_000.0f;
        int alive = 0;
        for (Particle p : particles) {
            if (p.maxAgeMillis <= 0.0f || p.ageMillis >= p.maxAgeMillis) continue;
            p.ageMillis += dtMillis;
            p.x += p.vx * dtSec;
            p.y += p.vy * dtSec;
            // Mild drag + gravity lift for a tech-spark feel.
            p.vx *= 0.985f;
            p.vy = p.vy * 0.985f + 22.0f * dtSec;
            if (p.ageMillis < p.maxAgeMillis) alive++;
        }
        aliveCount = alive;
        return alive > 0;
    }

    public int aliveCount() {
        return aliveCount;
    }

    public Particle[] particles() {
        return particles;
    }

    /** SplitMix64-style step; deterministic per engine instance. */
    private double nextDouble() {
        long z = (state[0] += 0x9E3779B97F4A7C15L);
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        z = z ^ (z >>> 31);
        return (z >>> 11) * 0x1.0p-53;
    }
}
