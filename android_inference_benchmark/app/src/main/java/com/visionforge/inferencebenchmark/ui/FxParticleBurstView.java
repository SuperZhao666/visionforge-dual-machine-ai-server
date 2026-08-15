package com.visionforge.inferencebenchmark.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.view.View;
import android.view.animation.LinearInterpolator;

/**
 * One-shot particle burst overlay driven by {@link FxParticleEngine}.
 *
 * <p>Fires exactly one bounded burst per state upgrade, then hides. Never
 * loops ambient animation; the host screen stays idle between transitions.</p>
 */
final class FxParticleBurstView extends View {
    private final FxParticleEngine engine =
            new FxParticleEngine(FxTransitionPolicy.BURST_PARTICLE_COUNT, 20260724L);
    private final Paint particlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private ValueAnimator animator;
    private long lastFrameNanos;
    private int accentColor;

    FxParticleBurstView(Context context) {
        super(context);
        // INVISIBLE views still participate in layout.  Keeping this overlay
        // measured avoids a zero-size retry loop when the first healthy-state
        // transition arrives before the effect has ever been shown.
        setVisibility(INVISIBLE);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
    }

    /** Fires one bounded burst from the view centre in the given accent colour. */
    void burst(int color) {
        if (getWidth() <= 0 || getHeight() <= 0) {
            // The effect is cosmetic.  Never self-post while geometry is
            // unavailable: a GONE/zero-size overlay would otherwise flood the
            // main Looper and starve the real connection-state render.
            return;
        }
        if (animator != null && animator.isRunning()) return;
        accentColor = color;
        engine.burst(getWidth() / 2.0f, getHeight() / 2.0f,
                FxTransitionPolicy.BURST_PARTICLE_COUNT,
                getWidth() * 0.9f, 7.0f, FxTransitionPolicy.BURST_DURATION_MS);
        lastFrameNanos = 0L;
        setVisibility(VISIBLE);
        animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(FxTransitionPolicy.BURST_DURATION_MS);
        animator.setInterpolator(new LinearInterpolator());
        animator.addUpdateListener(animation -> step());
        animator.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                setVisibility(INVISIBLE);
            }
        });
        animator.start();
    }

    private void step() {
        long now = System.nanoTime();
        float dtMillis = lastFrameNanos == 0L ? 16.0f : (now - lastFrameNanos) / 1_000_000.0f;
        lastFrameNanos = now;
        if (!engine.advance(dtMillis) && animator != null) {
            animator.cancel();
            setVisibility(INVISIBLE);
        }
        invalidate();
    }

    @Override
    protected void onDetachedFromWindow() {
        if (animator != null) animator.cancel();
        setVisibility(INVISIBLE);
        super.onDetachedFromWindow();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        particlePaint.setColor(accentColor);
        for (FxParticleEngine.Particle p : engine.particles()) {
            float life = p.lifeFraction();
            if (life <= 0.0f) continue;
            particlePaint.setAlpha(Math.round(255 * life));
            canvas.drawCircle(p.x, p.y, p.size * life + 0.5f, particlePaint);
        }
    }
}
