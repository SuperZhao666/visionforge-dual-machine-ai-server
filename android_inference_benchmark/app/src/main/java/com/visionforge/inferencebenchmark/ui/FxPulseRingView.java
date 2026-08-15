package com.visionforge.inferencebenchmark.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

/**
 * One-shot expanding pulse ring played on state upgrades. The view is GONE
 * whenever idle, runs exactly one bounded animator, then hides itself again —
 * the accessibility tree is never kept awake.
 */
final class FxPulseRingView extends View {
    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();
    private ValueAnimator animator;
    private float progress = 1.0f;
    private int accentColor;

    FxPulseRingView(Context context) {
        super(context);
        setVisibility(GONE);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        ringPaint.setStyle(Paint.Style.STROKE);
    }

    /** Plays one bounded pulse in the given accent colour; no-op while playing. */
    void pulse(int color) {
        if (animator != null && animator.isRunning()) return;
        accentColor = color;
        progress = 0.0f;
        setVisibility(VISIBLE);
        animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(FxTransitionPolicy.PULSE_DURATION_MS);
        animator.setInterpolator(new DecelerateInterpolator());
        animator.addUpdateListener(animation -> {
            progress = (Float) animation.getAnimatedValue();
            invalidate();
        });
        animator.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                setVisibility(GONE);
            }
        });
        animator.start();
    }

    @Override
    protected void onDetachedFromWindow() {
        if (animator != null) animator.cancel();
        super.onDetachedFromWindow();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (progress >= 1.0f) return;
        float width = getWidth();
        float height = getHeight();
        if (width <= 0 || height <= 0) return;
        float inset = progress * width * 0.22f;
        rect.set(inset, inset * height / width, width - inset, height - inset * height / width);
        ringPaint.setColor(accentColor);
        ringPaint.setAlpha(Math.round(255 * (1.0f - progress)));
        ringPaint.setStrokeWidth((1.0f - progress) * 6.0f + 1.5f);
        canvas.drawRoundRect(rect, 18.0f + progress * 22.0f, 18.0f + progress * 22.0f, ringPaint);
    }
}
