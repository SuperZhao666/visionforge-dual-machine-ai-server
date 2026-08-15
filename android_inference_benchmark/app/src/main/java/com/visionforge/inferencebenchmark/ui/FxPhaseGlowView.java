package com.visionforge.inferencebenchmark.ui;

import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.view.View;

import java.util.HashMap;
import java.util.Map;

/**
 * Radial phase glow drawn behind the hero status icon. Phase colours are
 * semantic (waiting = slate-violet, healthy = soft violet, failure = coral)
 * and capped at 0.25 centre alpha.
 *
 * <p>Shaders are cached per phase colour and rebuilt only when the view size
 * changes; a phase switch runs one bounded 250 ms cross-fade between the
 * previous and current cached shaders. onDraw only issues drawCircle calls
 * and never allocates, and the tree is fully idle once the fade settles.</p>
 */
final class FxPhaseGlowView extends View {
    private static final long PHASE_FADE_MS = 250L;
    private static final float CENTER_ALPHA = 0.25f;

    private final Paint previousPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint currentPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Map<Integer, Shader> shaderCache = new HashMap<>();
    private int currentColor;
    private int previousColor;
    private float blend = 1.0f;
    private ValueAnimator animator;

    FxPhaseGlowView(Context context) {
        super(context);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
    }

    /** Retargets the glow; a real phase change cross-fades over 250 ms. */
    void setPhase(int color) {
        if (color == currentColor) return;
        if (currentColor == 0) {
            currentColor = color;
            invalidate();
            return;
        }
        // A re-target mid-fade snaps the previous stop to the last target;
        // the new fade still runs from the current blend, so the visible
        // colour never jumps backwards.
        previousColor = currentColor;
        currentColor = color;
        if (animator != null) animator.cancel();
        animator = ValueAnimator.ofFloat(0.0f, 1.0f);
        animator.setDuration(PHASE_FADE_MS);
        animator.addUpdateListener(animation -> {
            blend = (Float) animation.getAnimatedValue();
            invalidate();
        });
        animator.addListener(new AnimatorListenerAdapter() {
            @Override
            public void onAnimationEnd(android.animation.Animator animation) {
                animator = null;
                blend = 1.0f;
                invalidate();
            }
        });
        blend = 0.0f;
        animator.start();
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        shaderCache.clear();
    }

    @Override
    protected void onDetachedFromWindow() {
        if (animator != null) animator.cancel();
        super.onDetachedFromWindow();
    }

    private Shader shaderFor(int color) {
        Shader shader = shaderCache.get(color);
        if (shader == null) {
            float radius = Math.max(1.0f, Math.max(getWidth(), getHeight()) * 0.5f);
            shader = new RadialGradient(getWidth() * 0.5f, getHeight() * 0.5f, radius,
                    FxGlowDrawable.withAlpha(color, CENTER_ALPHA), Color.TRANSPARENT,
                    Shader.TileMode.CLAMP);
            shaderCache.put(color, shader);
        }
        return shader;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (currentColor == 0) return;
        float cx = getWidth() * 0.5f;
        float cy = getHeight() * 0.5f;
        float radius = Math.max(getWidth(), getHeight()) * 0.5f;
        if (blend < 1.0f && previousColor != 0) {
            previousPaint.setShader(shaderFor(previousColor));
            previousPaint.setAlpha(Math.round(255 * (1.0f - blend)));
            canvas.drawCircle(cx, cy, radius, previousPaint);
        }
        currentPaint.setShader(shaderFor(currentColor));
        currentPaint.setAlpha(blend >= 1.0f ? 255 : Math.round(255 * blend));
        canvas.drawCircle(cx, cy, radius, currentPaint);
    }
}
