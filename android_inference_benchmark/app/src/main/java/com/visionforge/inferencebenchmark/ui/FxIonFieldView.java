package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RadialGradient;
import android.graphics.Rect;
import android.graphics.Shader;
import android.view.Choreographer;
import android.view.View;

/**
 * Ambient "ion field" backdrop layer: a small fixed set of slowly drifting
 * charged-particle sprites (bright core + radial glow + one short afterglow
 * ghost) floating above the static nebula backdrop and below every screen.
 *
 * <p>Performance contract:
 * <ul>
 *   <li>4 pre-rendered radial-gradient sprite bitmaps are shared by all ions;
 *   <li>particles live in a preallocated array, the single destination Rect
 *       and Paint are reused — {@link #onDraw} allocates nothing;
 *   <li>one visibility-bound frame callback advances the ions only while the
 *       shell is actually visible, then stops on detach/hidden states.
 * </ul>
 */
final class FxIonFieldView extends View {
    /** Clearly visible ambient field while staying far below content cost. */
    private static final int ION_COUNT = 72;
    /** Sprite edge in dp; every ion draws a scaled copy of one shared sprite. */
    private static final int SPRITE_DP = 64;
    /** Sprite palette: soft violet, electric violet, deep violet, rare amber. */
    private static final int[] PALETTE = {0xFFA78BFA, 0xFF8B5CF6, 0xFF6D45D8, 0xFFF59E0B};
    /** Ghost trail alpha relative to the ion's current alpha. */
    private static final float GHOST_ALPHA = 0.45f;
    /** Ambient motion is intentionally low-rate; inference gets every cycle. */
    private static final long IDLE_FRAME_DELAY_MILLIS = 50L;

    /** One preallocated ion; all fields are mutated in place, never re-newed. */
    private static final class Ion {
        float x;
        float y;
        float vx;
        float vy;
        float previousX;
        float previousY;
        float radiusPx;
        float phase;
        float breathSpeed;
        int baseAlpha;
        int sprite;
    }

    private final Ion[] ions = new Ion[ION_COUNT];
    private final Bitmap[] sprites = new Bitmap[PALETTE.length];
    private final Paint spritePaint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
    private final Rect destination = new Rect();
    private final long[] randomState = new long[1];
    private final Choreographer.FrameCallback frameCallback =
            new Choreographer.FrameCallback() {
                @Override
                public void doFrame(long frameTimeNanos) {
                    frameCallbackPosted = false;
                    if (!shouldAnimate()) {
                        lastFrameNanos = 0L;
                        return;
                    }
                    if (lastFrameNanos == 0L) lastFrameNanos = frameTimeNanos;
                    float deltaSeconds = Math.min(
                            0.050f,
                            (frameTimeNanos - lastFrameNanos) / 1_000_000_000.0f);
                    lastFrameNanos = frameTimeNanos;
                    step(deltaSeconds);
                    invalidate();
                    postNextFrame();
                }
            };
    private boolean attached;
    private boolean seeded;
    private boolean frameCallbackPosted;
    private boolean realtimeWorkActive;
    private long lastFrameNanos;
    private long lastInteractionNanos;

    /** Ambient field sleeps after this much user inactivity; any touch wakes it. */
    private static final long SLEEP_AFTER_INACTIVITY_NANOS = 45_000_000_000L;

    FxIonFieldView(Context context) {
        super(context);
        setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_NO);
        setClickable(false);
        setFocusable(false);
        randomState[0] = 0x2F6E2B9E3779B97FL;
        for (int i = 0; i < ions.length; i++) ions[i] = new Ion();
        int spritePx = Math.max(24, VisionForgeTheme.dp(context, SPRITE_DP));
        for (int i = 0; i < PALETTE.length; i++) {
            sprites[i] = createSprite(PALETTE[i], spritePx);
        }
    }

    /** Pre-renders one ion sprite: hot core, colour body, fading halo. */
    private static Bitmap createSprite(int color, int sizePx) {
        Bitmap bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        float centre = sizePx * 0.5f;
        int core = Color.argb(235,
                Math.min(255, Color.red(color) + 110),
                Math.min(255, Color.green(color) + 110),
                Math.min(255, Color.blue(color) + 110));
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        paint.setShader(new RadialGradient(centre, centre, centre,
                new int[]{core, FxGlowDrawable.withAlpha(color, 0.85f),
                        FxGlowDrawable.withAlpha(color, 0.22f), Color.TRANSPARENT},
                new float[]{0.0f, 0.14f, 0.48f, 1.0f}, Shader.TileMode.CLAMP));
        canvas.drawCircle(centre, centre, centre, paint);
        return bitmap;
    }

    @Override
    protected void onSizeChanged(int width, int height, int oldWidth, int oldHeight) {
        super.onSizeChanged(width, height, oldWidth, oldHeight);
        if (width <= 0 || height <= 0) return;
        // Reseed positions whenever the viewport really changes so ions stay
        // distributed; velocities and phases are stable identity, not layout.
        seed(width, height);
        startAnimationIfVisible();
    }

    private void seed(int width, int height) {
        for (Ion ion : ions) {
            ion.x = nextFloat() * width;
            ion.y = nextFloat() * height;
            ion.previousX = ion.x;
            ion.previousY = ion.y;
            if (seeded) continue;
            // Clearly perceptible drift: 28–64 px/s with a slight upward bias
            // like rising charge; slow enough to stay ambient, fast enough to
            // be seen without staring.
            float speed = 28.0f + 36.0f * nextFloat();
            double heading = nextFloat() * Math.PI * 2.0;
            ion.vx = (float) (Math.cos(heading) * speed);
            ion.vy = (float) (Math.sin(heading) * speed) - 8.0f;
            float roll = nextFloat();
            ion.sprite = roll < 0.40f ? 0 : roll < 0.70f ? 1 : roll < 0.90f ? 2 : 3;
            ion.radiusPx = Math.max(2.0f,
                    VisionForgeTheme.dp(getContext(), 3) + nextFloat()
                            * VisionForgeTheme.dp(getContext(), 7));
            ion.phase = nextFloat() * (float) (Math.PI * 2.0);
            ion.breathSpeed = 0.35f + 0.55f * nextFloat();
            ion.baseAlpha = 150 + Math.round(80 * nextFloat());
        }
        seeded = true;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        for (Ion ion : ions) {
            float breath = 0.55f + 0.45f * (float) Math.sin(ion.phase);
            int alpha = Math.round(ion.baseAlpha * breath);
            if (alpha <= 2) continue;
            Bitmap sprite = sprites[ion.sprite];
            float radius = ion.radiusPx;
            // Short afterglow ghost at the previous position: a cheap trail
            // that never leaves residue on the backdrop.
            spritePaint.setAlpha(Math.round(alpha * GHOST_ALPHA));
            destination.set(Math.round(ion.previousX - radius), Math.round(ion.previousY - radius),
                    Math.round(ion.previousX + radius), Math.round(ion.previousY + radius));
            canvas.drawBitmap(sprite, null, destination, spritePaint);
            spritePaint.setAlpha(alpha);
            destination.set(Math.round(ion.x - radius), Math.round(ion.y - radius),
                    Math.round(ion.x + radius), Math.round(ion.y + radius));
            canvas.drawBitmap(sprite, null, destination, spritePaint);
        }
        spritePaint.setAlpha(255);
    }

    @Override
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        attached = true;
        lastInteractionNanos = System.nanoTime();
        startAnimationIfVisible();
    }

    @Override
    protected void onDetachedFromWindow() {
        stopAnimation();
        attached = false;
        super.onDetachedFromWindow();
    }

    @Override
    protected void onWindowVisibilityChanged(int visibility) {
        super.onWindowVisibilityChanged(visibility);
        startAnimationIfVisible();
    }

    @Override
    protected void onVisibilityChanged(View changedView, int visibility) {
        super.onVisibilityChanged(changedView, visibility);
        startAnimationIfVisible();
    }

    /** Freezes the decorative layer while video decode/inference is live. */
    void setRealtimeWorkActive(boolean active) {
        if (realtimeWorkActive == active) return;
        realtimeWorkActive = active;
        if (active) {
            stopAnimation();
            return;
        }
        startAnimationIfVisible();
    }

    /**
     * Called by the host activity on any user interaction. Restarts the
     * ambient loop after an inactivity sleep and resets the sleep budget.
     */
    void onUserInteraction() {
        lastInteractionNanos = System.nanoTime();
        startAnimationIfVisible();
    }

    /** Starts a visibility-bound ambient loop, or stops it if hidden. */
    private void startAnimationIfVisible() {
        if (!shouldAnimate()) {
            stopAnimation();
            return;
        }
        invalidate();
        postNextFrame();
    }

    private boolean shouldAnimate() {
        return attached
                && !realtimeWorkActive
                && !isAsleep()
                && getWindowVisibility() == VISIBLE
                && isShown()
                && getWidth() > 0
                && getHeight() > 0;
    }

    private boolean isAsleep() {
        return lastInteractionNanos != 0L
                && System.nanoTime() - lastInteractionNanos > SLEEP_AFTER_INACTIVITY_NANOS;
    }

    private void postNextFrame() {
        if (frameCallbackPosted) return;
        frameCallbackPosted = true;
        Choreographer.getInstance().postFrameCallbackDelayed(
                frameCallback, IDLE_FRAME_DELAY_MILLIS);
    }

    private void stopAnimation() {
        if (!frameCallbackPosted) {
            lastFrameNanos = 0L;
            return;
        }
        Choreographer.getInstance().removeFrameCallback(frameCallback);
        frameCallbackPosted = false;
        lastFrameNanos = 0L;
    }

    private void step(float deltaSeconds) {
        int width = getWidth();
        int height = getHeight();
        if (width <= 0 || height <= 0 || deltaSeconds <= 0.0f) return;
        for (Ion ion : ions) {
            ion.previousX = ion.x;
            ion.previousY = ion.y;
            ion.x += ion.vx * deltaSeconds;
            ion.y += ion.vy * deltaSeconds;
            ion.phase += ion.breathSpeed * deltaSeconds;
            float radius = ion.radiusPx;
            if (ion.x < -radius) ion.x = width + radius;
            else if (ion.x > width + radius) ion.x = -radius;
            if (ion.y < -radius) ion.y = height + radius;
            else if (ion.y > height + radius) ion.y = -radius;
        }
    }

    /** SplitMix64 step; deterministic per view instance, allocation-free. */
    private float nextFloat() {
        long z = (randomState[0] += 0x9E3779B97F4A7C15L);
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        z = z ^ (z >>> 31);
        return (z >>> 11) * 0x1.0p-53f;
    }
}
