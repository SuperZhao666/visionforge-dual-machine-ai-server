package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/**
 * Static glass-tech card surface: translucent rounded surface, a full-card
 * diagonal sheen, a subtle circuit grid (bitmap-shader tile, one draw call),
 * a top edge highlight and a neon state-colour stroke.
 *
 * <p>Instances are meant to be kept and re-targeted via {@link #retarget}:
 * paints, shaders and the grid tile are only rebuilt when the colours or the
 * bounds actually change, so the 500 ms status tick costs nothing once
 * steady. Draws only when invalidated, never on a timer.</p>
 */
final class FxGlowDrawable extends Drawable {
    private final Paint surfacePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint sheenPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint strokePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint edgePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF rect = new RectF();
    private final Path clipPath = new Path();
    private final float radiusPx;
    private final float gridStepPx;
    private final boolean glass;
    private int accent;
    private int surface;

    FxGlowDrawable(Context context, int surfaceColor, int accentColor, float radiusDp,
                   float strokeWidthDp) {
        this(context, surfaceColor, accentColor, radiusDp, strokeWidthDp, true);
    }

    FxGlowDrawable(Context context, int surfaceColor, int accentColor, float radiusDp,
                   float strokeWidthDp, boolean glass) {
        this.glass = glass;
        radiusPx = VisionForgeTheme.dp(context, (int) radiusDp);
        gridStepPx = VisionForgeTheme.dp(context, 26);
        surfacePaint.setStyle(Paint.Style.FILL);
        gridPaint.setStyle(Paint.Style.FILL);
        strokePaint.setStyle(Paint.Style.STROKE);
        strokePaint.setStrokeWidth(VisionForgeTheme.dp(context, (int) Math.max(1, strokeWidthDp)));
        sheenPaint.setStyle(Paint.Style.FILL);
        edgePaint.setStyle(Paint.Style.STROKE);
        edgePaint.setStrokeWidth(VisionForgeTheme.dp(context, 1));
        applyColors(surfaceColor, accentColor);
    }

    static int withAlpha(int color, float alpha) {
        return Color.argb(Math.max(0, Math.min(255, Math.round(255 * alpha))),
                Color.red(color), Color.green(color), Color.blue(color));
    }

    private void applyColors(int surfaceColor, int accentColor) {
        surface = surfaceColor;
        accent = accentColor;
        surfacePaint.setColor(glass ? withAlpha(surfaceColor, 0.86f) : surfaceColor);
        strokePaint.setColor(accentColor);
    }

    /**
     * Re-aims this drawable at a new surface/accent pair, rebuilding shaders
     * and re-invalidating only when something really changed. Returns true
     * when a visual change was applied.
     */
    boolean retarget(int surfaceColor, int accentColor) {
        if (surface == surfaceColor && accent == accentColor) return false;
        applyColors(surfaceColor, accentColor);
        rebuildShaders();
        invalidateSelf();
        return true;
    }

    @Override
    protected void onBoundsChange(android.graphics.Rect bounds) {
        rect.set(bounds);
        clipPath.reset();
        clipPath.addRoundRect(rect, radiusPx, radiusPx, Path.Direction.CW);
        rebuildShaders();
    }

    private void rebuildShaders() {
        android.graphics.Rect bounds = getBounds();
        if (bounds == null || bounds.isEmpty()) return;
        sheenPaint.setShader(new LinearGradient(
                bounds.left, bounds.top, bounds.right, bounds.bottom,
                new int[]{withAlpha(accent, 0.14f), withAlpha(accent, 0.03f),
                        withAlpha(accent, 0.0f), withAlpha(0xFFFFFFFF, 0.05f)},
                new float[]{0.0f, 0.38f, 0.72f, 1.0f}, Shader.TileMode.CLAMP));
        edgePaint.setShader(new LinearGradient(
                bounds.left, bounds.top, bounds.right, bounds.top,
                withAlpha(0xFFFFFFFF, 0.20f), withAlpha(0xFFFFFFFF, 0.02f),
                Shader.TileMode.CLAMP));
        if (gridPaint.getShader() == null) {
            int tile = Math.max(8, (int) gridStepPx);
            Bitmap gridTile = Bitmap.createBitmap(tile, tile, Bitmap.Config.ARGB_8888);
            Canvas tileCanvas = new Canvas(gridTile);
            Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
            line.setColor(withAlpha(0xFF66708A, 0.08f));
            line.setStrokeWidth(1.0f);
            tileCanvas.drawLine(0.5f, 0, 0.5f, tile, line);
            tileCanvas.drawLine(0, 0.5f, tile, 0.5f, line);
            gridPaint.setShader(new BitmapShader(gridTile,
                    Shader.TileMode.REPEAT, Shader.TileMode.REPEAT));
        }
    }

    @Override
    public void draw(Canvas canvas) {
        canvas.drawRoundRect(rect, radiusPx, radiusPx, surfacePaint);
        int save = canvas.save();
        canvas.clipPath(clipPath);
        canvas.drawRect(rect, sheenPaint);
        canvas.drawRect(rect, gridPaint);
        canvas.restoreToCount(save);
        canvas.drawRoundRect(rect, radiusPx, radiusPx, strokePaint);
        canvas.drawLine(rect.left + radiusPx, rect.top + 0.5f,
                rect.right - radiusPx, rect.top + 0.5f, edgePaint);
    }

    @Override
    public void setAlpha(int alpha) {
        surfacePaint.setAlpha(alpha);
    }

    @Override
    public void setColorFilter(ColorFilter colorFilter) {
        surfacePaint.setColorFilter(colorFilter);
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }
}
