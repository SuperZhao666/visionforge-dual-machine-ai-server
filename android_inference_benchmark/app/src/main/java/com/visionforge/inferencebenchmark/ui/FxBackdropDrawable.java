package com.visionforge.inferencebenchmark.ui;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.RadialGradient;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;

/**
 * Static deep-space page backdrop: vertical depth gradient, a seeded star
 * field and two soft nebula washes. Rendered once into a cached bitmap at
 * half resolution and then blitted — zero per-frame cost, zero animation,
 * fully idle-safe while still giving the shell a high-tech depth.
 */
final class FxBackdropDrawable extends Drawable {
    private final Paint bitmapPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private Bitmap cache;

    @Override
    protected void onBoundsChange(android.graphics.Rect bounds) {
        int width = Math.max(1, bounds.width() / 2);
        int height = Math.max(1, bounds.height() / 2);
        cache = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        render(new Canvas(cache), width, height);
    }

    private void render(Canvas canvas, int width, int height) {
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        paint.setShader(new LinearGradient(0, 0, 0, height,
                Color.rgb(11, 14, 19), Color.rgb(17, 22, 36), Shader.TileMode.CLAMP));
        canvas.drawRect(0, 0, width, height, paint);
        paint.setShader(null);
        // Aurora nebula washes, deliberately faint.
        paint.setShader(new RadialGradient(width * 0.82f, height * 0.10f, width * 0.62f,
                withAlpha(0xFF8B5CF6, 0.14f), Color.TRANSPARENT, Shader.TileMode.CLAMP));
        canvas.drawRect(0, 0, width, height, paint);
        paint.setShader(new RadialGradient(width * 0.12f, height * 0.66f, width * 0.70f,
                withAlpha(0xFF6D45D8, 0.11f), Color.TRANSPARENT, Shader.TileMode.CLAMP));
        canvas.drawRect(0, 0, width, height, paint);
        paint.setShader(new RadialGradient(width * 0.55f, height * 1.02f, width * 0.80f,
                withAlpha(0xFF4C1D95, 0.10f), Color.TRANSPARENT, Shader.TileMode.CLAMP));
        canvas.drawRect(0, 0, width, height, paint);
        paint.setShader(null);
        // Seeded star field with depth layers.
        long state = 0x9E3779B97F4A7C15L;
        for (int i = 0; i < 170; i++) {
            state = next(state);
            float x = (state >>> 11) * 0x1.0p-53f * width;
            state = next(state);
            float y = (state >>> 11) * 0x1.0p-53f * height;
            state = next(state);
            float roll = (state >>> 11) * 0x1.0p-53f;
            float size = roll < 0.75f ? 1.0f : roll < 0.95f ? 1.6f : 2.4f;
            int alpha = roll < 0.75f ? 46 : roll < 0.95f ? 78 : 120;
            paint.setColor(Color.argb(alpha, 232, 228, 248));
            canvas.drawCircle(x, y, size, paint);
        }
        // Horizon glow near the bottom for depth.
        paint.setShader(new LinearGradient(0, height * 0.86f, 0, height,
                Color.TRANSPARENT, withAlpha(0xFF8B5CF6, 0.06f), Shader.TileMode.CLAMP));
        canvas.drawRect(0, height * 0.86f, width, height, paint);
    }

    private static long next(long z) {
        z += 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static int withAlpha(int color, float alpha) {
        return Color.argb(Math.round(255 * alpha), Color.red(color),
                Color.green(color), Color.blue(color));
    }

    @Override
    public void draw(Canvas canvas) {
        if (cache != null) {
            canvas.drawBitmap(cache, null, getBounds(), bitmapPaint);
        }
    }

    @Override
    public void setAlpha(int alpha) {
        bitmapPaint.setAlpha(alpha);
    }

    @Override
    public void setColorFilter(ColorFilter colorFilter) {
        bitmapPaint.setColorFilter(colorFilter);
    }

    @Override
    public int getOpacity() {
        return PixelFormat.OPAQUE;
    }
}
