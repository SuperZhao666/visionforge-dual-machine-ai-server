package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

import com.visionforge.inferencebenchmark.R;

import java.util.ArrayDeque;
import java.util.Deque;

/** Lightweight live chart backed only by observed QNN P50 samples. */
final class LatencySparklineView extends View {
    private static final int MAX_SAMPLES = 60;
    private final Deque<Double> samples = new ArrayDeque<>(MAX_SAMPLES);
    private final Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint tipPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();

    LatencySparklineView(Context context) {
        this(context, VisionForgeTheme.ACCENT);
    }

    LatencySparklineView(Context context, int lineColor) {
        super(context);
        setMinimumHeight(VisionForgeTheme.dp(context, 112));
        gridPaint.setColor(VisionForgeTheme.OUTLINE);
        gridPaint.setStrokeWidth(VisionForgeTheme.dp(context, 1));
        linePaint.setColor(lineColor);
        linePaint.setStyle(Paint.Style.STROKE);
        linePaint.setStrokeWidth(VisionForgeTheme.dp(context, 2));
        linePaint.setStrokeCap(Paint.Cap.ROUND);
        linePaint.setStrokeJoin(Paint.Join.ROUND);
        glowPaint.setColor(FxGlowDrawable.withAlpha(lineColor, 0.28f));
        glowPaint.setStyle(Paint.Style.STROKE);
        glowPaint.setStrokeWidth(VisionForgeTheme.dp(context, 7));
        glowPaint.setStrokeCap(Paint.Cap.ROUND);
        glowPaint.setStrokeJoin(Paint.Join.ROUND);
        tipPaint.setColor(lineColor);
        tipPaint.setStyle(Paint.Style.FILL);
        setContentDescription(context.getString(R.string.latency_trend_content_description));
    }

    void addSample(double milliseconds) {
        if (!Double.isFinite(milliseconds) || milliseconds < 0.0) return;
        if (samples.size() == MAX_SAMPLES) samples.removeFirst();
        samples.addLast(milliseconds);
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float width = getWidth();
        float height = getHeight();
        float inset = VisionForgeTheme.dp(getContext(), 8);
        canvas.drawLine(inset, height * 0.25f, width - inset, height * 0.25f, gridPaint);
        canvas.drawLine(inset, height * 0.5f, width - inset, height * 0.5f, gridPaint);
        canvas.drawLine(inset, height * 0.75f, width - inset, height * 0.75f, gridPaint);
        if (samples.size() < 2) return;

        double minimum = Double.POSITIVE_INFINITY;
        double maximum = Double.NEGATIVE_INFINITY;
        for (double sample : samples) {
            minimum = Math.min(minimum, sample);
            maximum = Math.max(maximum, sample);
        }
        double padding = Math.max(0.2, (maximum - minimum) * 0.25);
        minimum = Math.max(0.0, minimum - padding);
        maximum += padding;
        double range = Math.max(0.1, maximum - minimum);
        float step = (width - inset * 2f) / (samples.size() - 1f);
        path.reset();
        int index = 0;
        float lastX = inset;
        float lastY = height - inset;
        for (double sample : samples) {
            float x = inset + step * index++;
            float y = (float) (height - inset - ((sample - minimum) / range) * (height - inset * 2f));
            if (index == 1) path.moveTo(x, y);
            else path.lineTo(x, y);
            lastX = x;
            lastY = y;
        }
        canvas.drawPath(path, glowPaint);
        canvas.drawPath(path, linePaint);
        canvas.drawCircle(lastX, lastY, VisionForgeTheme.dp(getContext(), 3), tipPaint);
    }
}
