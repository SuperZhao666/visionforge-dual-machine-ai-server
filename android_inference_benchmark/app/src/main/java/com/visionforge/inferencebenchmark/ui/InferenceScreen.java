package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.R;

/** Unified link-health and real-time inference destination. */
final class InferenceScreen implements MobileScreen {
    private final Context context;
    private final ScrollView root;
    private final LinkStatusSection linkStatusSection;
    private TextView confidenceChip;
    private TextView nmsChip;
    private LatencySparklineView sparkline;
    private String lastQnnP50;

    InferenceScreen(Context context) {
        this.context = context;
        linkStatusSection = new LinkStatusSection(context);
        root = VisionForgeTheme.scrollPage(context);
        root.setContentDescription(UiAutomationIds.SCROLL_INFERENCE);
        root.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        LinearLayout page = VisionForgeTheme.pageBody(context);
        root.addView(page);
        page.addView(linkStatusSection.view(), VisionForgeTheme.match(context, 10));
        page.addView(createTrendCard(), VisionForgeTheme.match(context, 10));
        page.addView(createChipRow(), VisionForgeTheme.match(context, 10));
    }

    private View createTrendCard() {
        LinearLayout card = VisionForgeTheme.card(context);
        LinearLayout header = new LinearLayout(context);
        TextView title = VisionForgeTheme.text(context,
                context.getString(R.string.latency_trend), 14, VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(title);
        header.addView(title, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(VisionForgeTheme.text(context,
                context.getString(R.string.latency_trend_window), 12,
                VisionForgeTheme.TEXT_MUTED));
        card.addView(header);
        sparkline = new LatencySparklineView(context, VisionForgeTheme.INFERENCE_ACCENT);
        card.addView(sparkline, VisionForgeTheme.match(context, 8));
        return card;
    }

    private View createChipRow() {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        TextView size = chip(context.getString(R.string.input_shape_416));
        confidenceChip = chip("");
        nmsChip = chip("");
        row.addView(size, VisionForgeTheme.weighted(context, 1f, 7));
        row.addView(confidenceChip, VisionForgeTheme.weighted(context, 1f, 7));
        row.addView(nmsChip, VisionForgeTheme.weighted(context, 1f, 0));
        return row;
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void render(MobileUiState state) {
        linkStatusSection.render(state);
        VisionForgeTheme.setTextIfChanged(confidenceChip,
                context.getString(R.string.confidence_summary, state.confidence));
        VisionForgeTheme.setTextIfChanged(nmsChip,
                context.getString(R.string.nms_summary, state.nmsIou));
        // Skip re-queuing an unchanged sample: duplicate values would only
        // flatten the trend line and cost a full view invalidation per tick.
        if (state.qnnP50 == null ? lastQnnP50 == null : !state.qnnP50.equals(lastQnnP50)) {
            lastQnnP50 = state.qnnP50;
            sparkline.addSample(parseMillis(state.qnnP50));
        }
    }

    private TextView chip(String value) {
        TextView chip = VisionForgeTheme.text(context, value, 12, VisionForgeTheme.TEXT);
        chip.setGravity(Gravity.CENTER);
        chip.setPadding(VisionForgeTheme.dp(context, 4), VisionForgeTheme.dp(context, 11),
                VisionForgeTheme.dp(context, 4), VisionForgeTheme.dp(context, 11));
        chip.setBackground(VisionForgeTheme.rounded(context, VisionForgeTheme.SURFACE, 12,
                VisionForgeTheme.OUTLINE, 1));
        return chip;
    }

    private static double parseMillis(String value) {
        if (value == null || !value.endsWith(" ms")) return Double.NaN;
        try {
            return Double.parseDouble(value.substring(0, value.length() - 3).trim());
        } catch (NumberFormatException ignored) {
            return Double.NaN;
        }
    }

}
