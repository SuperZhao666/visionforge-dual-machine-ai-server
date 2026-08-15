package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.EnumMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Persistent destination navigation bar with a sliding selection pill.
 * The pill glides between items with one bounded 220 ms translation; between
 * switches everything is static, keeping the accessibility tree idle.
 */
final class BottomNavigationBar {
    private static final long PILL_SLIDE_MS = 220L;

    private final Context context;
    private final FrameLayout frame;
    private final LinearLayout root;
    private final View pill;
    private final Map<MobileDestination, Item> items = new EnumMap<>(MobileDestination.class);
    /** Pill surfaces are created once per destination and reused on every switch. */
    private final Map<MobileDestination, android.graphics.drawable.Drawable> pillBackgrounds =
            new EnumMap<>(MobileDestination.class);
    private MobileDestination current = MobileDestination.INFERENCE;

    BottomNavigationBar(Context context, Consumer<MobileDestination> onSelected) {
        this.context = context;
        frame = new FrameLayout(context);
        frame.setBackground(VisionForgeTheme.rounded(context,
                FxGlowDrawable.withAlpha(VisionForgeTheme.SURFACE, 0.82f), 0,
                VisionForgeTheme.OUTLINE, 1));
        pill = new View(context);
        pill.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        frame.addView(pill, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root = new LinearLayout(context);
        root.setOrientation(LinearLayout.HORIZONTAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(VisionForgeTheme.dp(context, 8), VisionForgeTheme.dp(context, 6),
                VisionForgeTheme.dp(context, 8), VisionForgeTheme.dp(context, 6));
        frame.addView(root, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        for (MobileDestination destination : MobileDestination.values()) {
            Item item = new Item(destination);
            items.put(destination, item);
            root.addView(item.root, new LinearLayout.LayoutParams(0,
                    VisionForgeTheme.dp(context, 58), 1f));
            item.root.setOnClickListener(view -> onSelected.accept(destination));
        }
        frame.post(() -> positionPill(current, false));
        setSelected(MobileDestination.INFERENCE);
    }

    View view() {
        return frame;
    }

    void setSelected(MobileDestination selected) {
        current = selected;
        for (Map.Entry<MobileDestination, Item> entry : items.entrySet()) {
            boolean active = entry.getKey() == selected;
            Item item = entry.getValue();
            int color = active ? VisionForgeTheme.destinationAccent(selected)
                    : VisionForgeTheme.TEXT_MUTED;
            item.icon.setTextColor(color);
            // Selected icon gets a soft same-colour halo; unselected icons
            // stay on the #8A93A6 muted slate with no shadow at all.
            item.icon.setShadowLayer(
                    active ? VisionForgeTheme.dp(context, 7) : 0, 0, 0,
                    active ? FxGlowDrawable.withAlpha(color, 0.65f)
                            : android.graphics.Color.TRANSPARENT);
            item.label.setTextColor(color);
            item.label.setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            item.root.setSelected(active);
        }
        positionPill(selected, true);
    }

    private void positionPill(MobileDestination selected, boolean animate) {
        Item item = items.get(selected);
        if (item == null) return;
        if (item.root.getWidth() <= 0) {
            root.post(() -> positionPill(selected, false));
            return;
        }
        FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) pill.getLayoutParams();
        params.width = item.root.getWidth();
        params.height = item.root.getHeight();
        params.topMargin = root.getPaddingTop();
        pill.setLayoutParams(params);
        android.graphics.drawable.Drawable background = pillBackgrounds.get(selected);
        if (background == null) {
            // Selection pill: diagonal violet gradient at 26% alpha, keeping
            // the per-destination accent stroke. Cached per destination.
            background = VisionForgeTheme.gradient(context,
                    new int[]{FxGlowDrawable.withAlpha(VisionForgeTheme.PRIMARY, 0.26f),
                            FxGlowDrawable.withAlpha(VisionForgeTheme.ACCENT, 0.26f)},
                    14, VisionForgeTheme.destinationAccent(selected), 1);
            pillBackgrounds.put(selected, background);
        }
        pill.setBackground(background);
        pill.setTranslationY(0.0f);
        float targetX = item.root.getLeft();
        pill.animate().cancel();
        if (animate && pill.getTranslationX() != targetX) {
            pill.animate().translationX(targetX)
                    .setDuration(PILL_SLIDE_MS).start();
        } else {
            pill.setTranslationX(targetX);
        }
    }

    private final class Item {
        final LinearLayout root;
        final TextView icon;
        final TextView label;

        Item(MobileDestination destination) {
            root = new LinearLayout(context);
            root.setOrientation(LinearLayout.VERTICAL);
            root.setGravity(Gravity.CENTER);
            root.setClickable(true);
            root.setFocusable(true);
            root.setContentDescription(destination.contentDescription);
            icon = VisionForgeTheme.icon(context, destination.icon, 24, VisionForgeTheme.TEXT_MUTED);
            label = VisionForgeTheme.text(context, context.getString(destination.labelResource),
                    11, VisionForgeTheme.TEXT_MUTED);
            label.setGravity(Gravity.CENTER);
            root.addView(icon, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, VisionForgeTheme.dp(context, 30)));
            root.addView(label, new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, VisionForgeTheme.dp(context, 22)));
        }
    }
}
