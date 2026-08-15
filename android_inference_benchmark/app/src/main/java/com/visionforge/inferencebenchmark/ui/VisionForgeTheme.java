package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Central design tokens and component factories for the native Android shell. */
final class VisionForgeTheme {
    // Obsidian Aurora tokens: obsidian surfaces, electric violet primary,
    // soft violet healthy, lava amber warning, coral error, slate idle.
    static final int BACKGROUND = Color.rgb(11, 14, 19);
    static final int SURFACE = Color.rgb(20, 25, 36);
    static final int SURFACE_RAISED = Color.rgb(26, 33, 48);
    static final int OUTLINE = Color.rgb(35, 43, 58);
    static final int OUTLINE_ACTIVE = Color.rgb(139, 92, 246);
    static final int TEXT = Color.rgb(230, 234, 242);
    static final int TEXT_MUTED = Color.rgb(138, 147, 166);
    static final int ACCENT = Color.rgb(167, 139, 250);
    static final int ACCENT_DARK = Color.rgb(42, 36, 70);
    static final int PRIMARY = Color.rgb(139, 92, 246);
    static final int PRIMARY_PRESSED = Color.rgb(109, 69, 216);
    static final int INFERENCE_ACCENT = Color.rgb(196, 181, 253);
    static final int INFERENCE_ACCENT_DARK = Color.rgb(56, 50, 84);
    static final int WARNING = Color.rgb(245, 158, 11);
    static final int DANGER = Color.rgb(251, 113, 133);
    static final int DISABLED = Color.rgb(100, 116, 139);
    /** Slate-violet used for the hero "waiting/idle" radial phase glow. */
    static final int HERO_WAITING = Color.rgb(122, 120, 150);

    private static Typeface materialIcons;

    private VisionForgeTheme() {
    }

    static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    static TextView text(Context context, CharSequence value, float sizeSp, int color) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        view.setGravity(Gravity.CENTER_VERTICAL);
        return view;
    }

    /**
     * TextView.setText triggers a full layout even when the content is equal;
     * the 500 ms status tick would otherwise relayout the whole tree twice a
     * second. Skip the write unless the text actually changed.
     */
    static void setTextIfChanged(TextView view, CharSequence value) {
        CharSequence current = view.getText();
        if (current == null ? value != null : !current.equals(value)) {
            view.setText(value);
        }
    }

    static TextView icon(Context context, String glyph, float sizeSp, int color) {
        TextView view = text(context, glyph, sizeSp, color);
        view.setGravity(Gravity.CENTER);
        view.setTypeface(materialIconTypeface(context));
        view.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        return view;
    }

    static LinearLayout card(Context context) {
        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(context, 16), dp(context, 16), dp(context, 16), dp(context, 16));
        card.setBackground(rounded(context, SURFACE, 12, OUTLINE, 1));
        return card;
    }

    static ScrollView scrollPage(Context context) {
        ScrollView scroll = new ScrollView(context);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setOverScrollMode(View.OVER_SCROLL_IF_CONTENT_SCROLLS);
        return scroll;
    }

    static LinearLayout pageBody(Context context) {
        LinearLayout page = new LinearLayout(context);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(context, 16), dp(context, 12), dp(context, 16), dp(context, 24));
        return page;
    }

    static TextView sectionLabel(Context context, int labelResource) {
        TextView label = text(context, context.getString(labelResource), 14, TEXT);
        heading(label);
        label.setPadding(dp(context, 2), dp(context, 22), 0, dp(context, 10));
        return label;
    }

    /** Heading style: bold with a 2% letter-spacing for display titles. */
    static void heading(TextView view) {
        view.setTypeface(Typeface.DEFAULT_BOLD);
        view.setLetterSpacing(0.02f);
    }

    static int destinationAccent(MobileDestination destination) {
        return destination == MobileDestination.INFERENCE ? INFERENCE_ACCENT : ACCENT;
    }

    static Button primaryButton(Context context, int labelResource) {
        Button button = buttonBase(context, context.getString(labelResource));
        button.setTextColor(primaryTextColors());
        button.setTypeface(Typeface.DEFAULT_BOLD);
        button.setBackground(primaryPressable(context));
        button.setMinHeight(dp(context, 54));
        attachPressScale(button);
        return button;
    }

    static Button secondaryButton(Context context, int labelResource) {
        Button button = buttonBase(context, context.getString(labelResource));
        button.setBackground(pressable(context, SURFACE, SURFACE_RAISED, 12, OUTLINE));
        button.setTextColor(TEXT);
        button.setMinHeight(dp(context, 50));
        return button;
    }

    static Button compactButton(Context context, int labelResource) {
        Button button = secondaryButton(context, labelResource);
        button.setTextSize(13);
        button.setMinHeight(dp(context, 42));
        button.setPadding(dp(context, 12), 0, dp(context, 12), 0);
        return button;
    }

    static TextView pill(Context context, CharSequence value, int foreground, int background) {
        TextView pill = text(context, value, 12, foreground);
        pill.setGravity(Gravity.CENTER);
        pill.setTypeface(Typeface.DEFAULT_BOLD);
        pill.setPadding(dp(context, 12), dp(context, 6), dp(context, 12), dp(context, 6));
        pill.setBackground(rounded(context, background, 20, background, 0));
        return pill;
    }

    static GradientDrawable rounded(Context context, int color, int radiusDp, int strokeColor,
                                    int strokeWidthDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(color);
        drawable.setCornerRadius(dp(context, radiusDp));
        if (strokeWidthDp > 0) drawable.setStroke(dp(context, strokeWidthDp), strokeColor);
        return drawable;
    }

    /** Diagonal (45°) two-stop gradient surface; created once per state and cached by callers. */
    static GradientDrawable gradient(Context context, int[] colors, int radiusDp, int strokeColor,
                                     int strokeWidthDp) {
        GradientDrawable drawable = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR, colors);
        drawable.setCornerRadius(dp(context, radiusDp));
        if (strokeWidthDp > 0) drawable.setStroke(dp(context, strokeWidthDp), strokeColor);
        return drawable;
    }

    /**
     * Static tech surface: neon surface with circuit grid, edge highlight and
     * a soft accent glow. Draws only on state-change invalidation, so the
     * accessibility tree stays idle. Accent follows the semantic state colour.
     */
    static android.graphics.drawable.Drawable glowCard(Context context, int surfaceColor,
                                                       int accentColor, float radiusDp) {
        return new FxGlowDrawable(context, surfaceColor, accentColor, radiusDp, 1);
    }

    static LinearLayout.LayoutParams match(Context context, int topMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(context, topMarginDp);
        return params;
    }

    static LinearLayout.LayoutParams weighted(Context context, float weight, int endMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, weight);
        params.setMarginEnd(dp(context, endMarginDp));
        return params;
    }

    static LinearLayout.LayoutParams fixed(Context context, int widthDp, int heightDp,
                                           int endMarginDp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(dp(context, widthDp),
                dp(context, heightDp));
        params.setMarginEnd(dp(context, endMarginDp));
        return params;
    }

    static ColorStateList seekBarTint(int color) {
        return ColorStateList.valueOf(color);
    }

    private static Button buttonBase(Context context, CharSequence value) {
        Button button = new Button(context);
        button.setText(value);
        button.setTextSize(15);
        button.setAllCaps(false);
        button.setGravity(Gravity.CENTER);
        button.setPadding(dp(context, 16), 0, dp(context, 16), 0);
        button.setStateListAnimator(null);
        return button;
    }

    /**
     * Primary states: a 45° electric-violet gradient at rest, a deepened
     * violet gradient while pressed, and a slate surface at reduced opacity
     * when disabled (no flat grey fill, no whole-button alpha hack).
     */
    private static StateListDrawable primaryPressable(Context context) {
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[]{android.R.attr.state_pressed},
                gradient(context, new int[]{PRIMARY_PRESSED, PRIMARY}, 12, PRIMARY_PRESSED, 1));
        states.addState(new int[]{android.R.attr.state_focused},
                gradient(context, new int[]{PRIMARY_PRESSED, PRIMARY}, 12, ACCENT, 1));
        states.addState(new int[]{-android.R.attr.state_enabled},
                gradient(context, new int[]{FxGlowDrawable.withAlpha(DISABLED, 0.52f),
                        FxGlowDrawable.withAlpha(DISABLED, 0.40f)}, 12,
                        FxGlowDrawable.withAlpha(DISABLED, 0.35f), 1));
        states.addState(new int[]{},
                gradient(context, new int[]{PRIMARY, ACCENT}, 12, PRIMARY, 1));
        return states;
    }

    private static ColorStateList primaryTextColors() {
        return new ColorStateList(
                new int[][]{new int[]{-android.R.attr.state_enabled}, new int[]{}},
                new int[]{FxGlowDrawable.withAlpha(Color.WHITE, 0.65f), Color.WHITE});
    }

    /**
     * Quick, interruptible 0.97 press scale driven by the vsync-choreographed
     * view animator; returning false keeps the normal click/ripple path, so
     * performClick stays with the framework's own click handling.
     */
    @android.annotation.SuppressLint("ClickableViewAccessibility")
    private static void attachPressScale(Button button) {
        button.setOnTouchListener((view, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    view.animate().cancel();
                    view.animate().scaleX(0.97f).scaleY(0.97f).setDuration(90L).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    view.animate().cancel();
                    view.animate().scaleX(1.0f).scaleY(1.0f).setDuration(140L).start();
                    break;
                default:
                    break;
            }
            return false;
        });
    }

    private static StateListDrawable pressable(Context context, int normal, int pressed,
                                               int radiusDp, int outline) {
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[]{android.R.attr.state_pressed},
                rounded(context, pressed, radiusDp, outline, 1));
        states.addState(new int[]{android.R.attr.state_focused},
                rounded(context, pressed, radiusDp, ACCENT, 1));
        states.addState(new int[]{}, rounded(context, normal, radiusDp, outline, 1));
        return states;
    }

    private static Typeface materialIconTypeface(Context context) {
        if (materialIcons == null) {
            materialIcons = Typeface.createFromAsset(context.getAssets(),
                    "fonts/MaterialIcons-Regular.ttf");
        }
        return materialIcons;
    }
}
