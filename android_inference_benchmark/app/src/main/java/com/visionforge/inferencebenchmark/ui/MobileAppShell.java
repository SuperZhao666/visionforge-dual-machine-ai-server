package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.R;

import java.util.EnumMap;
import java.util.Map;

/** Activity-owned application shell with real destination switching and safe insets. */
public final class MobileAppShell {
    private final Context context;
    private final MobileAppActions actions;
    private final FrameLayout shellFrame;
    private final LinearLayout root;
    private final FxIonFieldView ionField;
    private final FrameLayout content;
    private final BottomNavigationBar navigation;
    private final Map<MobileDestination, MobileScreen> screens = new EnumMap<>(MobileDestination.class);
    private MobileDestination selectedDestination = MobileDestination.INFERENCE;
    private MobileUiState latestState;
    private boolean hasLaidOut;

    public MobileAppShell(Context context, MobileAppActions actions) {
        this.context = context;
        this.actions = actions;
        shellFrame = createShellFrame();
        root = createRoot();
        ionField = new FxIonFieldView(context);
        // Z-order: static backdrop (frame background) < ion field < content.
        // The ion layer never intercepts touches and sits below every screen.
        shellFrame.addView(ionField, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        shellFrame.addView(root, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        root.addView(createAppBar(), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, VisionForgeTheme.dp(context, 62)));
        content = createContent();
        root.addView(content, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        createScreens();
        navigation = new BottomNavigationBar(context,
                destination -> selectDestination(destination, true));
        root.addView(navigation.view(), new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, VisionForgeTheme.dp(context, 70)));
        // One-time bounded entrance; settles to a fully idle tree afterwards.
        root.post(() -> {
            hasLaidOut = true;
            View first = screens.get(selectedDestination).view();
            first.setAlpha(0.0f);
            first.setTranslationY(VisionForgeTheme.dp(context, 18));
            first.animate().alpha(1.0f).translationY(0.0f).setDuration(380L).start();
        });
    }

    private FrameLayout createShellFrame() {
        FrameLayout frame = new FrameLayout(context);
        frame.setBackground(new FxBackdropDrawable());
        frame.setOnApplyWindowInsetsListener((view, insets) -> applyInsets(insets));
        return frame;
    }

    private LinearLayout createRoot() {
        LinearLayout shell = new LinearLayout(context);
        shell.setOrientation(LinearLayout.VERTICAL);
        // Transparent: the nebula backdrop and the ion field live underneath.
        shell.setBackgroundColor(android.graphics.Color.TRANSPARENT);
        return shell;
    }

    private View createAppBar() {
        boolean compactHeader = context.getResources().getConfiguration().screenWidthDp <= 360;
        int brandSizeDp = compactHeader ? 40 : 46;
        LinearLayout appBar = new LinearLayout(context);
        appBar.setOrientation(LinearLayout.HORIZONTAL);
        appBar.setGravity(Gravity.CENTER_VERTICAL);
        appBar.setPadding(VisionForgeTheme.dp(context, compactHeader ? 10 : 16),
                VisionForgeTheme.dp(context, 8),
                VisionForgeTheme.dp(context, compactHeader ? 8 : 12),
                VisionForgeTheme.dp(context, 8));
        // Static brand halo behind the launcher mark; no animation, idle-safe.
        FrameLayout brandFrame = new FrameLayout(context);
        android.graphics.drawable.GradientDrawable halo =
                new android.graphics.drawable.GradientDrawable();
        halo.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        halo.setGradientType(android.graphics.drawable.GradientDrawable.RADIAL_GRADIENT);
        halo.setGradientRadius(VisionForgeTheme.dp(context, 30));
        halo.setColors(new int[]{FxGlowDrawable.withAlpha(0xFF8B5CF6, 0.55f),
                FxGlowDrawable.withAlpha(0xFF8B5CF6, 0.0f)});
        halo.setGradientCenter(0.5f, 0.5f);
        View haloView = new View(context);
        haloView.setBackground(halo);
        haloView.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        brandFrame.addView(haloView, new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT));
        ImageView brandMark = new ImageView(context);
        brandMark.setImageResource(R.drawable.visionforge_launcher);
        brandMark.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        brandFrame.addView(brandMark, new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT));
        appBar.addView(brandFrame, VisionForgeTheme.fixed(
                context, brandSizeDp, brandSizeDp, compactHeader ? 6 : 10));
        TextView title = VisionForgeTheme.text(context, context.getString(R.string.app_name), 22,
                VisionForgeTheme.TEXT);
        title.setSingleLine(true);
        // setSingleLine enables horizontal scrolling internally. Disable it again so
        // TextView auto-size measures the actual weighted width instead of an infinite row.
        title.setHorizontallyScrolling(false);
        title.setMaxLines(1);
        title.setEllipsize(TextUtils.TruncateAt.END);
        title.setAutoSizeTextTypeUniformWithConfiguration(
                compactHeader ? 8 : 12, compactHeader ? 20 : 22,
                1, TypedValue.COMPLEX_UNIT_SP);
        VisionForgeTheme.heading(title);
        appBar.addView(title, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        TextView logExport = VisionForgeTheme.icon(context, MaterialIcons.SETTINGS, 27,
                VisionForgeTheme.TEXT);
        logExport.setClickable(true);
        logExport.setFocusable(true);
        logExport.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        logExport.setContentDescription(context.getString(R.string.action_export_runtime_log));
        logExport.setOnClickListener(view -> actions.onExportRuntimeLog());
        appBar.addView(logExport, VisionForgeTheme.fixed(context, 46, 46, 0));
        return appBar;
    }

    private FrameLayout createContent() {
        FrameLayout frame = new FrameLayout(context);
        frame.setBackgroundColor(android.graphics.Color.TRANSPARENT);
        return frame;
    }

    private void createScreens() {
        screens.put(MobileDestination.AUTHORIZATION,
                new AuthorizationScreen(context, actions));
        screens.put(MobileDestination.INFERENCE, new InferenceScreen(context));
        screens.put(MobileDestination.CONTROL, new ControlScreen(context, actions));
        for (MobileDestination destination : MobileDestination.values()) {
            View screen = screens.get(destination).view();
            screen.setVisibility(destination == selectedDestination ? View.VISIBLE : View.GONE);
            content.addView(screen, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        }
    }

    public View view() {
        return shellFrame;
    }

    public MobileDestination selectedDestination() {
        return selectedDestination;
    }

    public void restoreDestination(MobileDestination destination) {
        selectDestination(destination == null ? MobileDestination.INFERENCE : destination, false);
    }

    public void render(MobileUiState state) {
        latestState = state;
        ionField.setRealtimeWorkActive(
                state.videoLinkLive || state.controlTriggerStreamReady);
        // Only the visible screen renders; hidden screens are refreshed once
        // when they become visible. Rendering GONE subtrees twice a second is
        // wasted layout work and the main source of frame-time spikes.
        MobileScreen visible = screens.get(selectedDestination);
        if (visible != null) visible.render(state);
    }

    /** Forwards activity-level user interaction to ambient decorative layers. */
    public void onUserInteraction() {
        ionField.onUserInteraction();
    }

    private void selectDestination(MobileDestination destination, boolean notify) {
        if (destination == null) return;
        View outgoing = screens.get(selectedDestination).view();
        View incoming = screens.get(destination).view();
        boolean animate = hasLaidOut && destination != selectedDestination;
        for (Map.Entry<MobileDestination, MobileScreen> entry : screens.entrySet()) {
            entry.getValue().view().setVisibility(
                    entry.getKey() == destination ? View.VISIBLE : View.GONE);
        }
        selectedDestination = destination;
        navigation.setSelected(destination);
        // Bring the incoming screen up to date before showing it; it has not
        // received ticks while hidden.
        if (latestState != null && destination != null) {
            screens.get(destination).render(latestState);
        }
        if (animate) {
            // Bounded swap: incoming slides up and fades in. The outgoing view
            // is already GONE, so fading it would tick an invisible animator
            // for 140 ms; cancel any stale animation and reset it instantly.
            outgoing.animate().cancel();
            outgoing.setAlpha(1.0f);
            outgoing.setTranslationY(0.0f);
            // Cancel first so rapid repeated switches never stack animators.
            incoming.animate().cancel();
            incoming.setAlpha(0.0f);
            incoming.setTranslationY(VisionForgeTheme.dp(context, 14));
            incoming.animate().alpha(1.0f).translationY(0.0f).setDuration(220L).start();
        }
        if (notify) actions.onDestinationSelected(destination);
    }

    @SuppressWarnings("deprecation") // minSdk 29 compatibility.
    private WindowInsets applyInsets(WindowInsets insets) {
        root.setPadding(0, insets.getSystemWindowInsetTop(), 0,
                insets.getSystemWindowInsetBottom());
        return insets;
    }
}
