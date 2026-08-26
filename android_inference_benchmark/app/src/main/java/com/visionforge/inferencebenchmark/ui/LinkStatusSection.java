package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.R;

/** Reusable link-health section rendered inside the unified inference destination. */
final class LinkStatusSection {
    private final Context context;
    private final LinearLayout root;
    private TextView connectionIcon;
    private TextView connectionTitle;
    private TextView connectionHealth;
    private TextView connectionDetail;
    private LinearLayout connectionCard;
    private FxGlowDrawable connectionGlow;
    private FxPhaseGlowView connectionPhaseGlow;
    private FxPulseRingView connectionPulse;
    private FxParticleBurstView connectionBurst;
    private Boolean lastLive;
    private int lastConnectionColor;
    private StageView udpStage;
    private StageView decoderStage;
    private StageView qnnStage;
    private StageView outputStage;
    private MetricView processingMetric;
    private MetricView inputMetric;
    private MetricView decodedMetric;
    private MetricView inferenceThroughputMetric;
    private MetricView qnnMetric;
    private MetricView failureMetric;
    private TextView safetyIcon;
    private TextView safetyNote;

    LinkStatusSection(Context context) {
        this.context = context;
        root = new LinearLayout(context);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setContentDescription(UiAutomationIds.INFERENCE_LINK_STATUS);
        root.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        root.addView(createConnectionCard(), VisionForgeTheme.match(context, 4));
        addSafetyStatus(root);
        root.addView(VisionForgeTheme.sectionLabel(context, R.string.section_pipeline));
        root.addView(createPipelineStages());
        root.addView(VisionForgeTheme.sectionLabel(context, R.string.section_metrics));
        root.addView(createMetricsCard());
    }

    private View createConnectionCard() {
        FrameLayout frame = new FrameLayout(context);
        connectionCard = VisionForgeTheme.card(context);
        LinearLayout connectionRow = new LinearLayout(context);
        connectionRow.setGravity(Gravity.CENTER_VERTICAL);
        connectionIcon = VisionForgeTheme.icon(context, MaterialIcons.LINK, 34,
                VisionForgeTheme.ACCENT);
        connectionIcon.setBackground(VisionForgeTheme.rounded(context,
                VisionForgeTheme.ACCENT_DARK, 32, VisionForgeTheme.OUTLINE_ACTIVE, 1));
        // Radial phase glow sits behind the icon and cross-fades its colour
        // with the receiver phase; it is decorative and accessibility-muted.
        FrameLayout iconFrame = new FrameLayout(context);
        connectionPhaseGlow = new FxPhaseGlowView(context);
        iconFrame.addView(connectionPhaseGlow, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        iconFrame.addView(connectionIcon, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        connectionRow.addView(iconFrame, VisionForgeTheme.fixed(context, 64, 64, 14));

        LinearLayout connectionCopy = new LinearLayout(context);
        connectionCopy.setOrientation(LinearLayout.VERTICAL);
        connectionTitle = VisionForgeTheme.text(context, "", 24, VisionForgeTheme.ACCENT);
        VisionForgeTheme.heading(connectionTitle);
        connectionHealth = VisionForgeTheme.text(context, "", 13, VisionForgeTheme.TEXT_MUTED);
        connectionHealth.setPadding(0, VisionForgeTheme.dp(context, 3), 0, 0);
        connectionDetail = VisionForgeTheme.text(context, "", 14, VisionForgeTheme.TEXT);
        connectionDetail.setPadding(0, VisionForgeTheme.dp(context, 9), 0, 0);
        connectionCopy.addView(connectionTitle);
        connectionCopy.addView(connectionHealth);
        connectionCopy.addView(connectionDetail);
        connectionRow.addView(connectionCopy, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        connectionCard.addView(connectionRow);
        frame.addView(connectionCard, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        connectionPulse = new FxPulseRingView(context);
        frame.addView(connectionPulse, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        connectionBurst = new FxParticleBurstView(context);
        frame.addView(connectionBurst, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        return frame;
    }

    private View createPipelineStages() {
        LinearLayout stages = new LinearLayout(context);
        stages.setOrientation(LinearLayout.HORIZONTAL);
        udpStage = new StageView(R.string.stage_udp, MaterialIcons.ETHERNET);
        decoderStage = new StageView(R.string.stage_decode, MaterialIcons.CODE);
        qnnStage = new StageView(R.string.stage_qnn, MaterialIcons.MEMORY);
        outputStage = new StageView(R.string.stage_makcu, MaterialIcons.USB);
        stages.addView(udpStage.frame, VisionForgeTheme.weighted(context, 1f, 7));
        stages.addView(decoderStage.frame, VisionForgeTheme.weighted(context, 1f, 7));
        stages.addView(qnnStage.frame, VisionForgeTheme.weighted(context, 1f, 7));
        stages.addView(outputStage.frame, VisionForgeTheme.weighted(context, 1f, 0));
        return stages;
    }

    private View createMetricsCard() {
        LinearLayout metricsCard = VisionForgeTheme.card(context);
        LinearLayout firstMetricRow = new LinearLayout(context);
        firstMetricRow.setOrientation(LinearLayout.HORIZONTAL);
        inputMetric = new MetricView(R.string.metric_input);
        decodedMetric = new MetricView(R.string.metric_decoded);
        firstMetricRow.addView(inputMetric.root, VisionForgeTheme.weighted(context, 1f, 8));
        firstMetricRow.addView(decodedMetric.root, VisionForgeTheme.weighted(context, 1f, 0));
        metricsCard.addView(firstMetricRow);

        LinearLayout secondMetricRow = new LinearLayout(context);
        secondMetricRow.setOrientation(LinearLayout.HORIZONTAL);
        inferenceThroughputMetric = new MetricView(R.string.metric_inference);
        qnnMetric = new MetricView(R.string.metric_qnn);
        secondMetricRow.addView(inferenceThroughputMetric.root,
                VisionForgeTheme.weighted(context, 1f, 8));
        secondMetricRow.addView(qnnMetric.root, VisionForgeTheme.weighted(context, 1f, 0));
        metricsCard.addView(secondMetricRow, VisionForgeTheme.match(context, 8));

        LinearLayout thirdMetricRow = new LinearLayout(context);
        thirdMetricRow.setOrientation(LinearLayout.HORIZONTAL);
        processingMetric = new MetricView(R.string.metric_phone_p50);
        failureMetric = new MetricView(R.string.metric_failures);
        thirdMetricRow.addView(processingMetric.root,
                VisionForgeTheme.weighted(context, 1f, 8));
        thirdMetricRow.addView(failureMetric.root, VisionForgeTheme.weighted(context, 1f, 0));
        metricsCard.addView(thirdMetricRow, VisionForgeTheme.match(context, 8));
        return metricsCard;
    }

    private void addSafetyStatus(LinearLayout page) {
        LinearLayout safetyRow = new LinearLayout(context);
        safetyRow.setGravity(Gravity.CENTER);
        safetyIcon = VisionForgeTheme.icon(context, MaterialIcons.LOCK, 18,
                VisionForgeTheme.WARNING);
        safetyRow.addView(safetyIcon, VisionForgeTheme.fixed(context, 24, 30, 5));
        safetyNote = VisionForgeTheme.text(context,
                context.getString(R.string.control_auto_locked), 13, VisionForgeTheme.WARNING);
        safetyRow.addView(safetyNote);
        page.addView(safetyRow, VisionForgeTheme.match(context, 18));
    }

    public View view() {
        return root;
    }

    public void render(MobileUiState state) {
        boolean receiverReady = state.receiverServiceReady || state.receiverRunning;
        int connectionColor = state.videoLinkLive ? VisionForgeTheme.ACCENT
                : receiverReady ? VisionForgeTheme.WARNING : VisionForgeTheme.TEXT_MUTED;
        if (state.videoLinkLive) {
            setConnection(R.string.connection_live, R.string.session_healthy,
                    R.string.connection_live_detail, connectionColor);
        } else if (receiverReady) {
            setConnection(R.string.connection_waiting, R.string.session_waiting,
                    detailOrDefault(state.ethernetDetail,
                            state.receiverRunning
                                    ? R.string.connection_waiting_detail
                                    : R.string.connection_service_ready_detail),
                    connectionColor);
        } else {
            setConnection(R.string.connection_stopped, R.string.session_stopped,
                    detailOrDefault(state.ethernetDetail,
                            R.string.connection_stopped_detail), connectionColor);
        }
        renderConnectionFx(state, connectionColor);
        udpStage.render(state.videoLinkLive ? R.string.state_online
                : state.receiverRunning ? R.string.state_ready
                        : state.receiverServiceReady ? R.string.state_waiting
                                : R.string.state_stopped,
                state.videoLinkLive ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED,
                false);
        decoderStage.render(state.decoderReady ? R.string.state_ready : R.string.state_waiting,
                state.decoderReady ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED,
                false);
        boolean pipelineRunning = state.pipelineRunning();
        qnnStage.render(pipelineRunning ? R.string.state_running : R.string.state_waiting,
                pipelineRunning ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED,
                hasFailures(state.qnnFailures));
        boolean selectedOutputReady = state.selectedOutputTransportReady();
        outputStage.render(
                state.bluetoothHidOutputRouteActive
                        ? R.string.stage_bluetooth_hid : R.string.stage_makcu,
                state.bluetoothHidOutputRouteActive
                        ? MaterialIcons.BLUETOOTH : MaterialIcons.USB,
                selectedOutputReady ? R.string.state_ready : R.string.state_disconnected,
                selectedOutputReady ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED,
                false);
        String unavailableMetric = "--";
        processingMetric.setValue(
                pipelineRunning ? state.phoneProcessingP50 : unavailableMetric);
        inputMetric.setValue(pipelineRunning ? state.accessUnitFps : unavailableMetric);
        decodedMetric.setValue(
                pipelineRunning ? state.decodedFrameFps : unavailableMetric);
        inferenceThroughputMetric.setValue(
                pipelineRunning ? state.qnnFps : unavailableMetric);
        qnnMetric.setValue(pipelineRunning ? state.qnnP50 : unavailableMetric);
        String visibleQnnFailures =
                pipelineRunning ? state.qnnFailures : unavailableMetric;
        failureMetric.setValue(visibleQnnFailures);
        // A non-zero failure count is a warning surface, not a healthy one.
        failureMetric.setValueColor(hasFailures(visibleQnnFailures)
                ? VisionForgeTheme.WARNING : VisionForgeTheme.ACCENT);

        VisionForgeTheme.setTextIfChanged(safetyNote, state.controlOutputRecoverySuspended
                ? context.getString(R.string.control_recovery_suspended)
                : state.controlOutputEnabled ? context.getString(R.string.control_enabled)
                : selectedOutputReady ? context.getString(R.string.control_ready)
                : context.getString(R.string.control_auto_locked));
        int safetyColor = state.controlOutputRecoverySuspended
                ? VisionForgeTheme.WARNING
                : state.controlOutputEnabled || selectedOutputReady
                        ? VisionForgeTheme.ACCENT : VisionForgeTheme.WARNING;
        safetyIcon.setText(state.controlOutputRecoverySuspended
                ? MaterialIcons.REFRESH
                : state.controlOutputEnabled ? MaterialIcons.CHECK
                : selectedOutputReady ? MaterialIcons.SHIELD : MaterialIcons.LOCK);
        safetyIcon.setTextColor(safetyColor);
        safetyNote.setTextColor(safetyColor);
    }

    private void setConnection(int title, int health, int detail, int color) {
        setConnection(title, health, context.getString(detail), color);
    }

    private void setConnection(int title, int health, String detail, int color) {
        VisionForgeTheme.setTextIfChanged(connectionTitle, context.getString(title));
        VisionForgeTheme.setTextIfChanged(connectionHealth, context.getString(health));
        VisionForgeTheme.setTextIfChanged(connectionDetail, detail);
        connectionTitle.setTextColor(color);
        connectionIcon.setTextColor(color);
    }

    private String detailOrDefault(String detail, int fallback) {
        return detail == null || detail.isBlank() ? context.getString(fallback) : detail;
    }

    private void renderConnectionFx(MobileUiState state, int connectionColor) {
        boolean live = state.videoLinkLive;
        int effects = lastLive == null
                ? FxTransitionPolicy.EFFECT_NONE
                : FxTransitionPolicy.forConnectionChange(lastLive, live);
        boolean colorChanged = lastConnectionColor != 0 && lastConnectionColor != connectionColor;
        lastLive = live;
        lastConnectionColor = connectionColor;
        int glowAccent = live ? VisionForgeTheme.ACCENT
                : (state.receiverServiceReady || state.receiverRunning)
                        ? VisionForgeTheme.WARNING : VisionForgeTheme.OUTLINE;
        // Hero radial phase glow: healthy = soft violet, failure = coral,
        // waiting/idle = slate-violet. Failure follows the QNN failure count,
        // the only explicit failure signal in the link state.
        int phaseColor = live ? VisionForgeTheme.ACCENT
                : state.receiverRunning && hasFailures(state.qnnFailures)
                        ? VisionForgeTheme.DANGER : VisionForgeTheme.HERO_WAITING;
        connectionPhaseGlow.setPhase(phaseColor);
        if (connectionGlow == null) {
            connectionGlow = new FxGlowDrawable(context, VisionForgeTheme.SURFACE, glowAccent, 12, 1);
            connectionCard.setBackground(connectionGlow);
        } else {
            connectionGlow.retarget(VisionForgeTheme.SURFACE, glowAccent);
        }
        if ((effects & FxTransitionPolicy.EFFECT_PULSE_RING) != 0) {
            connectionPulse.pulse(connectionColor);
        }
        if ((effects & FxTransitionPolicy.EFFECT_PARTICLE_BURST) != 0) {
            connectionBurst.burst(connectionColor);
        }
        if ((effects & FxTransitionPolicy.EFFECT_COLOR_SWEEP) != 0 || colorChanged) {
            crossFade(connectionCard, connectionIcon);
        }
    }

    /** Bounded cross-fade used for colour sweeps; settles back to alpha 1. */
    private static void crossFade(View card, TextView icon) {
        card.animate().cancel();
        icon.animate().cancel();
        card.setAlpha(1.0f);
        long half = FxTransitionPolicy.SWEEP_DURATION_MS / 2;
        card.animate().alpha(0.55f).setDuration(half)
                .withEndAction(() -> card.animate().alpha(1.0f).setDuration(half).start())
                .start();
        icon.setAlpha(0.0f);
        icon.animate().alpha(1.0f).setDuration(FxTransitionPolicy.SWEEP_DURATION_MS).start();
    }

    private static boolean hasFailures(String failures) {
        return failures != null && !"--".equals(failures) && !"0".equals(failures);
    }

    private final class StageView {
        final FrameLayout frame;
        final LinearLayout root;
        final TextView title;
        final TextView icon;
        final TextView state;
        final FxPulseRingView pulse;
        final FxParticleBurstView burst;
        final View iconGlow;
        final android.graphics.drawable.GradientDrawable iconGlowDrawable;
        FxGlowDrawable glow;
        Boolean lastHealthy;
        int lastColor;
        int lastSemantic;

        StageView(int titleResource, String glyph) {
            frame = new FrameLayout(context);
            root = VisionForgeTheme.card(context);
            root.setGravity(Gravity.CENTER);
            root.setPadding(VisionForgeTheme.dp(context, 5), VisionForgeTheme.dp(context, 12),
                    VisionForgeTheme.dp(context, 5), VisionForgeTheme.dp(context, 12));
            title = VisionForgeTheme.text(context, context.getString(titleResource), 11,
                    VisionForgeTheme.TEXT);
            title.setGravity(Gravity.CENTER);
            VisionForgeTheme.heading(title);
            root.addView(title);
            icon = VisionForgeTheme.icon(context, glyph, 28, VisionForgeTheme.TEXT_MUTED);
            // Low-alpha semantic glow plate behind the icon; decorative only.
            FrameLayout iconFrame = new FrameLayout(context);
            iconGlowDrawable = VisionForgeTheme.rounded(context,
                    FxGlowDrawable.withAlpha(VisionForgeTheme.DISABLED, 0.16f), 12,
                    FxGlowDrawable.withAlpha(VisionForgeTheme.DISABLED, 0.32f), 1);
            iconGlow = new View(context);
            iconGlow.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
            iconGlow.setBackground(iconGlowDrawable);
            iconFrame.addView(iconGlow, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
            iconFrame.addView(icon, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
            LinearLayout.LayoutParams iconSlot = new LinearLayout.LayoutParams(
                    VisionForgeTheme.dp(context, 44), VisionForgeTheme.dp(context, 44));
            iconSlot.gravity = Gravity.CENTER_HORIZONTAL;
            iconSlot.topMargin = VisionForgeTheme.dp(context, 8);
            root.addView(iconFrame, iconSlot);
            state = VisionForgeTheme.text(context, "", 10, VisionForgeTheme.TEXT_MUTED);
            state.setGravity(Gravity.CENTER);
            root.addView(state, VisionForgeTheme.match(context, 5));
            frame.addView(root, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
            pulse = new FxPulseRingView(context);
            frame.addView(pulse, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
            burst = new FxParticleBurstView(context);
            frame.addView(burst, new FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));
        }

        void render(
                int titleResource,
                String glyph,
                int stateResource,
                int color,
                boolean failed) {
            VisionForgeTheme.setTextIfChanged(title, context.getString(titleResource));
            VisionForgeTheme.setTextIfChanged(icon, glyph);
            render(stateResource, color, failed);
        }

        void render(int stateResource, int color, boolean failed) {
            VisionForgeTheme.setTextIfChanged(state, context.getString(stateResource));
            state.setTextColor(color);
            icon.setTextColor(color);
            boolean healthy = color == VisionForgeTheme.ACCENT && !failed;
            int effects = lastHealthy == null
                    ? FxTransitionPolicy.EFFECT_NONE
                    : FxTransitionPolicy.forStageChange(lastHealthy, healthy);
            boolean colorChanged = lastColor != 0 && lastColor != color;
            lastHealthy = healthy;
            lastColor = color;
            // Semantic: healthy = soft violet, failure = coral, idle = slate.
            int semantic = failed ? VisionForgeTheme.DANGER
                    : color == VisionForgeTheme.ACCENT ? VisionForgeTheme.ACCENT
                    : VisionForgeTheme.DISABLED;
            renderSemantic(semantic);
            int glowAccent = failed ? VisionForgeTheme.DANGER
                    : healthy ? VisionForgeTheme.ACCENT : VisionForgeTheme.OUTLINE;
            if (glow == null) {
                glow = new FxGlowDrawable(context, VisionForgeTheme.SURFACE, glowAccent, 12, 1);
                root.setBackground(glow);
            } else {
                glow.retarget(VisionForgeTheme.SURFACE, glowAccent);
            }
            if ((effects & FxTransitionPolicy.EFFECT_PULSE_RING) != 0) pulse.pulse(color);
            if ((effects & FxTransitionPolicy.EFFECT_PARTICLE_BURST) != 0) burst.burst(color);
            if ((effects & FxTransitionPolicy.EFFECT_COLOR_SWEEP) != 0 || colorChanged) {
                crossFade(root, icon);
            }
        }

        /**
         * Applies the semantic colour to the icon glow plate. On a
         * real change only that decoration runs a bounded 200 ms
         * fade-out/recolour/fade-in; the card itself never flashes.
         */
        private void renderSemantic(int semantic) {
            if (lastSemantic == semantic) return;
            if (lastSemantic == 0) {
                iconGlowDrawable.setColor(FxGlowDrawable.withAlpha(semantic, 0.16f));
                iconGlowDrawable.setStroke(VisionForgeTheme.dp(context, 1),
                        FxGlowDrawable.withAlpha(semantic, 0.32f));
                lastSemantic = semantic;
                return;
            }
            lastSemantic = semantic;
            long half = FxTransitionPolicy.SEMANTIC_FADE_MS / 2;
            iconGlow.animate().cancel();
            iconGlow.animate().alpha(0.0f).setDuration(half)
                    .withEndAction(() -> {
                        iconGlowDrawable.setColor(FxGlowDrawable.withAlpha(semantic, 0.16f));
                        iconGlowDrawable.setStroke(VisionForgeTheme.dp(context, 1),
                                FxGlowDrawable.withAlpha(semantic, 0.32f));
                        iconGlow.animate().alpha(1.0f).setDuration(half).start();
                    })
                    .start();
        }
    }

    private final class MetricView {
        final LinearLayout root;
        final TextView value;

        MetricView(int labelResource) {
            root = new LinearLayout(context);
            root.setOrientation(LinearLayout.VERTICAL);
            root.setPadding(VisionForgeTheme.dp(context, 12), VisionForgeTheme.dp(context, 12),
                    VisionForgeTheme.dp(context, 12), VisionForgeTheme.dp(context, 12));
            root.setBackground(VisionForgeTheme.rounded(context, VisionForgeTheme.BACKGROUND, 12,
                    VisionForgeTheme.OUTLINE, 1));
            TextView label = VisionForgeTheme.text(context, context.getString(labelResource), 12,
                    VisionForgeTheme.TEXT_MUTED);
            root.addView(label);
            value = VisionForgeTheme.text(context, "--", 22, VisionForgeTheme.ACCENT);
            value.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            // Static neon halo on the metric digits; set once, zero per-tick cost.
            value.setShadowLayer(VisionForgeTheme.dp(context, 5), 0, 0,
                    FxGlowDrawable.withAlpha(VisionForgeTheme.ACCENT, 0.55f));
            value.setPadding(0, VisionForgeTheme.dp(context, 6), 0, 0);
            root.addView(value);
        }

        void setValue(String newValue) {
            VisionForgeTheme.setTextIfChanged(value,
                    newValue == null || newValue.isEmpty() ? "--" : newValue);
        }

        void setValueColor(int color) {
            value.setTextColor(color);
        }
    }
}
