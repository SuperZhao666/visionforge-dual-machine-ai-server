package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.SeekBar;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.ControlTrigger;
import com.visionforge.inferencebenchmark.MobileAimTarget;
import com.visionforge.inferencebenchmark.MobileModelCatalog;
import com.visionforge.inferencebenchmark.R;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Protected control destination; the hardware gate remains the authority. */
final class ControlScreen implements MobileScreen {
    private final Context context;
    private final ScrollView root;
    private final MobileAppActions actions;
    private final Map<ControlPreset, Button> presetButtons = new EnumMap<>(ControlPreset.class);
    private final Map<ControlTrigger, Button> triggerButtons =
            new EnumMap<>(ControlTrigger.class);
    private final Map<MobileModelCatalog.Profile, Button> modelButtons =
            new IdentityHashMap<>();
    private final Map<MobileAimTarget, Button> aimTargetButtons =
            new EnumMap<>(MobileAimTarget.class);
    private final List<LinearLayout> aimTargetRows = new ArrayList<>();
    private TextView deviceIcon;
    private TextView deviceName;
    private TextView deviceBadge;
    private TextView outputRouteStatus;
    private TextView outputRouteDetail;
    private Button makcuRouteButton;
    private Button bluetoothHidRouteButton;
    private SliderBinding gainSlider;
    private SliderBinding deadzoneSlider;
    private SliderBinding maximumSlider;
    private SliderBinding switchConfirmationSlider;
    private TextView maximumLimitDetail;
    private SliderBinding confidenceSlider;
    private TextView triggerStatus;
    private ControlPreset lastRenderedPreset;
    private ControlTrigger lastRenderedTrigger;
    private Boolean lastRouteMakcuActive;
    private Boolean lastRouteBluetoothActive;
    private Boolean lastRouteBluetoothAvailable;
    private MobileModelCatalog.Profile lastRenderedModel;
    private MobileAimTarget lastRenderedAimTarget;

    ControlScreen(Context context, MobileAppActions actions) {
        this.context = context;
        this.actions = actions;
        root = VisionForgeTheme.scrollPage(context);
        root.setContentDescription(UiAutomationIds.SCROLL_CONTROL);
        root.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        LinearLayout page = VisionForgeTheme.pageBody(context);
        root.addView(page);
        page.addView(createDeviceCard(), VisionForgeTheme.match(context, 4));
        page.addView(createOutputRouteCard(), VisionForgeTheme.match(context, 10));
        page.addView(createModelCard(), VisionForgeTheme.match(context, 10));
        page.addView(createAimTargetCard(), VisionForgeTheme.match(context, 10));
        page.addView(createTriggerCard(), VisionForgeTheme.match(context, 10));
        page.addView(createPresetCard(), VisionForgeTheme.match(context, 10));
        page.addView(VisionForgeTheme.sectionLabel(context, R.string.section_fine_tuning));
        addSliders(page);
        addActions(page);
    }

    /** Section-level glass surface; created once per card, zero per-tick cost. */
    private LinearLayout sectionCard() {
        LinearLayout card = VisionForgeTheme.card(context);
        card.setBackground(VisionForgeTheme.glowCard(
                context, VisionForgeTheme.SURFACE, VisionForgeTheme.OUTLINE, 12));
        return card;
    }

    private View createDeviceCard() {
        LinearLayout card = sectionCard();
        LinearLayout row = new LinearLayout(context);
        row.setGravity(Gravity.CENTER_VERTICAL);
        deviceIcon = VisionForgeTheme.icon(context, MaterialIcons.USB, 24,
                VisionForgeTheme.TEXT);
        deviceIcon.setBackground(VisionForgeTheme.rounded(
                context, VisionForgeTheme.SURFACE_RAISED,
                14, VisionForgeTheme.OUTLINE, 1));
        row.addView(deviceIcon, VisionForgeTheme.fixed(context, 46, 46, 12));
        deviceName = VisionForgeTheme.text(context,
                context.getString(R.string.output_route_makcu), 16,
                VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(deviceName);
        row.addView(deviceName, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        deviceBadge = VisionForgeTheme.pill(context, "", VisionForgeTheme.WARNING,
                VisionForgeTheme.SURFACE_RAISED);
        row.addView(deviceBadge);
        Button retry = VisionForgeTheme.compactButton(context, R.string.action_retry_device);
        retry.setTextColor(VisionForgeTheme.ACCENT);
        retry.setOnClickListener(view -> actions.onRetryOutputDevice());
        row.addView(retry, VisionForgeTheme.fixed(context, 104, 46, 0));
        card.addView(row);
        return card;
    }

    private View createOutputRouteCard() {
        LinearLayout card = sectionCard();
        LinearLayout header = new LinearLayout(context);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.addView(VisionForgeTheme.icon(context, MaterialIcons.TUNE, 22,
                VisionForgeTheme.ACCENT), VisionForgeTheme.fixed(context, 32, 42, 8));
        TextView title = VisionForgeTheme.text(
                context, context.getString(R.string.section_output_route), 16,
                VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(title);
        header.addView(title, new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        outputRouteStatus = VisionForgeTheme.pill(context, "",
                VisionForgeTheme.ACCENT, VisionForgeTheme.ACCENT_DARK);
        header.addView(outputRouteStatus);
        card.addView(header);

        outputRouteDetail = VisionForgeTheme.text(context, "", 12,
                VisionForgeTheme.TEXT_MUTED);
        outputRouteDetail.setPadding(0, VisionForgeTheme.dp(context, 5), 0,
                VisionForgeTheme.dp(context, 10));
        card.addView(outputRouteDetail);

        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        makcuRouteButton = VisionForgeTheme.compactButton(context, R.string.output_route_makcu);
        makcuRouteButton.setContentDescription(UiAutomationIds.OUTPUT_ROUTE_MAKCU);
        makcuRouteButton.setOnClickListener(view -> actions.onSelectMakcuOutputRoute());
        row.addView(makcuRouteButton, VisionForgeTheme.weighted(context, 1f, 6));
        bluetoothHidRouteButton = VisionForgeTheme.compactButton(
                context, R.string.output_route_bluetooth_hid);
        bluetoothHidRouteButton.setContentDescription(
                UiAutomationIds.OUTPUT_ROUTE_BLUETOOTH_HID);
        bluetoothHidRouteButton.setOnClickListener(
                view -> actions.onSelectBluetoothHidOutputRoute());
        row.addView(bluetoothHidRouteButton, VisionForgeTheme.weighted(context, 1f, 0));
        card.addView(row);
        return card;
    }

    private View createPresetCard() {
        LinearLayout card = sectionCard();
        card.setPadding(VisionForgeTheme.dp(context, 8), VisionForgeTheme.dp(context, 8),
                VisionForgeTheme.dp(context, 8), VisionForgeTheme.dp(context, 8));
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        addPresetButton(row, ControlPreset.STANDARD, R.string.preset_standard);
        addPresetButton(row, ControlPreset.PRECISE, R.string.preset_precise);
        addPresetButton(row, ControlPreset.CUSTOM, R.string.preset_custom);
        card.addView(row);
        return card;
    }

    private View createModelCard() {
        LinearLayout card = sectionCard();
        TextView title = VisionForgeTheme.text(
                context, context.getString(R.string.game_model_title), 16,
                VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(title);
        card.addView(title);
        for (int rowStart = 0;
                rowStart < MobileModelCatalog.PRODUCTION_SELECTABLE.length;
                rowStart += 2) {
            LinearLayout row = new LinearLayout(context);
            row.setOrientation(LinearLayout.HORIZONTAL);
            int rowSpacing = rowStart == 0 ? 9 : 6;
            row.setPadding(0, VisionForgeTheme.dp(context, rowSpacing), 0, 0);
            int rowEnd = Math.min(
                    rowStart + 2, MobileModelCatalog.PRODUCTION_SELECTABLE.length);
            for (int index = rowStart; index < rowEnd; index++) {
                MobileModelCatalog.Profile model =
                        MobileModelCatalog.PRODUCTION_SELECTABLE[index];
                addModelButton(
                        row, model, labelResourceForModel(model), index == rowEnd - 1);
            }
            card.addView(row);
        }
        return card;
    }

    private int labelResourceForModel(MobileModelCatalog.Profile model) {
        if (model == MobileModelCatalog.VALORANT) return R.string.game_valorant;
        if (model == MobileModelCatalog.OVERWATCH_2) return R.string.game_overwatch2;
        if (model == MobileModelCatalog.DELTA_FORCE) return R.string.game_delta_force;
        if (model == MobileModelCatalog.COUNTER_STRIKE_2) {
            return R.string.game_counter_strike_2;
        }
        return R.string.game_model_title;
    }

    private View createAimTargetCard() {
        LinearLayout card = sectionCard();
        TextView title = VisionForgeTheme.text(
                context, context.getString(R.string.aim_target_title), 16,
                VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(title);
        card.addView(title);
        LinearLayout firstRow = new LinearLayout(context);
        firstRow.setOrientation(LinearLayout.HORIZONTAL);
        firstRow.setPadding(0, VisionForgeTheme.dp(context, 9), 0, 0);
        addAimTargetButton(firstRow, MobileAimTarget.BODY, R.string.target_body, false);
        addAimTargetButton(firstRow, MobileAimTarget.HEAD, R.string.target_head, true);
        aimTargetRows.add(firstRow);
        card.addView(firstRow);
        LinearLayout secondRow = new LinearLayout(context);
        secondRow.setOrientation(LinearLayout.HORIZONTAL);
        addAimTargetButton(secondRow, MobileAimTarget.TEAMMATE, R.string.target_teammate, false);
        addAimTargetButton(secondRow, MobileAimTarget.AI, R.string.target_ai, false);
        addAimTargetButton(secondRow, MobileAimTarget.CROSSHAIR, R.string.target_crosshair, true);
        aimTargetRows.add(secondRow);
        card.addView(secondRow, VisionForgeTheme.match(context, 6));
        LinearLayout ctRow = new LinearLayout(context);
        ctRow.setOrientation(LinearLayout.HORIZONTAL);
        addAimTargetButton(ctRow, MobileAimTarget.CT_BODY, R.string.target_ct_body, false);
        addAimTargetButton(ctRow, MobileAimTarget.CT_HEAD, R.string.target_ct_head, true);
        aimTargetRows.add(ctRow);
        card.addView(ctRow, VisionForgeTheme.match(context, 6));
        LinearLayout tRow = new LinearLayout(context);
        tRow.setOrientation(LinearLayout.HORIZONTAL);
        addAimTargetButton(tRow, MobileAimTarget.T_BODY, R.string.target_t_body, false);
        addAimTargetButton(tRow, MobileAimTarget.T_HEAD, R.string.target_t_head, true);
        aimTargetRows.add(tRow);
        card.addView(tRow, VisionForgeTheme.match(context, 6));
        return card;
    }

    private void addModelButton(
            LinearLayout row, MobileModelCatalog.Profile model, int labelResource,
            boolean last) {
        Button button = VisionForgeTheme.compactButton(context, labelResource);
        button.setContentDescription(UiAutomationIds.gameModel(model.token));
        button.setOnClickListener(view -> actions.onSelectGameModel(model));
        modelButtons.put(model, button);
        row.addView(button, VisionForgeTheme.weighted(context, 1f, last ? 0 : 6));
    }

    private void addAimTargetButton(
            LinearLayout row, MobileAimTarget target, int labelResource, boolean last) {
        Button button = VisionForgeTheme.compactButton(context, labelResource);
        button.setContentDescription(UiAutomationIds.aimTarget(target.storageToken));
        button.setOnClickListener(view -> actions.onSetAimTarget(target));
        aimTargetButtons.put(target, button);
        row.addView(button, VisionForgeTheme.weighted(context, 1f, last ? 0 : 6));
    }

    private View createTriggerCard() {
        LinearLayout card = sectionCard();
        LinearLayout header = new LinearLayout(context);
        header.setGravity(Gravity.CENTER_VERTICAL);
        TextView title = VisionForgeTheme.text(
                context, context.getString(R.string.control_trigger_title), 16,
                VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(title);
        header.addView(title, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        triggerStatus = VisionForgeTheme.pill(
                context, "", VisionForgeTheme.ACCENT,
                VisionForgeTheme.ACCENT_DARK);
        header.addView(triggerStatus);
        card.addView(header);
        TextView detail = VisionForgeTheme.text(
                context, context.getString(R.string.control_trigger_detail), 12,
                VisionForgeTheme.TEXT_MUTED);
        detail.setPadding(0, VisionForgeTheme.dp(context, 5), 0,
                VisionForgeTheme.dp(context, 10));
        card.addView(detail);
        LinearLayout firstRow = new LinearLayout(context);
        firstRow.setOrientation(LinearLayout.HORIZONTAL);
        addTriggerButton(firstRow, ControlTrigger.RIGHT_MOUSE,
                R.string.trigger_right_mouse, false);
        addTriggerButton(firstRow, ControlTrigger.SIDE_BUTTON_1,
                R.string.trigger_mouse4, true);
        card.addView(firstRow);
        LinearLayout secondRow = new LinearLayout(context);
        secondRow.setOrientation(LinearLayout.HORIZONTAL);
        addTriggerButton(secondRow, ControlTrigger.SIDE_BUTTON_2,
                R.string.trigger_mouse5, false);
        addTriggerButton(secondRow, ControlTrigger.ALWAYS,
                R.string.trigger_always, true);
        card.addView(secondRow, VisionForgeTheme.match(context, 6));
        return card;
    }

    private void addTriggerButton(
            LinearLayout row, ControlTrigger trigger, int labelResource,
            boolean isLastInRow) {
        Button button = VisionForgeTheme.compactButton(context, labelResource);
        button.setOnClickListener(view -> actions.onSetControlTrigger(trigger));
        triggerButtons.put(trigger, button);
        row.addView(button, VisionForgeTheme.weighted(context, 1f,
                isLastInRow ? 0 : 6));
    }

    private void addPresetButton(LinearLayout row, ControlPreset preset, int labelResource) {
        Button button = VisionForgeTheme.compactButton(context, labelResource);
        button.setOnClickListener(view -> actions.onApplyControlPreset(preset));
        presetButtons.put(preset, button);
        row.addView(button, VisionForgeTheme.weighted(context, 1f,
                preset == ControlPreset.CUSTOM ? 0 : 6));
    }

    private void addSliders(LinearLayout page) {
        gainSlider = new SliderBinding(R.string.control_gain, 0.01f, 2.00f, 199,
                value -> String.format(Locale.US, "%.2f", value), actions::onSetControlGain);
        page.addView(gainSlider.root);
        deadzoneSlider = new SliderBinding(R.string.control_deadzone, 0.0f, 64.0f, 128,
                value -> String.format(Locale.US, "%.1f px", value), actions::onSetControlDeadzone);
        page.addView(deadzoneSlider.root, VisionForgeTheme.match(context, 8));
        maximumSlider = new SliderBinding(R.string.control_max_axis, 1.0f, 127.0f, 126,
                value -> Integer.toString(Math.round(value)),
                value -> actions.onSetMaximumAxisDelta(Math.round(value)));
        page.addView(maximumSlider.root, VisionForgeTheme.match(context, 8));
        switchConfirmationSlider = new SliderBinding(
                R.string.control_switch_confirmation, 10.0f, 100.0f, 18,
                value -> context.getString(
                        R.string.control_switch_confirmation_value,
                        Math.round(value)),
                value -> actions.onSetSwitchConfirmationMillis(Math.round(value)));
        page.addView(switchConfirmationSlider.root, VisionForgeTheme.match(context, 8));
        maximumLimitDetail = VisionForgeTheme.text(context,
                context.getString(R.string.control_effective_limits_pending), 12,
                VisionForgeTheme.TEXT_MUTED);
        maximumLimitDetail.setPadding(0, VisionForgeTheme.dp(context, 2), 0, 0);
        page.addView(maximumLimitDetail);
        confidenceSlider = new SliderBinding(R.string.inference_confidence, 0.10f, 0.85f, 75,
                value -> String.format(Locale.US, "%.2f", value), actions::onSetInferenceConfidence);
        page.addView(confidenceSlider.root, VisionForgeTheme.match(context, 8));
    }

    private void addActions(LinearLayout page) {
        Button restore = VisionForgeTheme.secondaryButton(context, R.string.action_restore_defaults);
        restore.setOnClickListener(view -> actions.onRestoreControlDefaults());
        page.addView(restore, VisionForgeTheme.match(context, 12));
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void render(MobileUiState state) {
        renderModelAndTarget(state);
        renderOutputRoute(state);
        boolean selectedOutputReady = state.selectedOutputTransportReady();
        VisionForgeTheme.setTextIfChanged(deviceName, context.getString(
                state.bluetoothHidOutputRouteActive
                        ? R.string.output_route_bluetooth_hid
                        : R.string.output_route_makcu));
        VisionForgeTheme.setTextIfChanged(deviceIcon,
                state.bluetoothHidOutputRouteActive
                        ? MaterialIcons.BLUETOOTH : MaterialIcons.USB);
        VisionForgeTheme.setTextIfChanged(deviceBadge, context.getString(
                selectedOutputReady ? R.string.state_ready : R.string.state_disconnected));
        deviceBadge.setTextColor(
                selectedOutputReady ? VisionForgeTheme.ACCENT : VisionForgeTheme.WARNING);
        gainSlider.render(state.controlGain);
        deadzoneSlider.render(state.controlDeadzonePixels);
        maximumSlider.render(state.maximumAxisDelta);
        switchConfirmationSlider.render(state.switchConfirmationMillis);
        renderEffectiveMotionLimits(state);
        confidenceSlider.render(state.confidence);
        renderPreset(state.selectedPreset);
        renderTrigger(state);
    }

    private void renderEffectiveMotionLimits(MobileUiState state) {
        boolean available = state.effectiveUncalibratedMaximumAxisDelta > 0
                && state.maximumStepCountsPerTick >= 0.0f
                && state.maximumJerkCountsPerTick2 >= 0.0f;
        String detail = available
                ? context.getString(R.string.control_effective_limits,
                        state.effectiveUncalibratedMaximumAxisDelta,
                        state.maximumStepCountsPerTick,
                        state.maximumJerkCountsPerTick2)
                : context.getString(R.string.control_effective_limits_pending);
        VisionForgeTheme.setTextIfChanged(maximumLimitDetail, detail);
    }

    private void renderModelAndTarget(MobileUiState state) {
        if (state.activeModel == lastRenderedModel
                && state.aimTarget == lastRenderedAimTarget) return;
        lastRenderedModel = state.activeModel;
        lastRenderedAimTarget = state.aimTarget;
        for (Map.Entry<MobileModelCatalog.Profile, Button> entry : modelButtons.entrySet()) {
            styleSelectorButton(entry.getValue(), entry.getKey() == state.activeModel);
        }
        for (Map.Entry<MobileAimTarget, Button> entry : aimTargetButtons.entrySet()) {
            boolean supported = state.activeModel.supports(entry.getKey());
            entry.getValue().setVisibility(supported ? View.VISIBLE : View.GONE);
            styleSelectorButton(entry.getValue(), supported && entry.getKey() == state.aimTarget);
        }
        for (LinearLayout row : aimTargetRows) {
            boolean hasVisibleTarget = false;
            for (int index = 0; index < row.getChildCount(); index++) {
                if (row.getChildAt(index).getVisibility() == View.VISIBLE) {
                    hasVisibleTarget = true;
                    break;
                }
            }
            row.setVisibility(hasVisibleTarget ? View.VISIBLE : View.GONE);
        }
    }

    private void styleSelectorButton(Button button, boolean active) {
        button.setTextColor(active ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED);
        button.setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
        button.setBackground(VisionForgeTheme.rounded(context,
                active ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.SURFACE,
                12, active ? VisionForgeTheme.ACCENT : VisionForgeTheme.OUTLINE, 1));
    }

    private void renderOutputRoute(MobileUiState state) {
        boolean bluetoothActive = state.bluetoothHidOutputRouteActive;
        VisionForgeTheme.setTextIfChanged(outputRouteStatus, context.getString(
                bluetoothActive
                        ? R.string.output_route_status_bluetooth_hid
                        : R.string.output_route_status_makcu));
        int detailResource;
        if (bluetoothActive) {
            if (!state.bluetoothHidPermissionGranted) {
                detailResource = R.string.output_route_detail_bluetooth_permission;
            } else if (state.bluetoothHidSessionReady
                    && state.controlTriggerStreamReady) {
                detailResource = R.string.output_route_detail_bluetooth_connected;
            } else if (state.bluetoothHidSessionReady) {
                detailResource = R.string.output_route_detail_bluetooth_waiting_buttons;
            } else {
                detailResource = R.string.output_route_detail_bluetooth_selected;
            }
        } else if (!state.bluetoothHidOutputRouteAvailable) {
            detailResource = R.string.output_route_detail_bluetooth_unavailable;
        } else if (!state.bluetoothHidPermissionGranted) {
            detailResource = R.string.output_route_detail_bluetooth_permission;
        } else {
            detailResource = R.string.output_route_detail_makcu;
        }
        VisionForgeTheme.setTextIfChanged(outputRouteDetail, context.getString(detailResource));
        boolean bluetoothAvailable = state.bluetoothHidOutputRouteAvailable;
        if (lastRouteMakcuActive == null || lastRouteMakcuActive != bluetoothActive
                || lastRouteBluetoothActive == null || lastRouteBluetoothActive != bluetoothActive
                || lastRouteBluetoothAvailable == null
                || lastRouteBluetoothAvailable != bluetoothAvailable) {
            lastRouteMakcuActive = bluetoothActive;
            lastRouteBluetoothActive = bluetoothActive;
            lastRouteBluetoothAvailable = bluetoothAvailable;
            styleRouteButton(makcuRouteButton, !bluetoothActive, true);
            styleRouteButton(
                    bluetoothHidRouteButton,
                    bluetoothActive,
                    state.bluetoothHidOutputRouteAvailable);
        }
    }

    private void styleRouteButton(Button button, boolean active, boolean enabled) {
        button.setEnabled(enabled);
        int textColor = VisionForgeTheme.DISABLED;
        int outlineColor = VisionForgeTheme.DISABLED;
        if (enabled) {
            textColor = active ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED;
            outlineColor = active ? VisionForgeTheme.ACCENT : VisionForgeTheme.OUTLINE;
        }
        button.setTextColor(textColor);
        button.setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
        button.setBackground(VisionForgeTheme.rounded(context,
                active ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.SURFACE,
                12, outlineColor, 1));
    }

    private void renderPreset(ControlPreset selected) {
        if (selected == lastRenderedPreset) return;
        lastRenderedPreset = selected;
        for (Map.Entry<ControlPreset, Button> entry : presetButtons.entrySet()) {
            boolean active = entry.getKey() == selected;
            Button button = entry.getValue();
            button.setTextColor(active ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED);
            button.setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
            button.setBackground(VisionForgeTheme.rounded(context,
                    active ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.SURFACE,
                    12, active ? VisionForgeTheme.ACCENT : VisionForgeTheme.OUTLINE, 1));
        }
    }

    private void renderTrigger(MobileUiState state) {
        if (state.controlTrigger != lastRenderedTrigger) {
            lastRenderedTrigger = state.controlTrigger;
            for (Map.Entry<ControlTrigger, Button> entry : triggerButtons.entrySet()) {
                boolean active = entry.getKey() == state.controlTrigger;
                Button button = entry.getValue();
                button.setTextColor(active ? VisionForgeTheme.ACCENT
                        : VisionForgeTheme.TEXT_MUTED);
                button.setTypeface(active ? Typeface.DEFAULT_BOLD : Typeface.DEFAULT);
                button.setBackground(VisionForgeTheme.rounded(context,
                        active ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.SURFACE,
                        12, active ? VisionForgeTheme.ACCENT : VisionForgeTheme.OUTLINE, 1));
            }
        }
        int statusResource;
        int statusColor;
        if (!state.controlTrigger.requiresButtonStream()) {
            statusResource = R.string.trigger_status_continuous;
            statusColor = VisionForgeTheme.ACCENT;
        } else if (!state.controlTriggerStreamReady) {
            statusResource = R.string.trigger_status_connecting;
            statusColor = VisionForgeTheme.WARNING;
        } else if (state.controlTriggerPressed) {
            statusResource = R.string.trigger_status_pressed;
            statusColor = VisionForgeTheme.ACCENT;
        } else {
            statusResource = R.string.trigger_status_ready;
            statusColor = VisionForgeTheme.ACCENT;
        }
        VisionForgeTheme.setTextIfChanged(triggerStatus, context.getString(statusResource));
        triggerStatus.setTextColor(statusColor);
    }

    private interface ValueFormatter {
        String format(float value);
    }

    private interface ValueAction {
        void accept(float value);
    }

    private final class SliderBinding {
        final LinearLayout root;
        final TextView value;
        final SeekBar seekBar;
        final float minimum;
        final float maximum;
        final int steps;
        final ValueFormatter formatter;
        final ValueAction action;
        TextView label;
        Boolean lastEnabled;

        SliderBinding(int labelResource, float minimum, float maximum, int steps,
                      ValueFormatter formatter, ValueAction action) {
            this.minimum = minimum;
            this.maximum = maximum;
            this.steps = steps;
            this.formatter = formatter;
            this.action = action;
            root = VisionForgeTheme.card(context);
            root.setPadding(VisionForgeTheme.dp(context, 14), VisionForgeTheme.dp(context, 12),
                    VisionForgeTheme.dp(context, 14), VisionForgeTheme.dp(context, 10));
            value = addHeader(root, labelResource);
            seekBar = createSeekBar();
            root.addView(seekBar, VisionForgeTheme.match(context, 4));
        }

        private TextView addHeader(LinearLayout parent, int labelResource) {
            LinearLayout row = new LinearLayout(context);
            row.setGravity(Gravity.CENTER_VERTICAL);
            label = VisionForgeTheme.text(context, context.getString(labelResource), 15,
                    VisionForgeTheme.TEXT);
            VisionForgeTheme.heading(label);
            row.addView(label, new LinearLayout.LayoutParams(0,
                    LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            TextView valueView = VisionForgeTheme.pill(context, "", VisionForgeTheme.ACCENT,
                    VisionForgeTheme.ACCENT_DARK);
            row.addView(valueView);
            parent.addView(row);
            return valueView;
        }

        private SeekBar createSeekBar() {
            SeekBar bar = new SeekBar(context);
            bar.setMin(0);
            bar.setMax(steps);
            bar.setProgressTintList(VisionForgeTheme.seekBarTint(VisionForgeTheme.ACCENT));
            bar.setThumbTintList(VisionForgeTheme.seekBarTint(VisionForgeTheme.ACCENT));
            bar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
                @Override
                public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
                    if (fromUser) value.setText(formatter.format(toValue(progress)));
                }

                @Override
                public void onStartTrackingTouch(SeekBar seekBar) {
                }

                @Override
                public void onStopTrackingTouch(SeekBar seekBar) {
                    action.accept(toValue(seekBar.getProgress()));
                }
            });
            return bar;
        }

        void render(float current) {
            VisionForgeTheme.setTextIfChanged(value, formatter.format(current));
            int progress = Math.round((current - minimum) / (maximum - minimum) * steps);
            if (seekBar.getProgress() != progress) seekBar.setProgress(progress);
        }

        void setEnabled(boolean enabled) {
            if (lastEnabled != null && lastEnabled == enabled) return;
            lastEnabled = enabled;
            seekBar.setEnabled(enabled);
            // Keep the disabled state readable: muted text, a neutral value
            // pill and a greyed track instead of alpha-dimming the whole card.
            label.setTextColor(enabled ? VisionForgeTheme.TEXT : VisionForgeTheme.TEXT_MUTED);
            value.setTextColor(enabled ? VisionForgeTheme.ACCENT : VisionForgeTheme.TEXT_MUTED);
            value.setBackground(VisionForgeTheme.rounded(context,
                    enabled ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.SURFACE_RAISED,
                    20, enabled ? VisionForgeTheme.ACCENT_DARK : VisionForgeTheme.OUTLINE, 1));
            seekBar.setProgressTintList(VisionForgeTheme.seekBarTint(
                    enabled ? VisionForgeTheme.ACCENT : VisionForgeTheme.DISABLED));
            seekBar.setThumbTintList(VisionForgeTheme.seekBarTint(
                    enabled ? VisionForgeTheme.ACCENT : VisionForgeTheme.DISABLED));
        }

        private float toValue(int progress) {
            return minimum + (maximum - minimum) * progress / steps;
        }
    }

}
