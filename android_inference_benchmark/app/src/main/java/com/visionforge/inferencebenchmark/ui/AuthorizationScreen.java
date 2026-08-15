package com.visionforge.inferencebenchmark.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.text.InputFilter;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.DualMachineCardCode;
import com.visionforge.inferencebenchmark.R;

import java.util.Locale;

/** Card-key activation and remaining-time presentation boundary. */
final class AuthorizationScreen implements MobileScreen {
    private final Context context;
    private final MobileAppActions actions;
    private final ScrollView root;
    private final EditText cardCode;
    private final Button activate;
    private final Button resumeActivation;
    private final TextView statusIcon;
    private final TextView statusTitle;
    private final TextView statusDetail;
    private final TextView remaining;
    private final TextView activationLabel;
    private final LinearLayout activationCard;
    private final LinearLayout statusCard;
    private final FxPhaseGlowView statusPhaseGlow;
    private FxGlowDrawable statusGlow;
    private boolean submissionEnabled;

    AuthorizationScreen(Context context, MobileAppActions actions) {
        this.context = context;
        this.actions = actions;
        root = VisionForgeTheme.scrollPage(context);
        root.setContentDescription(UiAutomationIds.SCROLL_AUTHORIZATION);
        root.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_YES);
        LinearLayout page = VisionForgeTheme.pageBody(context);
        root.addView(page);

        statusCard = VisionForgeTheme.card(context);
        statusGlow = new FxGlowDrawable(
                context, VisionForgeTheme.SURFACE, VisionForgeTheme.WARNING, 12, 1);
        statusCard.setBackground(statusGlow);
        LinearLayout statusRow = new LinearLayout(context);
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        statusIcon = VisionForgeTheme.icon(
                context, MaterialIcons.LOCK, 28, VisionForgeTheme.WARNING);
        // Same aurora idiom as the link hero: semantic phase glow behind the
        // status icon; decorative, accessibility-muted, bounded cross-fades.
        statusPhaseGlow = new FxPhaseGlowView(context);
        android.widget.FrameLayout iconFrame = new android.widget.FrameLayout(context);
        iconFrame.addView(statusPhaseGlow, new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT));
        iconFrame.addView(statusIcon, new android.widget.FrameLayout.LayoutParams(
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT,
                android.widget.FrameLayout.LayoutParams.MATCH_PARENT));
        statusRow.addView(iconFrame,
                VisionForgeTheme.fixed(context, 52, 52, 12));
        LinearLayout copy = new LinearLayout(context);
        copy.setOrientation(LinearLayout.VERTICAL);
        statusTitle = VisionForgeTheme.text(
                context, "", 17, VisionForgeTheme.TEXT);
        VisionForgeTheme.heading(statusTitle);
        statusDetail = VisionForgeTheme.text(
                context, "", 13, VisionForgeTheme.TEXT_MUTED);
        statusDetail.setPadding(0, VisionForgeTheme.dp(context, 4), 0, 0);
        copy.addView(statusTitle);
        copy.addView(statusDetail);
        statusRow.addView(copy, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        statusCard.addView(statusRow);
        page.addView(statusCard, VisionForgeTheme.match(context, 4));

        LinearLayout balanceCard = VisionForgeTheme.card(context);
        remaining = metricValue(
                balanceCard, R.string.section_authorization_balance);
        page.addView(balanceCard);

        activationLabel = VisionForgeTheme.sectionLabel(
                context, R.string.section_card_activation);
        page.addView(activationLabel);
        activationCard = VisionForgeTheme.card(context);
        cardCode = new EditText(context);
        cardCode.setHint(R.string.authorization_card_hint);
        cardCode.setSingleLine(true);
        cardCode.setTextColor(VisionForgeTheme.TEXT);
        cardCode.setHintTextColor(VisionForgeTheme.TEXT_MUTED);
        cardCode.setTextSize(15);
        cardCode.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
                | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        cardCode.setTransformationMethod(
                PasswordTransformationMethod.getInstance());
        cardCode.setFilters(new InputFilter[]{new InputFilter.LengthFilter(96)});
        cardCode.setSaveEnabled(false);
        cardCode.setImportantForAutofill(
                View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        cardCode.setImeOptions(EditorInfo.IME_ACTION_DONE);
        cardCode.setContentDescription(UiAutomationIds.CARD_CODE_INPUT);
        cardCode.setBackground(VisionForgeTheme.rounded(
                context, VisionForgeTheme.SURFACE_RAISED, 10,
                VisionForgeTheme.OUTLINE, 1));
        cardCode.setPadding(
                VisionForgeTheme.dp(context, 14),
                VisionForgeTheme.dp(context, 12),
                VisionForgeTheme.dp(context, 14),
                VisionForgeTheme.dp(context, 12));
        cardCode.setOnEditorActionListener((view, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                submitCard();
                return true;
            }
            return false;
        });
        activationCard.addView(cardCode);

        activate = VisionForgeTheme.primaryButton(
                context, R.string.action_activate_card);
        activate.setContentDescription(UiAutomationIds.CARD_ACTIVATE);
        activate.setOnClickListener(view -> submitCard());
        activationCard.addView(activate, VisionForgeTheme.match(context, 10));

        resumeActivation = VisionForgeTheme.secondaryButton(
                context, R.string.action_resume_activation);
        resumeActivation.setOnClickListener(
                view -> actions.onResumePendingActivation());
        activationCard.addView(
                resumeActivation, VisionForgeTheme.match(context, 8));

        TextView zeroCost = VisionForgeTheme.text(
                context,
                context.getString(R.string.authorization_zero_cost_notice),
                12,
                VisionForgeTheme.TEXT_MUTED);
        zeroCost.setPadding(0, VisionForgeTheme.dp(context, 10), 0, 0);
        activationCard.addView(zeroCost);
        page.addView(activationCard);
    }

    private TextView metricValue(LinearLayout card, int labelResource) {
        LinearLayout row = new LinearLayout(context);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        TextView label = VisionForgeTheme.text(
                context, context.getString(labelResource),
                14, VisionForgeTheme.TEXT_MUTED);
        TextView value = VisionForgeTheme.text(
                context, "--", 18, VisionForgeTheme.TEXT);
        value.setTypeface(Typeface.DEFAULT_BOLD);
        value.setGravity(Gravity.END | Gravity.CENTER_VERTICAL);
        row.addView(label, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        row.addView(value, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        card.addView(row, card.getChildCount() == 0
                ? new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT)
                : VisionForgeTheme.match(context, 12));
        return value;
    }

    private void submitCard() {
        if (!submissionEnabled) return;
        String raw = cardCode.getText().toString();
        cardCode.getText().clear();
        final String normalized;
        try {
            normalized = DualMachineCardCode.normalizeAndValidate(raw);
            cardCode.setError(null);
        } catch (IllegalArgumentException invalid) {
            cardCode.setError(context.getString(
                    R.string.authorization_card_invalid));
            return;
        }
        actions.onActivateCard(normalized);
    }

    @Override
    public View view() {
        return root;
    }

    @Override
    public void render(MobileUiState state) {
        DualMachineAuthorizationUiState authorization =
                state.authorization;
        int titleResource;
        int detailResource;
        int color;
        String glyph;
        switch (authorization.status) {
            case READY_FOR_ACTIVATION:
                titleResource = R.string.authorization_ready;
                detailResource = R.string.authorization_ready_detail;
                color = VisionForgeTheme.ACCENT;
                glyph = MaterialIcons.KEY;
                break;
            case ACTIVATING:
                titleResource = R.string.authorization_activating;
                detailResource = R.string.authorization_activating_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.REFRESH;
                break;
            case ACTIVATION_PENDING:
                titleResource = R.string.authorization_activation_pending;
                detailResource =
                        R.string.authorization_activation_pending_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.WARNING;
                break;
            case ACTIVE_IDLE:
                titleResource = R.string.authorization_active_idle;
                detailResource = R.string.authorization_active_idle_detail;
                color = VisionForgeTheme.ACCENT;
                glyph = MaterialIcons.CHECK;
                break;
            case REFRESHING:
                titleResource = R.string.authorization_refreshing;
                detailResource = R.string.authorization_refreshing_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.REFRESH;
                break;
            case STARTING:
                titleResource = R.string.authorization_starting;
                detailResource = R.string.authorization_starting_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.REFRESH;
                break;
            case IN_USE:
                titleResource = R.string.authorization_in_use;
                detailResource = R.string.authorization_in_use_detail;
                color = VisionForgeTheme.ACCENT;
                glyph = MaterialIcons.PLAY;
                break;
            case STOPPING:
                titleResource = R.string.authorization_stopping;
                detailResource = R.string.authorization_stopping_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.STOP;
                break;
            case EXHAUSTED:
                titleResource = R.string.authorization_exhausted;
                detailResource = R.string.authorization_exhausted_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.WARNING;
                break;
            case REVOKED:
                titleResource = R.string.authorization_revoked;
                detailResource = R.string.authorization_revoked_detail;
                color = VisionForgeTheme.DANGER;
                glyph = MaterialIcons.LOCK;
                break;
            case ERROR:
                titleResource = R.string.authorization_error;
                detailResource = R.string.authorization_error_detail;
                color = VisionForgeTheme.DANGER;
                glyph = MaterialIcons.WARNING;
                break;
            default:
                titleResource = R.string.authorization_ready;
                detailResource = R.string.authorization_ready_detail;
                color = VisionForgeTheme.WARNING;
                glyph = MaterialIcons.KEY;
                break;
        }
        VisionForgeTheme.setTextIfChanged(
                statusTitle, context.getString(titleResource));
        String detail = authorization.detail.isEmpty()
                ? context.getString(detailResource) : authorization.detail;
        VisionForgeTheme.setTextIfChanged(statusDetail, detail);
        VisionForgeTheme.setTextIfChanged(statusIcon, glyph);
        statusIcon.setTextColor(color);
        statusPhaseGlow.setPhase(color);
        if (statusGlow == null) {
            statusGlow = new FxGlowDrawable(context, VisionForgeTheme.SURFACE, color, 12, 1);
            statusCard.setBackground(statusGlow);
        } else {
            statusGlow.retarget(VisionForgeTheme.SURFACE, color);
        }
        VisionForgeTheme.setTextIfChanged(remaining,
                formatBalance(authorization));

        submissionEnabled = authorization.canActivateCard();
        boolean activationVisible = authorization.isActivationCardVisible();
        activationLabel.setVisibility(
                activationVisible ? View.VISIBLE : View.GONE);
        activationCard.setVisibility(
                activationVisible ? View.VISIBLE : View.GONE);
        cardCode.setEnabled(submissionEnabled);
        activate.setEnabled(submissionEnabled);
        VisionForgeTheme.setTextIfChanged(activate,
                context.getString(R.string.action_activate_card));
        resumeActivation.setVisibility(
                authorization.status
                        == DualMachineAuthorizationUiState.Status
                        .ACTIVATION_PENDING
                        ? View.VISIBLE : View.GONE);
        resumeActivation.setEnabled(authorization.canResumeActivation());
    }

    private String formatBalance(
            DualMachineAuthorizationUiState authorization) {
        if (authorization.permanent) {
            return context.getString(
                    R.string.authorization_permanent_balance);
        }
        if (!authorization.balanceKnown) {
            return context.getString(
                    R.string.authorization_balance_pending);
        }
        return formatDuration(authorization.remainingSeconds);
    }

    private static String formatDuration(long totalSeconds) {
        long hours = totalSeconds / 3_600L;
        long minutes = (totalSeconds % 3_600L) / 60L;
        long seconds = totalSeconds % 60L;
        if (hours > 0L) {
            return String.format(
                    Locale.CHINA, "%d 小时 %02d 分 %02d 秒",
                    hours, minutes, seconds);
        }
        return String.format(
                Locale.CHINA, "%d 分 %02d 秒", minutes, seconds);
    }
}
