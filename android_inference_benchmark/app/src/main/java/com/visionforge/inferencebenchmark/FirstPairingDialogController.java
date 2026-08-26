package com.visionforge.inferencebenchmark;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Typeface;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.visionforge.inferencebenchmark.runtime.FirstPairingUiState;

/** Owns the short-lived, two-sided first-pairing confirmation dialog. */
final class FirstPairingDialogController {
    @FunctionalInterface
    interface DecisionHandler {
        void submit(boolean matchingCodes);
    }

    private final Activity activity;
    private final DecisionHandler decisionHandler;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final Runnable countdownTask = new Runnable() {
        @Override
        public void run() {
            updateCountdown();
            if (dialog != null && dialog.isShowing()) {
                uiHandler.postDelayed(this, 1_000L);
            }
        }
    };

    private FirstPairingUiState state = FirstPairingUiState.none();
    private AlertDialog dialog;
    private TextView countdown;

    FirstPairingDialogController(
            Activity activity,
            DecisionHandler decisionHandler) {
        this.activity = activity;
        this.decisionHandler = decisionHandler;
    }

    void render(boolean activityStarted, FirstPairingUiState next) {
        state = next == null ? FirstPairingUiState.none() : next;
        if (!activityStarted || !state.pending) {
            dismiss();
            return;
        }
        if (dialog != null && dialog.isShowing()) {
            updateCountdown();
            return;
        }

        LinearLayout content = new LinearLayout(activity);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(24f * activity.getResources()
                .getDisplayMetrics().density);
        content.setPadding(padding, padding / 2, padding, 0);

        TextView instruction = new TextView(activity);
        instruction.setText(R.string.first_pairing_dialog_instruction);
        instruction.setTextSize(16f);
        content.addView(instruction);

        TextView sas = new TextView(activity);
        sas.setText(state.decimalSas);
        sas.setTextSize(36f);
        sas.setTypeface(Typeface.DEFAULT_BOLD);
        sas.setGravity(Gravity.CENTER);
        sas.setLetterSpacing(0.12f);
        sas.setContentDescription(activity.getString(
                R.string.first_pairing_dialog_code_description,
                state.decimalSas));
        LinearLayout.LayoutParams sasLayout = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        sasLayout.topMargin = padding / 2;
        sasLayout.bottomMargin = padding / 2;
        content.addView(sas, sasLayout);

        TextView host = new TextView(activity);
        host.setText(activity.getString(
                R.string.first_pairing_dialog_host,
                state.hostIpv4));
        host.setTextSize(15f);
        content.addView(host);

        countdown = new TextView(activity);
        countdown.setTextSize(14f);
        content.addView(countdown);

        dialog = new AlertDialog.Builder(activity)
                .setTitle(R.string.first_pairing_notification_title)
                .setView(content)
                .setNegativeButton(
                        R.string.first_pairing_action_reject,
                        (ignoredDialog, ignoredWhich) ->
                                decisionHandler.submit(false))
                .setPositiveButton(
                        R.string.first_pairing_action_confirm,
                        (ignoredDialog, ignoredWhich) ->
                                decisionHandler.submit(true))
                .create();
        dialog.setCancelable(false);
        dialog.setOnDismissListener(ignored -> {
            uiHandler.removeCallbacks(countdownTask);
            dialog = null;
            countdown = null;
        });
        dialog.show();
        uiHandler.removeCallbacks(countdownTask);
        uiHandler.post(countdownTask);
    }

    void dismiss() {
        uiHandler.removeCallbacks(countdownTask);
        AlertDialog active = dialog;
        if (active != null) active.dismiss();
    }

    private void updateCountdown() {
        if (countdown == null) return;
        long remaining = state.remainingSeconds(
                System.currentTimeMillis() / 1_000L);
        countdown.setText(activity.getString(
                R.string.first_pairing_dialog_countdown,
                remaining));
    }
}
