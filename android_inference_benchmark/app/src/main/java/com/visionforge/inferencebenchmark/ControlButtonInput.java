package com.visionforge.inferencebenchmark;

/** Read-only complete physical mouse button state used by control triggers. */
interface ControlButtonInput {
    interface Listener {
        void onButtonMaskChanged(int completeButtonMask);
    }

    void setButtonStateListener(Listener listener);

    void setRequiredTriggerMask(int requiredButtonMask);

    int currentButtonMask();

    boolean isButtonStreamReady();
}
