package com.visionforge.inferencebenchmark;

/** Physical activation source observed through the MAKCU button stream. */
public enum ControlTrigger {
    ALWAYS("always", 0),
    RIGHT_MOUSE("mouse2", 0x02),
    SIDE_BUTTON_1("mouse4", 0x08),
    SIDE_BUTTON_2("mouse5", 0x10);

    public final String storageToken;
    public final int buttonMask;

    ControlTrigger(String storageToken, int buttonMask) {
        this.storageToken = storageToken;
        this.buttonMask = buttonMask;
    }

    public boolean requiresButtonStream() {
        return buttonMask != 0;
    }

    public boolean isSatisfiedBy(int currentButtonMask) {
        return !requiresButtonStream() || (currentButtonMask & buttonMask) != 0;
    }

    static ControlTrigger fromStorageToken(String token) {
        if (token != null) {
            for (ControlTrigger trigger : values()) {
                if (trigger.storageToken.equalsIgnoreCase(token.trim())) return trigger;
            }
        }
        // A missing or corrupted persisted value must never silently turn
        // automatic movement into an unconditionally active output path.
        return SIDE_BUTTON_2;
    }

    /** Restores an explicit persisted choice while keeping invalid data safe. */
    static ControlTrigger fromPersistedStorageToken(String token) {
        return fromStorageToken(token);
    }

    static boolean persistedTokenNeedsMigration(String token) {
        return token == null
                || !fromPersistedStorageToken(token).storageToken.equals(token.trim());
    }
}
