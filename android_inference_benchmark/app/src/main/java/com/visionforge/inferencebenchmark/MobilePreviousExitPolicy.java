package com.visionforge.inferencebenchmark;

/** Pure classification for Android historical process-exit evidence. */
final class MobilePreviousExitPolicy {
    static final int REASON_LOW_MEMORY = 3;
    static final int REASON_CRASH = 4;
    static final int REASON_CRASH_NATIVE = 5;
    static final int REASON_ANR = 6;
    static final int REASON_USER_REQUESTED = 10;
    static final int REASON_USER_STOPPED = 11;

    enum Kind {
        NONE,
        TASK_CLEANED,
        USER_STOPPED,
        LOW_MEMORY,
        CRASH,
        ANR,
        OTHER
    }

    private MobilePreviousExitPolicy() {}

    static Kind classify(int reason, String description) {
        if (reason == REASON_USER_REQUESTED
                && normalized(description).contains("swipeupclean")) {
            return Kind.TASK_CLEANED;
        }
        if (reason == REASON_USER_REQUESTED
                || reason == REASON_USER_STOPPED) {
            return Kind.USER_STOPPED;
        }
        if (reason == REASON_LOW_MEMORY) return Kind.LOW_MEMORY;
        if (reason == REASON_CRASH || reason == REASON_CRASH_NATIVE) {
            return Kind.CRASH;
        }
        if (reason == REASON_ANR) return Kind.ANR;
        return reason <= 0 ? Kind.NONE : Kind.OTHER;
    }

    private static String normalized(String value) {
        return value == null
                ? ""
                : value.replace(" ", "")
                        .replace("_", "")
                        .toLowerCase(java.util.Locale.ROOT);
    }
}
