package com.visionforge.inferencebenchmark;

import java.io.PrintWriter;
import java.io.StringWriter;

/** Converts a Java failure and its complete cause chain into durable diagnostic text. */
final class MobileThrowableDiagnostics {
    private MobileThrowableDiagnostics() {
    }

    static String format(Throwable failure) {
        if (failure == null) return "throwable_unavailable";
        StringWriter text = new StringWriter();
        try (PrintWriter writer = new PrintWriter(text)) {
            failure.printStackTrace(writer);
        }
        return text.toString();
    }
}
