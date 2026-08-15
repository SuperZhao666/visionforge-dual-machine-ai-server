package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Dependency-free MAKCU serial connection state machine.
 *
 * <p>A successful result always leaves the supplied port open at 4 Mbaud.
 * Every failure closes it. No movement command is sent during negotiation.</p>
 */
final class MakcuProtocolNegotiator {
    static final int DEFAULT_BAUD_RATE = 115_200;
    static final int OPERATING_BAUD_RATE = 4_000_000;
    static final byte[] VERSION_QUERY =
            "km.version()\r\n".getBytes(StandardCharsets.US_ASCII);
    static final byte[] BAUD_CHANGE_FRAME = {
            (byte) 0xDE, (byte) 0xAD, 0x05, 0x00, (byte) 0xA5,
            0x00, 0x09, 0x3D, 0x00
    };

    private static final String RESPONSE_PROMPT = ">>> ";
    private static final int WRITE_TIMEOUT_MILLIS = 500;
    private static final int RESPONSE_READ_TIMEOUT_MILLIS = 50;
    private static final int RESPONSE_READ_ATTEMPTS = 10;
    private static final int DRAIN_READ_TIMEOUT_MILLIS = 10;
    private static final int DRAIN_READ_ATTEMPTS = 16;
    private static final int MAXIMUM_RESPONSE_BYTES = 1_024;
    private static final long BAUD_CHANGE_SETTLE_MILLIS = 100L;
    private static final long OPERATING_REOPEN_SETTLE_MILLIS = 50L;

    interface Port {
        boolean open(int baudRate);
        int write(byte[] bytes, int timeoutMillis);
        int read(byte[] destination, int timeoutMillis);
        void close();
    }

    interface Sleeper {
        void sleep(long millis);
    }

    interface Cancellation {
        boolean isCancelled();
    }

    static final class Result {
        final boolean succeeded;
        final String stage;

        private Result(boolean succeeded, String stage) {
            this.succeeded = succeeded;
            this.stage = stage;
        }
    }

    private final Sleeper sleeper;

    MakcuProtocolNegotiator(Sleeper sleeper) {
        this.sleeper = sleeper;
    }

    Result negotiate(Port port) {
        return negotiate(port, () -> false);
    }

    Result negotiate(Port port, Cancellation cancellation) {
        if (cancellation.isCancelled()) return fail(port, "cancelled");
        if (port.open(OPERATING_BAUD_RATE)
                && !cancellation.isCancelled()
                && verifyVersion(port, cancellation)) {
            return new Result(true, "existing_4mbaud_verified");
        }
        port.close();
        if (cancellation.isCancelled()) return fail(port, "cancelled");
        if (!switchFromDefaultBaud(port, cancellation)) {
            return fail(port, cancellation.isCancelled() ? "cancelled" : "baud_switch_failed");
        }
        if (cancellation.isCancelled()) return fail(port, "cancelled");
        if (!port.open(OPERATING_BAUD_RATE)) return fail(port, "4mbaud_reopen_failed");
        if (cancellation.isCancelled()) return fail(port, "cancelled");
        sleeper.sleep(OPERATING_REOPEN_SETTLE_MILLIS);
        if (cancellation.isCancelled()) return fail(port, "cancelled");
        if (!verifyVersion(port, cancellation)) {
            return fail(port, cancellation.isCancelled()
                    ? "cancelled" : "post_switch_identity_failed");
        }
        return new Result(true, "baud_switched_and_verified");
    }

    private boolean switchFromDefaultBaud(Port port, Cancellation cancellation) {
        if (cancellation.isCancelled()) return false;
        if (!port.open(DEFAULT_BAUD_RATE)) return false;
        if (cancellation.isCancelled() || !drainUntilQuiet(port, cancellation)) return false;
        if (port.write(BAUD_CHANGE_FRAME, WRITE_TIMEOUT_MILLIS)
                != BAUD_CHANGE_FRAME.length) return false;
        if (cancellation.isCancelled()) return false;
        sleeper.sleep(BAUD_CHANGE_SETTLE_MILLIS);
        if (cancellation.isCancelled()) return false;
        port.close();
        return true;
    }

    private boolean verifyVersion(Port port, Cancellation cancellation) {
        if (!drainUntilQuiet(port, cancellation) || cancellation.isCancelled()) return false;
        if (port.write(VERSION_QUERY, WRITE_TIMEOUT_MILLIS) != VERSION_QUERY.length) return false;
        if (cancellation.isCancelled()) return false;
        return MakcuDeviceIdentityPolicy.isVerifiedProtocolResponse(
                readResponseFrame(port, cancellation));
    }

    private static boolean drainUntilQuiet(Port port, Cancellation cancellation) {
        byte[] buffer = new byte[256];
        int drainedBytes = 0;
        for (int attempt = 0; attempt < DRAIN_READ_ATTEMPTS; attempt++) {
            if (cancellation.isCancelled()) return false;
            int read = port.read(buffer, DRAIN_READ_TIMEOUT_MILLIS);
            if (cancellation.isCancelled()) return false;
            if (read <= 0) return true;
            drainedBytes += read;
            if (drainedBytes > MAXIMUM_RESPONSE_BYTES) return false;
        }
        return false;
    }

    private static String readResponseFrame(Port port, Cancellation cancellation) {
        byte[] buffer = new byte[256];
        byte[] accumulated = new byte[0];
        for (int attempt = 0; attempt < RESPONSE_READ_ATTEMPTS; attempt++) {
            if (cancellation.isCancelled()) return "";
            int read = port.read(buffer, RESPONSE_READ_TIMEOUT_MILLIS);
            if (cancellation.isCancelled()) return "";
            if (read <= 0) continue;
            accumulated = append(accumulated, buffer, read);
            if (accumulated.length > MAXIMUM_RESPONSE_BYTES) return "";
            String response = new String(accumulated, StandardCharsets.US_ASCII);
            int promptEnd = response.indexOf(RESPONSE_PROMPT);
            if (promptEnd >= 0) return response.substring(0, promptEnd + RESPONSE_PROMPT.length());
        }
        return "";
    }

    private static byte[] append(byte[] existing, byte[] source, int count) {
        byte[] appended = Arrays.copyOf(existing, existing.length + count);
        System.arraycopy(source, 0, appended, existing.length, count);
        return appended;
    }

    private static Result fail(Port port, String stage) {
        port.close();
        return new Result(false, stage);
    }
}
