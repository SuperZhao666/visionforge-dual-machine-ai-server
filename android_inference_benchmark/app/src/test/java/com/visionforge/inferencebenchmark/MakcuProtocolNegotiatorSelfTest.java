package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;

/** Dependency-free regression contract for the documented MAKCU baud handshake. */
final class MakcuProtocolNegotiatorSelfTest {
    static void run() {
        verifiesAlreadyConfiguredDevice();
        verifiesDefaultBaudSwitchSequence();
        rejectsEchoAndClosesPort();
        rejectsStaleMoveResponseBeforeIdentity();
        cancellationStopsFurtherHardwareAccess();
    }

    private static void verifiesAlreadyConfiguredDevice() {
        FakePort port = new FakePort(true);
        FakeSleeper sleeper = new FakeSleeper();
        MakcuProtocolNegotiator.Result result = negotiator(sleeper).negotiate(port);
        require(result.succeeded);
        require("existing_4mbaud_verified".equals(result.stage));
        require(port.openBauds.equals(List.of(4_000_000)));
        require(port.isOpen);
        require(port.writes.size() == 1);
        require(Arrays.equals(port.writes.get(0), MakcuProtocolNegotiator.VERSION_QUERY));
        require(sleeper.delays.isEmpty());
    }

    private static void verifiesDefaultBaudSwitchSequence() {
        FakePort port = new FakePort(false);
        FakeSleeper sleeper = new FakeSleeper();
        MakcuProtocolNegotiator.Result result = negotiator(sleeper).negotiate(port);
        require(result.succeeded);
        require("baud_switched_and_verified".equals(result.stage));
        require(port.openBauds.equals(List.of(4_000_000, 115_200, 4_000_000)));
        require(port.writes.size() == 3);
        require(Arrays.equals(port.writes.get(1), MakcuProtocolNegotiator.BAUD_CHANGE_FRAME));
        require(Arrays.equals(port.writes.get(2), MakcuProtocolNegotiator.VERSION_QUERY));
        require(sleeper.delays.equals(List.of(100L, 50L)));
        require(port.isOpen);
    }

    private static void rejectsEchoAndClosesPort() {
        FakePort port = new FakePort(true);
        port.identityResponse = "km.version()\r\n>>> ";
        MakcuProtocolNegotiator.Result result = negotiator(millis -> { }).negotiate(port);
        require(!result.succeeded);
        require(!port.isOpen);
    }

    private static void rejectsStaleMoveResponseBeforeIdentity() {
        FakePort port = new FakePort(true);
        port.staleReads.add("km.move(1,2)\r\n>>> ".getBytes(StandardCharsets.US_ASCII));
        MakcuProtocolNegotiator.Result result = negotiator(millis -> { }).negotiate(port);
        require(result.succeeded);
        require(port.isOpen);
    }

    private static void cancellationStopsFurtherHardwareAccess() {
        FakePort port = new FakePort(true);
        boolean[] cancelled = {false};
        port.onRead = () -> cancelled[0] = true;
        MakcuProtocolNegotiator.Result result = negotiator(millis -> { })
                .negotiate(port, () -> cancelled[0]);
        require(!result.succeeded);
        require("cancelled".equals(result.stage));
        require(port.writes.isEmpty());
        require(!port.isOpen);
        require(port.openBauds.equals(List.of(4_000_000)));
    }

    private static MakcuProtocolNegotiator negotiator(MakcuProtocolNegotiator.Sleeper sleeper) {
        return new MakcuProtocolNegotiator(sleeper);
    }

    private static final class FakeSleeper implements MakcuProtocolNegotiator.Sleeper {
        final List<Long> delays = new ArrayList<>();
        @Override public void sleep(long millis) { delays.add(millis); }
    }

    private static final class FakePort implements MakcuProtocolNegotiator.Port {
        final List<Integer> openBauds = new ArrayList<>();
        final List<byte[]> writes = new ArrayList<>();
        final Deque<byte[]> staleReads = new ArrayDeque<>();
        final boolean respondsAtInitialOperatingBaud;
        boolean isOpen;
        boolean switched;
        int currentBaud;
        String identityResponse = "km.MAKCU\r\n>>> ";
        byte[] pendingResponse;
        Runnable onRead;

        FakePort(boolean respondsAtInitialOperatingBaud) {
            this.respondsAtInitialOperatingBaud = respondsAtInitialOperatingBaud;
        }

        @Override public boolean open(int baudRate) {
            close();
            currentBaud = baudRate;
            openBauds.add(baudRate);
            isOpen = true;
            return true;
        }

        @Override public int write(byte[] bytes, int timeoutMillis) {
            writes.add(Arrays.copyOf(bytes, bytes.length));
            if (Arrays.equals(bytes, MakcuProtocolNegotiator.BAUD_CHANGE_FRAME)
                    && currentBaud == MakcuProtocolNegotiator.DEFAULT_BAUD_RATE) {
                switched = true;
            } else if (Arrays.equals(bytes, MakcuProtocolNegotiator.VERSION_QUERY)
                    && currentBaud == MakcuProtocolNegotiator.OPERATING_BAUD_RATE
                    && (respondsAtInitialOperatingBaud || switched)) {
                pendingResponse = identityResponse.getBytes(StandardCharsets.US_ASCII);
            }
            return bytes.length;
        }

        @Override public int read(byte[] destination, int timeoutMillis) {
            if (onRead != null) {
                Runnable callback = onRead;
                onRead = null;
                callback.run();
            }
            byte[] response = !staleReads.isEmpty() ? staleReads.removeFirst() : pendingResponse;
            pendingResponse = null;
            if (response == null) return 0;
            System.arraycopy(response, 0, destination, 0, response.length);
            return response.length;
        }

        @Override public void close() {
            isOpen = false;
            currentBaud = 0;
            pendingResponse = null;
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU protocol negotiation contract failed");
    }
}
