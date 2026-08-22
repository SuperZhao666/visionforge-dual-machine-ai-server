package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;

/** Fail-closed owner for the exact nine-message pre-VFC1 exchange. */
public final class ControlBootstrapSequenceV1 {
    public enum Role {
        HOST,
        ANDROID
    }

    public enum Flow {
        OUTBOUND,
        INBOUND
    }

    public enum Phase {
        IN_PROGRESS,
        COMPLETED,
        ABORTED,
        FAILED
    }

    public enum AdvanceStatus {
        ADVANCED,
        COMPLETED,
        ABORTED,
        UNEXPECTED_MESSAGE,
        WRONG_FLOW,
        ALREADY_TERMINAL
    }

    public static final class ExpectedEvent {
        private final Flow flow;
        private final MessageType messageType;

        private ExpectedEvent(Flow flow, MessageType messageType) {
            this.flow = flow;
            this.messageType = messageType;
        }

        public Flow flow() {
            return flow;
        }

        public MessageType messageType() {
            return messageType;
        }
    }

    private static final MessageType[] MESSAGE_SEQUENCE = new MessageType[] {
            MessageType.HOST_HELLO,
            MessageType.ANDROID_CHALLENGE_REQUEST,
            MessageType.HOST_CHALLENGE_PROOF,
            MessageType.SERVER_CHALLENGE,
            MessageType.HOST_FINAL_PROOF,
            MessageType.PAIR_GENERATION_CREDENTIAL,
            MessageType.HOST_HANDSHAKE_SIGNATURE,
            MessageType.ANDROID_HANDSHAKE_CONFIRMATION,
            MessageType.HOST_FINISHED
    };

    private final Role localRole;
    private Phase phase;
    private int nextEventIndex;

    public ControlBootstrapSequenceV1(Role localRole) {
        this.localRole = localRole;
        phase = localRole == null ? Phase.FAILED : Phase.IN_PROGRESS;
    }

    public synchronized AdvanceStatus advanceOutbound(MessageType messageType) {
        return advance(Flow.OUTBOUND, messageType);
    }

    public synchronized AdvanceStatus advanceInbound(MessageType messageType) {
        return advance(Flow.INBOUND, messageType);
    }

    public synchronized ExpectedEvent expectedNext() {
        if (phase != Phase.IN_PROGRESS
                || nextEventIndex >= MESSAGE_SEQUENCE.length) {
            return null;
        }
        return new ExpectedEvent(
                expectedFlow(nextEventIndex),
                MESSAGE_SEQUENCE[nextEventIndex]);
    }

    public synchronized Phase phase() {
        return phase;
    }

    public synchronized int acceptedEventCount() {
        return nextEventIndex;
    }

    private AdvanceStatus advance(Flow flow, MessageType messageType) {
        if (phase != Phase.IN_PROGRESS) {
            return AdvanceStatus.ALREADY_TERMINAL;
        }
        if (flow != null && messageType == MessageType.ABORT) {
            phase = Phase.ABORTED;
            return AdvanceStatus.ABORTED;
        }
        ExpectedEvent expected = expectedNext();
        if (expected == null || flow != expected.flow()) {
            phase = Phase.FAILED;
            return AdvanceStatus.WRONG_FLOW;
        }
        if (messageType != expected.messageType()) {
            phase = Phase.FAILED;
            return AdvanceStatus.UNEXPECTED_MESSAGE;
        }
        nextEventIndex++;
        if (nextEventIndex == MESSAGE_SEQUENCE.length) {
            phase = Phase.COMPLETED;
            return AdvanceStatus.COMPLETED;
        }
        return AdvanceStatus.ADVANCED;
    }

    private Flow expectedFlow(int eventIndex) {
        boolean hostSends = (eventIndex & 1) == 0;
        boolean localSends = (localRole == Role.HOST) == hostSends;
        return localSends ? Flow.OUTBOUND : Flow.INBOUND;
    }
}
