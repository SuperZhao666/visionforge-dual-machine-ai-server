package com.visionforge.inferencebenchmark.handshake;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedControlBootstrapRecordV1.MessageType;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1.AdvanceStatus;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1.ExpectedEvent;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1.Flow;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1.Phase;
import com.visionforge.inferencebenchmark.handshake.ControlBootstrapSequenceV1.Role;

/** Dependency-free mirror of the C++ pre-VFC1 order state machine. */
public final class ControlBootstrapSequenceV1SelfTest {
    private static final MessageType[] SEQUENCE = new MessageType[] {
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

    private ControlBootstrapSequenceV1SelfTest() {}

    public static void main(String[] arguments) {
        completesTheSameExactHostAndAndroidSequence();
        rejectsWrongFlowSkippedAndRepeatedMessages();
        makesAbortAndCompletionTerminal();
        System.out.println("ControlBootstrapSequenceV1SelfTest: PASS");
    }

    private static void completesTheSameExactHostAndAndroidSequence() {
        ControlBootstrapSequenceV1 host =
                new ControlBootstrapSequenceV1(Role.HOST);
        ControlBootstrapSequenceV1 android =
                new ControlBootstrapSequenceV1(Role.ANDROID);
        for (int index = 0; index < SEQUENCE.length; index++) {
            boolean hostSends = (index & 1) == 0;
            ExpectedEvent hostExpected = host.expectedNext();
            ExpectedEvent androidExpected = android.expectedNext();
            require(hostExpected != null, "Host expected event");
            require(androidExpected != null, "Android expected event");
            require(hostExpected.messageType() == SEQUENCE[index], "Host type");
            require(androidExpected.messageType() == SEQUENCE[index], "Android type");
            require(
                    hostExpected.flow() == (hostSends ? Flow.OUTBOUND : Flow.INBOUND),
                    "Host flow");
            require(
                    androidExpected.flow() == (hostSends ? Flow.INBOUND : Flow.OUTBOUND),
                    "Android flow");
            AdvanceStatus expected = index + 1 == SEQUENCE.length
                    ? AdvanceStatus.COMPLETED
                    : AdvanceStatus.ADVANCED;
            require((hostSends
                    ? host.advanceOutbound(SEQUENCE[index])
                    : host.advanceInbound(SEQUENCE[index])) == expected, "Host advance");
            require((hostSends
                    ? android.advanceInbound(SEQUENCE[index])
                    : android.advanceOutbound(SEQUENCE[index])) == expected,
                    "Android advance");
            require(host.acceptedEventCount() == index + 1, "Host count");
            require(android.acceptedEventCount() == index + 1, "Android count");
        }
        require(host.phase() == Phase.COMPLETED, "Host complete");
        require(android.phase() == Phase.COMPLETED, "Android complete");
        require(host.expectedNext() == null, "No event after complete");
    }

    private static void rejectsWrongFlowSkippedAndRepeatedMessages() {
        ControlBootstrapSequenceV1 wrongFlow =
                new ControlBootstrapSequenceV1(Role.HOST);
        require(wrongFlow.advanceInbound(MessageType.HOST_HELLO)
                == AdvanceStatus.WRONG_FLOW, "wrong flow");
        require(wrongFlow.phase() == Phase.FAILED, "wrong flow burns owner");
        require(wrongFlow.advanceOutbound(MessageType.HOST_HELLO)
                == AdvanceStatus.ALREADY_TERMINAL, "failed owner terminal");

        ControlBootstrapSequenceV1 skipped =
                new ControlBootstrapSequenceV1(Role.HOST);
        require(skipped.advanceOutbound(MessageType.HOST_FINAL_PROOF)
                == AdvanceStatus.UNEXPECTED_MESSAGE, "skip rejected");
        require(skipped.phase() == Phase.FAILED, "skip burns owner");

        ControlBootstrapSequenceV1 repeated =
                new ControlBootstrapSequenceV1(Role.HOST);
        require(repeated.advanceOutbound(MessageType.HOST_HELLO)
                == AdvanceStatus.ADVANCED, "first hello");
        require(repeated.advanceOutbound(MessageType.HOST_HELLO)
                == AdvanceStatus.WRONG_FLOW, "repeat rejected");
        require(repeated.phase() == Phase.FAILED, "repeat burns owner");

        ControlBootstrapSequenceV1 invalid = new ControlBootstrapSequenceV1(null);
        require(invalid.phase() == Phase.FAILED, "null role failed");
        require(invalid.advanceOutbound(MessageType.ABORT)
                == AdvanceStatus.ALREADY_TERMINAL, "invalid owner terminal");
    }

    private static void makesAbortAndCompletionTerminal() {
        ControlBootstrapSequenceV1 localAbort =
                new ControlBootstrapSequenceV1(Role.HOST);
        require(localAbort.advanceOutbound(MessageType.ABORT)
                == AdvanceStatus.ABORTED, "local abort");
        require(localAbort.phase() == Phase.ABORTED, "local abort phase");
        require(localAbort.advanceInbound(MessageType.ABORT)
                == AdvanceStatus.ALREADY_TERMINAL, "abort terminal");

        ControlBootstrapSequenceV1 peerAbort =
                new ControlBootstrapSequenceV1(Role.ANDROID);
        require(peerAbort.advanceInbound(MessageType.ABORT)
                == AdvanceStatus.ABORTED, "peer abort");
        require(peerAbort.phase() == Phase.ABORTED, "peer abort phase");

        ControlBootstrapSequenceV1 completed =
                new ControlBootstrapSequenceV1(Role.HOST);
        for (int index = 0; index < SEQUENCE.length; index++) {
            boolean hostSends = (index & 1) == 0;
            if (hostSends) {
                completed.advanceOutbound(SEQUENCE[index]);
            } else {
                completed.advanceInbound(SEQUENCE[index]);
            }
        }
        require(completed.advanceOutbound(MessageType.ABORT)
                == AdvanceStatus.ALREADY_TERMINAL, "complete terminal");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
