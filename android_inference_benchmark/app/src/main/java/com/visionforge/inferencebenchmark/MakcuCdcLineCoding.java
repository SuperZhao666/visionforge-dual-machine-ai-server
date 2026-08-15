package com.visionforge.inferencebenchmark;

import java.util.Arrays;

/** Pure CDC line-coding and communication-interface contract. */
final class MakcuCdcLineCoding {
    static final int SET_LINE_CODING_REQUEST_TYPE = 0x21;
    static final int SET_LINE_CODING_REQUEST = 0x20;
    static final int GET_LINE_CODING_REQUEST_TYPE = 0xA1;
    static final int GET_LINE_CODING_REQUEST = 0x21;
    static final int SET_CONTROL_LINE_STATE_REQUEST_TYPE = 0x21;
    static final int SET_CONTROL_LINE_STATE_REQUEST = 0x22;
    static final int CONTROL_LINE_STATE_DTR_RTS = 3;
    static final int LINE_CODING_BYTES = 7;

    private MakcuCdcLineCoding() {}

    static byte[] encode8N1(int baudRate) {
        if (baudRate <= 0) throw new IllegalArgumentException("baudRate must be positive");
        return new byte[] {
                (byte) baudRate,
                (byte) (baudRate >>> 8),
                (byte) (baudRate >>> 16),
                (byte) (baudRate >>> 24),
                0,
                0,
                8
        };
    }

    static boolean matches(byte[] expected, byte[] observed, int transferredBytes) {
        return expected != null
                && observed != null
                && expected.length == LINE_CODING_BYTES
                && observed.length == LINE_CODING_BYTES
                && transferredBytes == LINE_CODING_BYTES
                && Arrays.equals(expected, observed);
    }

    static InterfaceResult selectUniqueAcmCommunicationInterface(
            int[] interfaceClasses, int[] interfaceSubclasses) {
        if (interfaceClasses == null || interfaceSubclasses == null
                || interfaceClasses.length == 0
                || interfaceClasses.length != interfaceSubclasses.length) {
            return InterfaceResult.failure("invalid_communication_interface_summary");
        }
        int selectedIndex = -1;
        int candidateCount = 0;
        for (int index = 0; index < interfaceClasses.length; index++) {
            if (interfaceClasses[index] != 2 || interfaceSubclasses[index] != 2) continue;
            selectedIndex = index;
            candidateCount++;
        }
        if (candidateCount == 0) {
            return InterfaceResult.failure("no_cdc_acm_communication_interface");
        }
        if (candidateCount != 1) {
            return InterfaceResult.failure("multiple_cdc_acm_communication_interfaces_count_"
                    + candidateCount);
        }
        return InterfaceResult.success(selectedIndex);
    }

    static final class InterfaceResult {
        final boolean succeeded;
        final int interfaceIndex;
        final String failureToken;

        private InterfaceResult(boolean succeeded, int interfaceIndex, String failureToken) {
            this.succeeded = succeeded;
            this.interfaceIndex = interfaceIndex;
            this.failureToken = failureToken;
        }

        private static InterfaceResult success(int interfaceIndex) {
            return new InterfaceResult(true, interfaceIndex, "none");
        }

        private static InterfaceResult failure(String failureToken) {
            return new InterfaceResult(false, -1, failureToken);
        }
    }
}
