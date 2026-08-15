package com.visionforge.inferencebenchmark;

/** Dependency-free contract for verified CDC 8N1 configuration. */
final class MakcuCdcLineCodingSelfTest {
    static void run() {
        encodesFourMegabaud8N1();
        matchesOnlyCompleteExactReadback();
        selectsExactlyOneCommunicationInterface();
        rejectsMissingOrAmbiguousCommunicationInterface();
    }

    private static void encodesFourMegabaud8N1() {
        require(MakcuCdcLineCoding.SET_LINE_CODING_REQUEST_TYPE == 0x21);
        require(MakcuCdcLineCoding.SET_LINE_CODING_REQUEST == 0x20);
        require(MakcuCdcLineCoding.GET_LINE_CODING_REQUEST_TYPE == 0xA1);
        require(MakcuCdcLineCoding.GET_LINE_CODING_REQUEST == 0x21);
        require(MakcuCdcLineCoding.SET_CONTROL_LINE_STATE_REQUEST_TYPE == 0x21);
        require(MakcuCdcLineCoding.SET_CONTROL_LINE_STATE_REQUEST == 0x22);
        require(MakcuCdcLineCoding.CONTROL_LINE_STATE_DTR_RTS == 3);
        byte[] lineCoding = MakcuCdcLineCoding.encode8N1(4_000_000);
        require(lineCoding.length == 7);
        require((lineCoding[0] & 0xff) == 0x00);
        require((lineCoding[1] & 0xff) == 0x09);
        require((lineCoding[2] & 0xff) == 0x3D);
        require((lineCoding[3] & 0xff) == 0x00);
        require(lineCoding[4] == 0 && lineCoding[5] == 0 && lineCoding[6] == 8);

        byte[] defaultBaud = MakcuCdcLineCoding.encode8N1(115_200);
        require((defaultBaud[0] & 0xff) == 0x00);
        require((defaultBaud[1] & 0xff) == 0xC2);
        require((defaultBaud[2] & 0xff) == 0x01);
        require((defaultBaud[3] & 0xff) == 0x00);
    }

    private static void matchesOnlyCompleteExactReadback() {
        byte[] expected = MakcuCdcLineCoding.encode8N1(115_200);
        byte[] observed = expected.clone();
        require(MakcuCdcLineCoding.matches(expected, observed, 7));
        observed[6] = 7;
        require(!MakcuCdcLineCoding.matches(expected, observed, 7));
        require(!MakcuCdcLineCoding.matches(expected, expected.clone(), 6));
        require(!MakcuCdcLineCoding.matches(expected, new byte[6], 7));
        require(!MakcuCdcLineCoding.matches(null, expected, 7));
    }

    private static void selectsExactlyOneCommunicationInterface() {
        MakcuCdcLineCoding.InterfaceResult result =
                MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                        new int[] {2, 10}, new int[] {2, 0});
        require(result.succeeded);
        require(result.interfaceIndex == 0);
        require("none".equals(result.failureToken));
    }

    private static void rejectsMissingOrAmbiguousCommunicationInterface() {
        MakcuCdcLineCoding.InterfaceResult missing =
                MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                        new int[] {2, 10}, new int[] {0, 0});
        require(!missing.succeeded);
        require("no_cdc_acm_communication_interface".equals(missing.failureToken));

        MakcuCdcLineCoding.InterfaceResult ambiguous =
                MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                        new int[] {2, 10, 2}, new int[] {2, 0, 2});
        require(!ambiguous.succeeded);
        require("multiple_cdc_acm_communication_interfaces_count_2"
                .equals(ambiguous.failureToken));

        require(!MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                null, null).succeeded);
        require(!MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                new int[0], new int[0]).succeeded);
        require(!MakcuCdcLineCoding.selectUniqueAcmCommunicationInterface(
                new int[] {2}, new int[] {2, 0}).succeeded);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU CDC line-coding contract failed");
    }
}
