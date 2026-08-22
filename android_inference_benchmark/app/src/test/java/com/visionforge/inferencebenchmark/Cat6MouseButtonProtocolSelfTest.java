package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Sender;
import com.visionforge.inferencebenchmark.dataplane.AuthenticatedMouseButtonV2;

import java.util.Arrays;

/** Regression for the confirmed-session-only CAT6 mouse-button boundary. */
final class Cat6MouseButtonProtocolSelfTest {
    private static final long CONNECTION_ID = 0x0123_4567_89ab_cdefL;

    public static void main(String[] arguments) throws Exception {
        run();
        System.out.println("Cat6MouseButtonProtocolSelfTest: PASS");
    }

    static void run() throws Exception {
        byte[] firstMaterial = trafficMaterial(0x10);
        byte[] secondMaterial = trafficMaterial(0x50);
        byte[] thirdMaterial = trafficMaterial(0x70);
        Cat6MouseButtonProtocol protocol = new Cat6MouseButtonProtocol();
        try (AuthenticatedDataPlaneV2Sender firstSender =
                     AuthenticatedMouseButtonV2.newSender(
                             firstMaterial, CONNECTION_ID);
             AuthenticatedDataPlaneV2Sender wrongConnectionSender =
                     AuthenticatedMouseButtonV2.newSender(
                             firstMaterial, CONNECTION_ID + 1L);
             AuthenticatedDataPlaneV2Sender secondSender =
                     AuthenticatedMouseButtonV2.newSender(
                             secondMaterial, CONNECTION_ID + 2L);
             AuthenticatedDataPlaneV2Sender thirdSender =
                     AuthenticatedMouseButtonV2.newSender(
                             thirdMaterial, CONNECTION_ID + 3L)) {
            byte[] firstEnvelope = firstSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x12));

            require(!protocol.sessionReady());
            require(protocol.decode(firstEnvelope, firstEnvelope.length) == null);
            require(protocol.decode(legacyPlaintextPacket(), 16) == null);

            require(protocol.installConfirmedMaterial(
                    firstMaterial, CONNECTION_ID));
            require(protocol.sessionReady());
            Cat6MouseButtonProtocol.Packet packet =
                    protocol.decode(firstEnvelope, firstEnvelope.length);
            require(packet != null);
            require(packet.buttonMask == 0x12);
            long firstRevision = packet.sessionRevision;

            require(protocol.decode(firstEnvelope, firstEnvelope.length) == null);
            require(protocol.installConfirmedMaterial(
                    firstMaterial, CONNECTION_ID));
            require(protocol.sessionReady());
            require(protocol.decode(firstEnvelope, firstEnvelope.length) == null);
            byte[] afterIdempotentInstall = firstSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x01));
            packet = protocol.decode(
                    afterIdempotentInstall, afterIdempotentInstall.length);
            require(packet != null && packet.buttonMask == 0x01);
            require(packet.sessionRevision == firstRevision);

            byte[] tampered = firstSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x02));
            tampered[tampered.length - 1] ^= 0x01;
            require(protocol.decode(tampered, tampered.length) == null);
            byte[] freshAfterTamper = firstSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x03));
            packet = protocol.decode(freshAfterTamper, freshAfterTamper.length);
            require(packet != null && packet.buttonMask == 0x03);

            byte[] wrongConnection = wrongConnectionSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x04));
            require(protocol.decode(wrongConnection, wrongConnection.length) == null);

            byte[] authenticatedInvalidMask = firstSender.seal(new byte[] {0x20});
            require(protocol.decode(
                    authenticatedInvalidMask, authenticatedInvalidMask.length) == null);

            require(protocol.installConfirmedMaterial(
                    secondMaterial, CONNECTION_ID + 2L));
            byte[] staleSession = firstSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x08));
            require(protocol.decode(staleSession, staleSession.length) == null);
            byte[] secondEnvelope = secondSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x10));
            packet = protocol.decode(secondEnvelope, secondEnvelope.length);
            require(packet != null && packet.buttonMask == 0x10);
            require(packet.sessionRevision > firstRevision);
            long decodedBeforeClearRevision = packet.sessionRevision;
            require(protocol.isCurrentSessionRevision(decodedBeforeClearRevision));

            require(protocol.clearConfirmedSession());
            require(!protocol.sessionReady());
            require(!protocol.isCurrentSessionRevision(decodedBeforeClearRevision));
            byte[] afterClear = secondSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x00));
            require(protocol.decode(afterClear, afterClear.length) == null);

            require(protocol.installConfirmedMaterial(
                    thirdMaterial, CONNECTION_ID + 3L));
            byte[] thirdEnvelope = thirdSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x08));
            require(protocol.decode(thirdEnvelope, thirdEnvelope.length) != null);
            byte[] malformedReplacement = Arrays.copyOf(
                    thirdMaterial, thirdMaterial.length - 1);
            require(!protocol.installConfirmedMaterial(
                    malformedReplacement, CONNECTION_ID + 4L));
            require(!protocol.sessionReady());
            byte[] afterRejectedReplacement = thirdSender.seal(
                    AuthenticatedMouseButtonV2.encodeButtonMask(0x04));
            require(protocol.decode(
                    afterRejectedReplacement,
                    afterRejectedReplacement.length) == null);
        } finally {
            protocol.close();
            Arrays.fill(firstMaterial, (byte) 0);
            Arrays.fill(secondMaterial, (byte) 0);
            Arrays.fill(thirdMaterial, (byte) 0);
        }
    }

    private static byte[] trafficMaterial(int seed) {
        byte[] material = new byte[AuthenticatedMouseButtonV2.TRAFFIC_MATERIAL_BYTES];
        for (int index = 0; index < material.length; index++) {
            material[index] = (byte) (seed + index);
        }
        return material;
    }

    private static byte[] legacyPlaintextPacket() {
        return new byte[] {
                0x56, 0x46, 0x4d, 0x42,
                0x01, 0x12, 0x00, 0x00,
                0x12, 0x34, 0x56, 0x78,
                0x00, 0x00, 0x00, 0x09
        };
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 mouse button protocol contract failed");
        }
    }
}
