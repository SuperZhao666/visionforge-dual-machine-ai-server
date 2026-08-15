package com.visionforge.inferencebenchmark.dataplane;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Physical Android-provider probe for the shared VFA2 AES-GCM fixture. */
public final class AuthenticatedDataPlaneV2InstrumentationProbe {
    private static final long CONNECTION_ID = 0x1020_3040_5060_7080L;
    private static final int KEY_EPOCH = 9;
    private static final long COUNTER = 0x0012_3456L;
    private static final String EXPECTED_WIRE_HEX =
            "564641320220010110203040506070800000000900000000001234560000000a"
                    + "9f6f11ab7a5393b4deda150df8b50ba9769f359e4cb09f4eddaf";

    private AuthenticatedDataPlaneV2InstrumentationProbe() {}

    public static void verify() throws Exception {
        byte[] key = new byte[AuthenticatedDataPlaneV2.AES_256_KEY_BYTES];
        for (int index = 0; index < key.length; index++) key[index] = (byte) index;
        byte[] prefix = {(byte) 0xa1, (byte) 0xb2, (byte) 0xc3, (byte) 0xd4};
        byte[] plaintext = "interop-v2".getBytes(StandardCharsets.US_ASCII);
        byte[] expectedWire = decodeHex(EXPECTED_WIRE_HEX);
        AuthenticatedDataPlaneV2.Domain domain = AuthenticatedDataPlaneV2.createDomain(
                CONNECTION_ID,
                KEY_EPOCH,
                AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                AuthenticatedDataPlaneV2.MessageType.VIDEO);
        try (AuthenticatedDataPlaneV2Sender sender = AuthenticatedDataPlaneV2.newSender(
                        key,
                        prefix,
                        domain,
                        AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES,
                        COUNTER);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            byte[] sealed = sender.seal(plaintext);
            require(Arrays.equals(sealed, expectedWire),
                    "Android AES-GCM provider does not match the VFA2 fixture");
            byte[] opened = receiver.open(expectedWire);
            require(Arrays.equals(opened, plaintext),
                    "Android AES-GCM provider cannot open the VFA2 fixture");
            Arrays.fill(opened, (byte) 0);

            byte[] forged = expectedWire.clone();
            forged[forged.length - 1] ^= 0x01;
            try {
                receiver.open(forged);
                throw new IllegalStateException("forged VFA2 tag was accepted");
            } catch (AuthenticatedDataPlaneV2Exception expected) {
                require(
                        expected.reason()
                                == AuthenticatedDataPlaneV2Exception.Reason
                                        .UNAUTHENTICATED_PACKET,
                        "packet-controlled failure leaked a detailed reason");
            } finally {
                Arrays.fill(forged, (byte) 0);
            }
            Arrays.fill(sealed, (byte) 0);
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(prefix, (byte) 0);
            Arrays.fill(plaintext, (byte) 0);
            Arrays.fill(expectedWire, (byte) 0);
        }
    }

    private static byte[] decodeHex(String value) {
        if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] decoded = new byte[value.length() / 2];
        for (int index = 0; index < decoded.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
