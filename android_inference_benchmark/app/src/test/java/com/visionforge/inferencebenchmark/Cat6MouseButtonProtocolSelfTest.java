package com.visionforge.inferencebenchmark;

/**
 * Development-only regression for the legacy plaintext button snapshot ABI.
 * Formal release is blocked while this parser remains on the production path.
 */
final class Cat6MouseButtonProtocolSelfTest {
    static void run() {
        byte[] datagram = new byte[] {
                0x56, 0x46, 0x4d, 0x42,
                0x01, 0x12, 0x00, 0x00,
                0x12, 0x34, 0x56, 0x78,
                0x00, 0x00, 0x00, 0x09
        };
        Cat6MouseButtonProtocol.Packet packet =
                Cat6MouseButtonProtocol.decode(datagram, datagram.length);
        require(packet != null);
        require(packet.buttonMask == 0x12);
        require(packet.sessionId == 0x12345678);
        require(packet.sequence == 9);

        byte[] malformed = datagram.clone();
        malformed[6] = 1;
        require(Cat6MouseButtonProtocol.decode(malformed, malformed.length) == null);
        malformed = datagram.clone();
        malformed[5] = 0x20;
        require(Cat6MouseButtonProtocol.decode(malformed, malformed.length) == null);
        require(Cat6MouseButtonProtocol.decode(datagram, datagram.length - 1) == null);

        require(Cat6MouseButtonProtocol.isNewerSequence(10, 9));
        require(!Cat6MouseButtonProtocol.isNewerSequence(9, 9));
        require(!Cat6MouseButtonProtocol.isNewerSequence(8, 9));
        require(Cat6MouseButtonProtocol.isNewerSequence(0, -1));
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 mouse button protocol contract failed");
        }
    }
}
