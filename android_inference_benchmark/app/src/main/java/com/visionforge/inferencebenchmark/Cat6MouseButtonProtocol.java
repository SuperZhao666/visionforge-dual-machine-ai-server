package com.visionforge.inferencebenchmark;

/** Strict decoder for the fixed Windows-to-phone CAT6 button snapshot. */
final class Cat6MouseButtonProtocol {
    static final int PORT = 5005;
    static final int PACKET_BYTES = 16;
    static final int VALID_BUTTON_MASK = 0x1f;
    private static final int MAGIC = 0x56464d42; // "VFMB"
    private static final int VERSION = 1;

    private Cat6MouseButtonProtocol() {
    }

    static Packet decode(byte[] datagram, int length) {
        if (datagram == null || length != PACKET_BYTES || datagram.length < length) {
            return null;
        }
        if (readInt(datagram, 0) != MAGIC || unsigned(datagram[4]) != VERSION
                || datagram[6] != 0 || datagram[7] != 0) {
            return null;
        }
        int buttonMask = unsigned(datagram[5]);
        int sessionId = readInt(datagram, 8);
        if (sessionId == 0 || (buttonMask & ~VALID_BUTTON_MASK) != 0) {
            return null;
        }
        return new Packet(buttonMask, sessionId, readInt(datagram, 12));
    }

    static boolean isNewerSequence(int candidate, int previous) {
        return candidate != previous && candidate - previous > 0;
    }

    private static int readInt(byte[] value, int offset) {
        return unsigned(value[offset]) << 24
                | unsigned(value[offset + 1]) << 16
                | unsigned(value[offset + 2]) << 8
                | unsigned(value[offset + 3]);
    }

    private static int unsigned(byte value) {
        return value & 0xff;
    }

    static final class Packet {
        final int buttonMask;
        final int sessionId;
        final int sequence;

        Packet(int buttonMask, int sessionId, int sequence) {
            this.buttonMask = buttonMask;
            this.sessionId = sessionId;
            this.sequence = sequence;
        }
    }
}
