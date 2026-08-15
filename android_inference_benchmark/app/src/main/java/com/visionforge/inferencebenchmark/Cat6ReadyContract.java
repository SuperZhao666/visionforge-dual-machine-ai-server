package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;

/** Dependency-free wire contract for the fixed CAT6 readiness channel. */
final class Cat6ReadyContract {
    static final int READY_PORT = 5003;
    static final int PROBE_PORT = 5004;
    static final int PROBE_DATAGRAM_BYTES = 1200;
    static final long READY_INTERVAL_MILLIS = 250L;
    private static final long MAXIMUM_SEQUENCE = 0xffff_ffffL;
    private static final int MAXIMUM_TOKEN_LENGTH = 64;
    private static final String READY_PREFIX = "VF_CAT6_READY_V1|";
    private static final String PROBE_PREFIX = "VF_CAT6_PROBE_V1|";
    private static final String PROBE_ACK_PREFIX = "VF_CAT6_PROBE_ACK_V1|";

    private Cat6ReadyContract() {
    }

    static byte[] ready(long sequence) {
        if (sequence < 0L || sequence > MAXIMUM_SEQUENCE) {
            throw new IllegalArgumentException("sequence outside unsigned 32-bit range");
        }
        return (READY_PREFIX + EthernetTransportContract.MOBILE_IPV4 + "|" + sequence)
                .getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] probe(String token) {
        if (!validToken(token)) throw new IllegalArgumentException("invalid CAT6 probe token");
        byte[] datagram = new byte[PROBE_DATAGRAM_BYTES];
        byte[] header = (PROBE_PREFIX + token + "|").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(header, 0, datagram, 0, header.length);
        return datagram;
    }

    static byte[] probeAck(byte[] datagram, int length) {
        if (datagram == null || length != PROBE_DATAGRAM_BYTES || length > datagram.length) {
            return null;
        }
        int headerLength = 0;
        while (headerLength < length && datagram[headerLength] != 0) headerLength++;
        for (int index = headerLength; index < length; index++) {
            if (datagram[index] != 0) return null;
        }
        String value = new String(datagram, 0, headerLength, StandardCharsets.US_ASCII);
        if (!value.startsWith(PROBE_PREFIX) || !value.endsWith("|")) return null;
        String token = value.substring(PROBE_PREFIX.length(), value.length() - 1);
        if (!validToken(token)) return null;
        byte[] response = new byte[PROBE_DATAGRAM_BYTES];
        byte[] header = (PROBE_ACK_PREFIX + token + "|").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(header, 0, response, 0, header.length);
        return response;
    }

    private static boolean validToken(String token) {
        if (token == null || token.isEmpty() || token.length() > MAXIMUM_TOKEN_LENGTH) return false;
        for (int index = 0; index < token.length(); index++) {
            char value = token.charAt(index);
            if (!(value >= '0' && value <= '9')
                    && !(value >= 'A' && value <= 'Z')
                    && !(value >= 'a' && value <= 'z')
                    && value != '_' && value != '-') {
                return false;
            }
        }
        return true;
    }
}
