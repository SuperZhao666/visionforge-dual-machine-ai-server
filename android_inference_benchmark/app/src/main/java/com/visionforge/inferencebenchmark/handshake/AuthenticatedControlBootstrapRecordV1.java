package com.visionforge.inferencebenchmark.handshake;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Strict unauthenticated TCP framing used only until peer Finished succeeds.
 *
 * <p>A parsed record is not proof of peer identity. Payload handlers must
 * rebuild their typed pair-generation, transcript and Finished objects and
 * complete mutual authentication before any VFC1 traffic key is installed.</p>
 */
public final class AuthenticatedControlBootstrapRecordV1 {
    public static final int VERSION = 1;
    public static final int HEADER_BYTES = 12;
    public static final int MAX_PAYLOAD_BYTES = 65_536;

    private static final byte[] MAGIC = new byte[] {'V', 'F', 'B', '1'};

    private AuthenticatedControlBootstrapRecordV1() {}

    public enum Direction {
        HOST_TO_ANDROID(1),
        ANDROID_TO_HOST(2);

        private final int code;

        Direction(int code) {
            this.code = code;
        }

        int code() {
            return code;
        }

        static Direction fromCode(int code) throws BootstrapException {
            for (Direction value : values()) {
                if (value.code == code) return value;
            }
            throw failure(Reason.INVALID_DIRECTION);
        }
    }

    public enum MessageType {
        HOST_HELLO(1),
        ANDROID_CHALLENGE_REQUEST(2),
        HOST_CHALLENGE_PROOF(3),
        SERVER_CHALLENGE(4),
        HOST_FINAL_PROOF(5),
        PAIR_GENERATION_CREDENTIAL(6),
        HOST_HANDSHAKE_SIGNATURE(7),
        ANDROID_HANDSHAKE_CONFIRMATION(8),
        HOST_FINISHED(9),
        ABORT(10);

        private final int code;

        MessageType(int code) {
            this.code = code;
        }

        int code() {
            return code;
        }

        static MessageType fromCode(int code) throws BootstrapException {
            for (MessageType value : values()) {
                if (value.code == code) return value;
            }
            throw failure(Reason.INVALID_MESSAGE_TYPE);
        }
    }

    public enum Reason {
        RECORD_TOO_SHORT,
        INVALID_MAGIC,
        UNSUPPORTED_VERSION,
        INVALID_HEADER_SIZE,
        INVALID_DIRECTION,
        UNEXPECTED_DIRECTION,
        INVALID_MESSAGE_TYPE,
        DIRECTION_MISMATCH,
        PAYLOAD_EMPTY,
        PAYLOAD_TOO_LARGE,
        LENGTH_MISMATCH,
        CLOSED
    }

    public static final class BootstrapException extends Exception {
        private static final long serialVersionUID = 1L;
        private final Reason reason;

        private BootstrapException(Reason reason) {
            super("authenticated control bootstrap record was rejected");
            this.reason = reason;
        }

        public Reason reason() {
            return reason;
        }
    }

    public static final class Record implements AutoCloseable {
        private final Direction direction;
        private final MessageType messageType;
        private byte[] payload;
        private boolean closed;

        private Record(
                Direction direction,
                MessageType messageType,
                byte[] payload) {
            this.direction = direction;
            this.messageType = messageType;
            this.payload = payload;
        }

        public synchronized Direction direction() throws BootstrapException {
            requireOpen();
            return direction;
        }

        public synchronized MessageType messageType() throws BootstrapException {
            requireOpen();
            return messageType;
        }

        public synchronized byte[] payload() throws BootstrapException {
            requireOpen();
            return payload.clone();
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            Arrays.fill(payload, (byte) 0);
            payload = null;
        }

        private synchronized void requireOpen() throws BootstrapException {
            if (closed || payload == null) {
                throw failure(Reason.CLOSED);
            }
        }
    }

    public static boolean isAllowed(Direction direction, MessageType messageType) {
        if (direction == null || messageType == null) return false;
        if (messageType == MessageType.ABORT) return true;
        if (direction == Direction.HOST_TO_ANDROID) {
            return messageType == MessageType.HOST_HELLO
                    || messageType == MessageType.HOST_CHALLENGE_PROOF
                    || messageType == MessageType.HOST_FINAL_PROOF
                    || messageType == MessageType.HOST_HANDSHAKE_SIGNATURE
                    || messageType == MessageType.HOST_FINISHED;
        }
        return messageType == MessageType.ANDROID_CHALLENGE_REQUEST
                || messageType == MessageType.SERVER_CHALLENGE
                || messageType == MessageType.PAIR_GENERATION_CREDENTIAL
                || messageType == MessageType.ANDROID_HANDSHAKE_CONFIRMATION;
    }

    public static byte[] encode(
            Direction direction,
            MessageType messageType,
            byte[] payload) throws BootstrapException {
        if (direction == null) throw failure(Reason.INVALID_DIRECTION);
        if (messageType == null) throw failure(Reason.INVALID_MESSAGE_TYPE);
        if (!isAllowed(direction, messageType)) {
            throw failure(Reason.DIRECTION_MISMATCH);
        }
        if (payload == null || payload.length == 0) {
            throw failure(Reason.PAYLOAD_EMPTY);
        }
        if (payload.length > MAX_PAYLOAD_BYTES) {
            throw failure(Reason.PAYLOAD_TOO_LARGE);
        }
        ByteBuffer output = ByteBuffer.allocate(HEADER_BYTES + payload.length);
        output.put(MAGIC);
        output.put((byte) VERSION);
        output.put((byte) HEADER_BYTES);
        output.put((byte) direction.code());
        output.put((byte) messageType.code());
        output.putInt(payload.length);
        output.put(payload);
        return output.array();
    }

    public static Record parse(byte[] encoded, Direction expectedDirection)
            throws BootstrapException {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw failure(Reason.RECORD_TOO_SHORT);
        }
        if (expectedDirection == null) {
            throw failure(Reason.INVALID_DIRECTION);
        }
        byte[] copy = encoded.clone();
        try {
            ByteBuffer input = ByteBuffer.wrap(copy);
            byte[] magic = new byte[MAGIC.length];
            input.get(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw failure(Reason.INVALID_MAGIC);
            }
            if (Byte.toUnsignedInt(input.get()) != VERSION) {
                throw failure(Reason.UNSUPPORTED_VERSION);
            }
            if (Byte.toUnsignedInt(input.get()) != HEADER_BYTES) {
                throw failure(Reason.INVALID_HEADER_SIZE);
            }
            Direction direction = Direction.fromCode(
                    Byte.toUnsignedInt(input.get()));
            if (direction != expectedDirection) {
                throw failure(Reason.UNEXPECTED_DIRECTION);
            }
            MessageType messageType = MessageType.fromCode(
                    Byte.toUnsignedInt(input.get()));
            if (!isAllowed(direction, messageType)) {
                throw failure(Reason.DIRECTION_MISMATCH);
            }
            long payloadLength = Integer.toUnsignedLong(input.getInt());
            if (payloadLength == 0L) {
                throw failure(Reason.PAYLOAD_EMPTY);
            }
            if (payloadLength > MAX_PAYLOAD_BYTES) {
                throw failure(Reason.PAYLOAD_TOO_LARGE);
            }
            if (payloadLength != input.remaining()) {
                throw failure(Reason.LENGTH_MISMATCH);
            }
            byte[] payload = new byte[(int) payloadLength];
            input.get(payload);
            return new Record(direction, messageType, payload);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    private static BootstrapException failure(Reason reason) {
        return new BootstrapException(reason);
    }
}
