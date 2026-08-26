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
        ABORT(10),
        HOST_FIRST_PAIR_OFFER(11),
        ANDROID_FIRST_PAIR_OFFER(12),
        ANDROID_FIRST_PAIR_CONFIRMATION(13),
        HOST_FIRST_PAIR_CONFIRMATION(14),
        ACTIVATION_PROOF_REQUEST(15),
        HOST_ACTIVATION_SIGNATURE(16),
        ACTIVATION_RESULT(17),
        FIRST_PAIR_COMPLETE(18);

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

    /** Result of feeding an arbitrary TCP fragment into {@link StreamDecoder}. */
    public enum StreamStatus {
        NEED_MORE,
        RECORD_READY,
        OUTPUT_PENDING,
        REJECTED,
        ALLOCATION_FAILED
    }

    public static final class FeedResult {
        private final StreamStatus status;
        private final int consumed;
        private final Reason rejection;

        private FeedResult(
                StreamStatus status,
                int consumed,
                Reason rejection) {
            this.status = status;
            this.consumed = consumed;
            this.rejection = rejection;
        }

        public StreamStatus status() {
            return status;
        }

        public int consumed() {
            return consumed;
        }

        public Reason rejection() {
            return rejection;
        }
    }

    /**
     * Bounded incremental decoder for the unauthenticated VFB1 TCP envelope.
     *
     * <p>It consumes at most one record at a time and returns the exact source
     * byte count consumed. A caller can therefore retain a coalesced remainder,
     * take the ready record, and feed the remainder as the next record. A bad
     * header permanently rejects this decoder because the owning TCP attempt
     * must be closed and restarted with fresh handshake state.</p>
     */
    public static final class StreamDecoder implements AutoCloseable {
        private final Direction expectedDirection;
        private final byte[] header = new byte[HEADER_BYTES];
        private int headerBytes;
        private byte[] encoded;
        private int encodedBytes;
        private boolean ready;
        private boolean rejected;
        private boolean closed;
        private Reason rejection = Reason.RECORD_TOO_SHORT;

        public StreamDecoder(Direction expectedDirection) {
            this.expectedDirection = expectedDirection;
            if (expectedDirection == null) {
                rejected = true;
                rejection = Reason.INVALID_DIRECTION;
            }
        }

        public synchronized FeedResult feed(byte[] source) {
            if (source == null) {
                throw new IllegalArgumentException("source is required");
            }
            return feed(source, 0, source.length);
        }

        public synchronized FeedResult feed(
                byte[] source,
                int offset,
                int length) {
            if (source == null) {
                throw new IllegalArgumentException("source is required");
            }
            if (offset < 0 || length < 0 || offset > source.length - length) {
                throw new IndexOutOfBoundsException("invalid source range");
            }
            if (closed) {
                return result(StreamStatus.REJECTED, 0, Reason.CLOSED);
            }
            if (rejected) {
                return result(StreamStatus.REJECTED, 0, rejection);
            }
            if (ready) {
                return result(StreamStatus.OUTPUT_PENDING, 0, null);
            }

            int consumed = 0;
            try {
                if (headerBytes < HEADER_BYTES) {
                    int copied = Math.min(HEADER_BYTES - headerBytes, length);
                    System.arraycopy(
                            source, offset, header, headerBytes, copied);
                    headerBytes += copied;
                    consumed += copied;
                    if (headerBytes < HEADER_BYTES) {
                        return result(
                                StreamStatus.NEED_MORE,
                                consumed,
                                Reason.RECORD_TOO_SHORT);
                    }
                    int payloadBytes = inspectHeader(
                            header, expectedDirection);
                    encoded = new byte[HEADER_BYTES + payloadBytes];
                    System.arraycopy(
                            header, 0, encoded, 0, HEADER_BYTES);
                    encodedBytes = HEADER_BYTES;
                    Arrays.fill(header, (byte) 0);
                }

                int copied = Math.min(
                        encoded.length - encodedBytes,
                        length - consumed);
                System.arraycopy(
                        source,
                        offset + consumed,
                        encoded,
                        encodedBytes,
                        copied);
                encodedBytes += copied;
                consumed += copied;
                if (encodedBytes < encoded.length) {
                    return result(
                            StreamStatus.NEED_MORE,
                            consumed,
                            Reason.RECORD_TOO_SHORT);
                }
                ready = true;
                return result(StreamStatus.RECORD_READY, consumed, null);
            } catch (BootstrapException malformed) {
                reject(malformed.reason());
                return result(StreamStatus.REJECTED, consumed, rejection);
            } catch (OutOfMemoryError allocationFailure) {
                reject(Reason.RECORD_TOO_SHORT);
                return result(
                        StreamStatus.ALLOCATION_FAILED,
                        consumed,
                        rejection);
            }
        }

        /** Transfers one complete encoded record and resets for the next. */
        public synchronized byte[] takeEncodedRecord() {
            if (closed || rejected || !ready || encoded == null) {
                throw new IllegalStateException("no VFB1 record is ready");
            }
            byte[] result = encoded;
            encoded = null;
            encodedBytes = 0;
            headerBytes = 0;
            ready = false;
            rejection = Reason.RECORD_TOO_SHORT;
            Arrays.fill(header, (byte) 0);
            return result;
        }

        public synchronized boolean recordReady() {
            return ready;
        }

        public synchronized boolean failed() {
            return rejected || closed;
        }

        @Override
        public synchronized void close() {
            if (closed) return;
            closed = true;
            ready = false;
            clear(encoded, header);
            encoded = null;
            encodedBytes = 0;
            headerBytes = 0;
        }

        private void reject(Reason reason) {
            rejected = true;
            ready = false;
            rejection = reason;
            clear(encoded, header);
            encoded = null;
            encodedBytes = 0;
            headerBytes = 0;
        }

        private static FeedResult result(
                StreamStatus status,
                int consumed,
                Reason rejection) {
            return new FeedResult(status, consumed, rejection);
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
                    || messageType == MessageType.HOST_FINISHED
                    || messageType == MessageType.HOST_FIRST_PAIR_OFFER
                    || messageType == MessageType.HOST_FIRST_PAIR_CONFIRMATION
                    || messageType == MessageType.HOST_ACTIVATION_SIGNATURE
                    || messageType == MessageType.FIRST_PAIR_COMPLETE;
        }
        return messageType == MessageType.ANDROID_CHALLENGE_REQUEST
                || messageType == MessageType.SERVER_CHALLENGE
                || messageType == MessageType.PAIR_GENERATION_CREDENTIAL
                || messageType == MessageType.ANDROID_HANDSHAKE_CONFIRMATION
                || messageType == MessageType.ANDROID_FIRST_PAIR_OFFER
                || messageType == MessageType.ANDROID_FIRST_PAIR_CONFIRMATION
                || messageType == MessageType.ACTIVATION_PROOF_REQUEST
                || messageType == MessageType.ACTIVATION_RESULT;
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
        byte[] copy = encoded.clone();
        try {
            int payloadLength = inspectHeader(copy, expectedDirection);
            if (HEADER_BYTES + payloadLength != copy.length) {
                throw failure(Reason.LENGTH_MISMATCH);
            }
            ByteBuffer input = ByteBuffer.wrap(copy);
            input.position(6);
            Direction direction = Direction.fromCode(
                    Byte.toUnsignedInt(input.get()));
            MessageType messageType = MessageType.fromCode(
                    Byte.toUnsignedInt(input.get()));
            input.position(HEADER_BYTES);
            byte[] payload = new byte[payloadLength];
            input.get(payload);
            return new Record(direction, messageType, payload);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    private static int inspectHeader(
            byte[] encoded,
            Direction expectedDirection) throws BootstrapException {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw failure(Reason.RECORD_TOO_SHORT);
        }
        if (expectedDirection == null) {
            throw failure(Reason.INVALID_DIRECTION);
        }
        ByteBuffer input = ByteBuffer.wrap(encoded, 0, HEADER_BYTES);
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
        return (int) payloadLength;
    }

    private static void clear(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static BootstrapException failure(Reason reason) {
        return new BootstrapException(reason);
    }
}
