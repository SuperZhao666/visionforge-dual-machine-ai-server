package com.visionforge.inferencebenchmark.dataplane;

import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception.Reason.CLOSED;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception.Reason.COUNTER_EXHAUSTED;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception.Reason.CRYPTO_UNAVAILABLE;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception.Reason.PAYLOAD_TOO_LARGE;
import static com.visionforge.inferencebenchmark.dataplane.AuthenticatedDataPlaneV2Exception.Reason.UNAUTHENTICATED_PACKET;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public final class AuthenticatedDataPlaneV2SelfTest {
    private static final String TEST_KEY_HEX =
            "000102030405060708090a0b0c0d0e0f"
                    + "101112131415161718191a1b1c1d1e1f";
    private static final String TEST_PREFIX_HEX = "a1b2c3d4";
    private static final long CONNECTION_ID = 0x1020_3040_5060_7080L;
    private static final int KEY_EPOCH = 9;
    private static final long VECTOR_COUNTER = 0x0012_3456L;
    private static final String VECTOR_HEADER_HEX =
            "56464132022001011020304050607080"
                    + "0000000900000000001234560000000a";
    private static final String VECTOR_NONCE_HEX = "a1b2c3d40000000000123456";
    private static final String VECTOR_WIRE_HEX =
            VECTOR_HEADER_HEX
                    + "9f6f11ab7a5393b4deda150df8b50ba9769f359e4cb09f4eddaf";

    public static void main(String[] arguments) throws Exception {
        verifiesFixedCrossLanguageVectorAndDefensiveCopies();
        verifiesMutationsDoNotAdvanceReplayState();
        verifiesWrongConnectionEpochDirectionTypeKeyAndPrefix();
        verifiesLimitedOutOfOrderAndReplayRejection();
        verifiesDefaultReplayWindowBoundary();
        verifiesExactReplayWindowShiftBoundaries();
        verifiesCounterBurnLifetimeLimitAndRekey();
        verifiesTupleDomainSeparation();
        verifiesUnsignedDomainBitPatterns();
        verifiesStrictEnvelopeParsingAndUdpBudget();
        verifiesClosedEndpointsAndInvalidInputsFailClosed();
    }

    private static void verifiesFixedCrossLanguageVectorAndDefensiveCopies()
            throws Exception {
        byte[] inputKey = testKey();
        byte[] inputPrefix = testPrefix();
        byte[] plaintext = "interop-v2".getBytes(StandardCharsets.US_ASCII);
        byte[] expectedWire = hex(VECTOR_WIRE_HEX);
        byte[] nonce =
                AuthenticatedDataPlaneV2Internals.composeNonce(
                        inputPrefix, VECTOR_COUNTER);
        require(Arrays.equals(nonce, hex(VECTOR_NONCE_HEX)), "fixed interop nonce");

        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(
                                inputKey,
                                inputPrefix,
                                domain,
                                AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES,
                                VECTOR_COUNTER);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(
                                inputKey, inputPrefix, domain)) {
            Arrays.fill(inputKey, (byte) 0x5a);
            Arrays.fill(inputPrefix, (byte) 0x5a);
            byte[] envelope = sender.seal(plaintext);
            require(Arrays.equals(envelope, expectedWire),
                    "Java/JCA output must match the independent C++ interop fixture");
            requireCanonicalHeader(envelope, domain, VECTOR_COUNTER, plaintext.length);
            requireOpenEquals(receiver, expectedWire, plaintext);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelope));
            clearAll(envelope);
        } finally {
            clearAll(inputKey, inputPrefix, plaintext, expectedWire, nonce);
        }
    }

    private static void verifiesMutationsDoNotAdvanceReplayState() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(key, prefix, domain);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(
                                key,
                                prefix,
                                domain,
                                AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES,
                                64)) {
            byte[][] envelopes = sealSequence(sender, 4);

            byte[] ciphertextMutation = envelopes[0].clone();
            ciphertextMutation[AuthenticatedDataPlaneV2Internals.HEADER_BYTES] ^= 0x01;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(ciphertextMutation));
            requireOpenEquals(receiver, envelopes[0], payload(0));

            byte[] tagMutation = envelopes[1].clone();
            tagMutation[tagMutation.length - 1] ^= 0x01;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(tagMutation));
            requireOpenEquals(receiver, envelopes[1], payload(1));

            byte[] aadCounterMutation = envelopes[2].clone();
            aadCounterMutation[AuthenticatedDataPlaneV2Internals.COUNTER_OFFSET + 7] ^= 0x40;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(aadCounterMutation));
            requireOpenEquals(receiver, envelopes[2], payload(2));

            byte[] truncated = Arrays.copyOf(envelopes[3], envelopes[3].length - 1);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(truncated));
            requireOpenEquals(receiver, envelopes[3], payload(3));
            clearAll(envelopes);
            clearAll(ciphertextMutation, tagMutation, aadCounterMutation, truncated);
        } finally {
            clearAll(key, prefix);
        }
    }

    private static void verifiesWrongConnectionEpochDirectionTypeKeyAndPrefix()
            throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        byte[] envelope = sealAtCounter(key, prefix, domain, 0L, payload(7));

        requireDomainMismatch(key, prefix, envelope, domain(
                CONNECTION_ID + 1L, KEY_EPOCH, domain.direction(), domain.messageType()));
        requireDomainMismatch(key, prefix, envelope, domain(
                CONNECTION_ID, KEY_EPOCH + 1, domain.direction(), domain.messageType()));
        requireDomainMismatch(key, prefix, envelope, domain(
                CONNECTION_ID, KEY_EPOCH,
                AuthenticatedDataPlaneV2.Direction.ANDROID_TO_HOST,
                domain.messageType()));
        requireDomainMismatch(key, prefix, envelope, domain(
                CONNECTION_ID, KEY_EPOCH, domain.direction(),
                AuthenticatedDataPlaneV2.MessageType.PRESENCE_PROBE));

        byte[] wrongKey = key.clone();
        wrongKey[0] ^= 0x01;
        requireUnauthenticatedRejection(wrongKey, prefix, envelope, domain);
        byte[] wrongPrefix = prefix.clone();
        wrongPrefix[0] ^= 0x01;
        requireUnauthenticatedRejection(key, wrongPrefix, envelope, domain);

        byte[] wrongVersion = envelope.clone();
        wrongVersion[AuthenticatedDataPlaneV2Internals.VERSION_OFFSET] = 3;
        try (AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(wrongVersion));
        }
        clearAll(key, prefix, envelope, wrongKey, wrongPrefix, wrongVersion);
    }

    private static void verifiesLimitedOutOfOrderAndReplayRejection() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(key, prefix, domain);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain, 128, 4)) {
            byte[][] envelopes = sealSequence(sender, 6);
            requireOpenEquals(receiver, envelopes[3], payload(3));
            requireOpenEquals(receiver, envelopes[1], payload(1));
            requireOpenEquals(receiver, envelopes[2], payload(2));
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelopes[1]));
            requireOpenEquals(receiver, envelopes[5], payload(5));
            requireOpenEquals(receiver, envelopes[4], payload(4));
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelopes[0]));
            clearAll(envelopes);
        } finally {
            clearAll(key, prefix);
        }
    }

    private static void verifiesDefaultReplayWindowBoundary() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(key, prefix, domain);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            byte[][] envelopes = sealSequence(sender, 1026);
            requireOpenEquals(receiver, envelopes[1023], payload(1023));
            requireOpenEquals(receiver, envelopes[0], payload(0));
            requireOpenEquals(receiver, envelopes[1024], payload(1024));
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelopes[0]));
            requireOpenEquals(receiver, envelopes[1], payload(1));
            requireOpenEquals(receiver, envelopes[1025], payload(1025));
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelopes[1]));
            clearAll(envelopes);
        } finally {
            clearAll(key, prefix);
        }
    }

    private static void verifiesExactReplayWindowShiftBoundaries() {
        int[] windowSizes = {1, 63, 64, 65, 127, 1023, 1024};
        long[] advances = {1L, 63L, 64L, 65L, 1023L, 1024L};
        for (int windowSize : windowSizes) {
            for (long advance : advances) {
                UnsignedReplayWindow window = new UnsignedReplayWindow(windowSize);
                require(window.commitAuthenticated(0L), "initial replay commit");
                require(window.commitAuthenticated(advance), "advanced replay commit");
                UnsignedReplayWindow.Decision expected = advance < windowSize
                        ? UnsignedReplayWindow.Decision.DUPLICATE
                        : UnsignedReplayWindow.Decision.TOO_OLD;
                require(window.inspect(0L) == expected,
                        "exact replay shift boundary " + windowSize + "/" + advance);

                if (advance >= windowSize && windowSize > 1) {
                    long insideEdge = advance - (windowSize - 1L);
                    require(window.inspect(insideEdge) == UnsignedReplayWindow.Decision.ACCEPT,
                            "inside replay edge remains available");
                    require(window.commitAuthenticated(insideEdge),
                            "inside replay edge commits");
                    require(window.inspect(insideEdge)
                                    == UnsignedReplayWindow.Decision.DUPLICATE,
                            "inside replay edge becomes duplicate");
                }
            }
        }
    }

    private static void verifiesCounterBurnLifetimeLimitAndRekey() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        AtomicInteger attempts = new AtomicInteger();
        AuthenticatedDataPlaneV2Internals.EncryptionAttemptHook failOnce =
                () -> {
                    if (attempts.getAndIncrement() == 0) {
                        throw new java.security.GeneralSecurityException(
                                "injected encryption-attempt failure");
                    }
                };
        try (AuthenticatedDataPlaneV2Sender sender =
                new AuthenticatedDataPlaneV2Sender(
                        key, prefix, domain, 128, 5L, failOnce)) {
            expectReason(CRYPTO_UNAVAILABLE, () -> sender.seal(payload(5)));
            byte[] afterFailure = sender.seal(payload(6));
            require(headerCounter(afterFailure) == 6L,
                    "failed AEAD attempt must burn counter 5");
            clearAll(afterFailure);
        }

        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(
                                key,
                                prefix,
                                domain,
                                128,
                                AuthenticatedDataPlaneV2.MAX_COUNTER_PER_TRAFFIC_KEY);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(
                                key, prefix, domain, 128, 4)) {
            byte[] finalPacket = sender.seal(payload(9));
            require(headerCounter(finalPacket)
                            == AuthenticatedDataPlaneV2.MAX_COUNTER_PER_TRAFFIC_KEY,
                    "final allowed traffic-key counter");
            requireOpenEquals(receiver, finalPacket, payload(9));
            expectReason(COUNTER_EXHAUSTED, () -> sender.seal(payload(10)));
            byte[] aboveLimit = finalPacket.clone();
            ByteBuffer.wrap(
                            aboveLimit,
                            AuthenticatedDataPlaneV2Internals.COUNTER_OFFSET,
                            Long.BYTES)
                    .putLong(AuthenticatedDataPlaneV2.MAX_PACKETS_PER_TRAFFIC_KEY);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(aboveLimit));
            clearAll(finalPacket, aboveLimit);
        }

        AuthenticatedDataPlaneV2Internals.EncryptionAttemptHook alwaysFail =
                () -> {
                    throw new java.security.GeneralSecurityException("injected limit failure");
                };
        try (AuthenticatedDataPlaneV2Sender sender =
                new AuthenticatedDataPlaneV2Sender(
                        key,
                        prefix,
                        domain,
                        128,
                        AuthenticatedDataPlaneV2.MAX_COUNTER_PER_TRAFFIC_KEY,
                        alwaysFail)) {
            expectReason(CRYPTO_UNAVAILABLE, () -> sender.seal(payload(1)));
            expectReason(COUNTER_EXHAUSTED, () -> sender.seal(payload(2)));
        }

        byte[] rekeyedKey = key.clone();
        byte[] rekeyedPrefix = prefix.clone();
        rekeyedKey[0] ^= 0x40;
        rekeyedPrefix[0] ^= 0x40;
        AuthenticatedDataPlaneV2.Domain rekeyedDomain = domain(
                CONNECTION_ID,
                KEY_EPOCH + 1,
                domain.direction(),
                domain.messageType());
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(
                                rekeyedKey, rekeyedPrefix, rekeyedDomain);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(
                                rekeyedKey, rekeyedPrefix, rekeyedDomain)) {
            byte[] rekeyedPacket = sender.seal(payload(0));
            require(headerCounter(rekeyedPacket) == 0L, "rekeyed tuple starts at counter zero");
            requireOpenEquals(receiver, rekeyedPacket, payload(0));
            clearAll(rekeyedPacket);
        }
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.newSender(
                key,
                prefix,
                domain,
                128,
                AuthenticatedDataPlaneV2.MAX_PACKETS_PER_TRAFFIC_KEY));
        clearAll(key, prefix, rekeyedKey, rekeyedPrefix);
    }

    private static void verifiesTupleDomainSeparation() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        byte[] otherKey = key.clone();
        byte[] otherPrefix = prefix.clone();
        otherKey[31] ^= 0x40;
        otherPrefix[3] ^= 0x40;
        AuthenticatedDataPlaneV2.Domain base = standardDomain();
        AuthenticatedDataPlaneV2.Domain other = domain(
                CONNECTION_ID,
                KEY_EPOCH,
                AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                AuthenticatedDataPlaneV2.MessageType.IDR_REQUEST);
        long counter = VECTOR_COUNTER;
        byte[] baseNonce = AuthenticatedDataPlaneV2Internals.composeNonce(prefix, counter);
        byte[] otherNonce = AuthenticatedDataPlaneV2Internals.composeNonce(otherPrefix, counter);
        require(Arrays.equals(
                        Arrays.copyOfRange(baseNonce, 4, 12),
                        hex("0000000000123456")),
                "counter must use network byte order");
        require(!MessageDigest.isEqual(
                        Arrays.copyOf(baseNonce, 4), Arrays.copyOf(otherNonce, 4)),
                "KDF-provided tuple prefixes must separate nonce domains");

        byte[] plaintext = payload(11);
        byte[] baseEnvelope = sealAtCounter(key, prefix, base, counter, plaintext);
        byte[] otherEnvelope =
                sealAtCounter(otherKey, otherPrefix, other, counter, plaintext);
        byte[] baseCiphertext = ciphertextAndTag(baseEnvelope);
        byte[] otherCiphertext = ciphertextAndTag(otherEnvelope);
        require(!MessageDigest.isEqual(baseCiphertext, otherCiphertext),
                "tuple-separated traffic material must change ciphertext/tag");
        requireDomainMismatch(key, prefix, baseEnvelope, other);
        clearAll(key, prefix, otherKey, otherPrefix, baseNonce, otherNonce,
                plaintext, baseEnvelope, otherEnvelope, baseCiphertext, otherCiphertext);
    }

    private static void verifiesUnsignedDomainBitPatterns() throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain unsignedDomain = domain(
                Long.MIN_VALUE,
                Integer.MIN_VALUE,
                AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                AuthenticatedDataPlaneV2.MessageType.VIDEO);
        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(key, prefix, unsignedDomain);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(key, prefix, unsignedDomain)) {
            byte[] envelope = sender.seal(payload(0));
            ByteBuffer header = ByteBuffer.wrap(envelope);
            header.position(AuthenticatedDataPlaneV2Internals.CONNECTION_ID_OFFSET);
            require(header.getLong() == Long.MIN_VALUE,
                    "u64 connection bit pattern must survive Java signed long");
            require(header.getInt() == Integer.MIN_VALUE,
                    "u32 epoch bit pattern must survive Java signed int");
            requireOpenEquals(receiver, envelope, payload(0));

            byte[] highCounter = envelope.clone();
            ByteBuffer.wrap(
                            highCounter,
                            AuthenticatedDataPlaneV2Internals.COUNTER_OFFSET,
                            Long.BYTES)
                    .putLong(Long.MIN_VALUE);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(highCounter));
            byte[] unsignedMaximumCounter = envelope.clone();
            ByteBuffer.wrap(
                            unsignedMaximumCounter,
                            AuthenticatedDataPlaneV2Internals.COUNTER_OFFSET,
                            Long.BYTES)
                    .putLong(-1L);
            expectReason(
                    UNAUTHENTICATED_PACKET,
                    () -> receiver.open(unsignedMaximumCounter));
            clearAll(envelope, highCounter, unsignedMaximumCounter);
        }
        clearAll(key, prefix);
    }

    private static void verifiesStrictEnvelopeParsingAndUdpBudget() throws Exception {
        require(AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES == 1364,
                "1412-byte UDP budget payload cap");
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        byte[] maximumPayload = new byte[AuthenticatedDataPlaneV2.DEFAULT_MAX_PAYLOAD_BYTES];
        Arrays.fill(maximumPayload, (byte) 0x3c);
        byte[] maximumEnvelope;
        try (AuthenticatedDataPlaneV2Sender sender =
                AuthenticatedDataPlaneV2.newSender(key, prefix, domain)) {
            maximumEnvelope = sender.seal(maximumPayload);
            require(maximumEnvelope.length == AuthenticatedDataPlaneV2.MAX_DATAGRAM_BYTES,
                    "maximum datagram size");
            expectReason(PAYLOAD_TOO_LARGE, () -> sender.seal(new byte[1365]));
        }
        try (AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            requireOpenEquals(receiver, maximumEnvelope, maximumPayload);
            byte[] oversized = Arrays.copyOf(maximumEnvelope, maximumEnvelope.length + 1);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(oversized));
            clearAll(oversized);
        }

        byte[] envelope = sealAtCounter(key, prefix, domain, 10L, payload(10));
        try (AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            byte[] trailing = Arrays.copyOf(envelope, envelope.length + 1);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(trailing));
            byte[] truncated = Arrays.copyOf(envelope, envelope.length - 1);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(truncated));
            byte[] signedMaximumLength = envelope.clone();
            ByteBuffer.wrap(
                            signedMaximumLength,
                            AuthenticatedDataPlaneV2Internals.PAYLOAD_LENGTH_OFFSET,
                            Integer.BYTES)
                    .putInt(0x7fff_ffff);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(signedMaximumLength));
            byte[] unsignedHighBitLength = envelope.clone();
            ByteBuffer.wrap(
                            unsignedHighBitLength,
                            AuthenticatedDataPlaneV2Internals.PAYLOAD_LENGTH_OFFSET,
                            Integer.BYTES)
                    .putInt(0x8000_0000);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(unsignedHighBitLength));
            byte[] unsignedMaximumLength = envelope.clone();
            Arrays.fill(
                    unsignedMaximumLength,
                    AuthenticatedDataPlaneV2Internals.PAYLOAD_LENGTH_OFFSET,
                    AuthenticatedDataPlaneV2Internals.HEADER_BYTES,
                    (byte) 0xff);
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(unsignedMaximumLength));
            byte[] invalidDirection = envelope.clone();
            invalidDirection[AuthenticatedDataPlaneV2Internals.DIRECTION_OFFSET] = 0x7f;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(invalidDirection));
            byte[] invalidType = envelope.clone();
            invalidType[AuthenticatedDataPlaneV2Internals.MESSAGE_TYPE_OFFSET] = 0x7f;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(invalidType));
            byte[] invalidHeaderSize = envelope.clone();
            invalidHeaderSize[AuthenticatedDataPlaneV2Internals.HEADER_SIZE_OFFSET] = 31;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(invalidHeaderSize));
            byte[] invalidMagic = envelope.clone();
            invalidMagic[AuthenticatedDataPlaneV2Internals.MAGIC_OFFSET] ^= 0x01;
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(invalidMagic));
            clearAll(trailing, truncated, signedMaximumLength, unsignedHighBitLength,
                    unsignedMaximumLength, invalidDirection, invalidType,
                    invalidHeaderSize, invalidMagic);
        }

        try (AuthenticatedDataPlaneV2Sender sender =
                        AuthenticatedDataPlaneV2.newSender(key, prefix, domain, 0, 0L);
                AuthenticatedDataPlaneV2Receiver receiver =
                        AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain, 0, 64)) {
            byte[] emptyEnvelope = sender.seal(new byte[0]);
            requireOpenEquals(receiver, emptyEnvelope, new byte[0]);
            clearAll(emptyEnvelope);
        }
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.newSender(
                key, prefix, domain, 1365, 0L));
        clearAll(key, prefix, maximumPayload, maximumEnvelope, envelope);
    }

    private static void verifiesClosedEndpointsAndInvalidInputsFailClosed()
            throws Exception {
        byte[] key = testKey();
        byte[] prefix = testPrefix();
        AuthenticatedDataPlaneV2.Domain domain = standardDomain();
        AuthenticatedDataPlaneV2Sender sender =
                AuthenticatedDataPlaneV2.newSender(key, prefix, domain);
        byte[] envelope = sender.seal(payload(1));
        sender.close();
        expectReason(CLOSED, () -> sender.seal(payload(2)));

        AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain);
        receiver.close();
        expectReason(CLOSED, () -> receiver.open(envelope));
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.newSender(
                new byte[31], prefix, domain));
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.newSender(
                key, new byte[3], domain));
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.createDomain(
                0L, KEY_EPOCH, domain.direction(), domain.messageType()));
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.createDomain(
                CONNECTION_ID, 0, domain.direction(), domain.messageType()));
        expectIllegalArgument(() -> AuthenticatedDataPlaneV2.newReceiver(
                key, prefix, domain, 1, 1025));
        try (AuthenticatedDataPlaneV2Sender nullRejectingSender =
                AuthenticatedDataPlaneV2.newSender(key, prefix, domain)) {
            expectIllegalArgument(() -> nullRejectingSender.seal(null));
        }
        clearAll(key, prefix, envelope);
    }

    private static void requireCanonicalHeader(
            byte[] envelope,
            AuthenticatedDataPlaneV2.Domain domain,
            long counter,
            int payloadLength) {
        require(envelope.length == AuthenticatedDataPlaneV2Internals.HEADER_BYTES
                        + payloadLength + AuthenticatedDataPlaneV2.GCM_TAG_BYTES,
                "canonical envelope length");
        ByteBuffer header = ByteBuffer.wrap(envelope);
        require(header.getInt() == AuthenticatedDataPlaneV2Internals.MAGIC, "VFA2 magic");
        require(Byte.toUnsignedInt(header.get()) == AuthenticatedDataPlaneV2.PROTOCOL_VERSION,
                "protocol version");
        require(Byte.toUnsignedInt(header.get()) == AuthenticatedDataPlaneV2Internals.HEADER_BYTES,
                "header size");
        require(Byte.toUnsignedInt(header.get()) == domain.messageType().wireCode(),
                "packet type");
        require(Byte.toUnsignedInt(header.get()) == domain.direction().wireCode(), "direction");
        require(header.getLong() == domain.connectionId(), "connection id");
        require(header.getInt() == domain.keyEpoch(), "key epoch");
        require(header.getLong() == counter, "network-order counter");
        require(header.getInt() == payloadLength, "payload length");
    }

    private static void requireDomainMismatch(
            byte[] key,
            byte[] prefix,
            byte[] envelope,
            AuthenticatedDataPlaneV2.Domain wrongDomain)
            throws Exception {
        try (AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, wrongDomain)) {
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelope));
        }
    }

    private static void requireUnauthenticatedRejection(
            byte[] key,
            byte[] prefix,
            byte[] envelope,
            AuthenticatedDataPlaneV2.Domain domain)
            throws Exception {
        try (AuthenticatedDataPlaneV2Receiver receiver =
                AuthenticatedDataPlaneV2.newReceiver(key, prefix, domain)) {
            expectReason(UNAUTHENTICATED_PACKET, () -> receiver.open(envelope));
        }
    }

    private static byte[][] sealSequence(AuthenticatedDataPlaneV2Sender sender, int count)
            throws Exception {
        byte[][] envelopes = new byte[count][];
        for (int index = 0; index < count; index++) {
            envelopes[index] = sender.seal(payload(index));
        }
        return envelopes;
    }

    private static byte[] sealAtCounter(
            byte[] key,
            byte[] prefix,
            AuthenticatedDataPlaneV2.Domain domain,
            long counter,
            byte[] plaintext)
            throws Exception {
        try (AuthenticatedDataPlaneV2Sender sender =
                AuthenticatedDataPlaneV2.newSender(key, prefix, domain, 128, counter)) {
            return sender.seal(plaintext);
        }
    }

    private static byte[] ciphertextAndTag(byte[] envelope) {
        return Arrays.copyOfRange(
                envelope, AuthenticatedDataPlaneV2Internals.HEADER_BYTES, envelope.length);
    }

    private static void requireOpenEquals(
            AuthenticatedDataPlaneV2Receiver receiver, byte[] envelope, byte[] expected)
            throws Exception {
        byte[] actual = receiver.open(envelope);
        try {
            require(Arrays.equals(actual, expected), "authenticated plaintext round-trip");
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    private static long headerCounter(byte[] envelope) {
        return ByteBuffer.wrap(
                        envelope,
                        AuthenticatedDataPlaneV2Internals.COUNTER_OFFSET,
                        Long.BYTES)
                .getLong();
    }

    private static AuthenticatedDataPlaneV2.Domain standardDomain() {
        return domain(
                CONNECTION_ID,
                KEY_EPOCH,
                AuthenticatedDataPlaneV2.Direction.HOST_TO_ANDROID,
                AuthenticatedDataPlaneV2.MessageType.VIDEO);
    }

    private static AuthenticatedDataPlaneV2.Domain domain(
            long connectionId,
            int keyEpoch,
            AuthenticatedDataPlaneV2.Direction direction,
            AuthenticatedDataPlaneV2.MessageType messageType) {
        return AuthenticatedDataPlaneV2.createDomain(
                connectionId, keyEpoch, direction, messageType);
    }

    private static byte[] payload(int sequence) {
        return ("payload-" + sequence).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] testKey() {
        return hex(TEST_KEY_HEX);
    }

    private static byte[] testPrefix() {
        return hex(TEST_PREFIX_HEX);
    }

    private static byte[] hex(String value) {
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

    private static void expectReason(
            AuthenticatedDataPlaneV2Exception.Reason expected, CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("expected rejection: " + expected);
        } catch (AuthenticatedDataPlaneV2Exception failure) {
            require(failure.reason() == expected,
                    "expected " + expected + " but received " + failure.reason());
        }
    }

    private static void expectIllegalArgument(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }

    private static void clearAll(byte[]... values) {
        for (byte[] value : values) {
            if (value != null) Arrays.fill(value, (byte) 0);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
