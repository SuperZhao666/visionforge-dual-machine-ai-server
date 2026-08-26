package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Strict typed VFC1 signing request for Host usage-authorization proofs.
 * Canonical JSON is parsed and rebuilt on Android, then only fixed-width
 * structured fields cross the authenticated channel. The Host independently
 * rebuilds the canonical payload before its device key is used.
 */
final class TypedUsageAuthorizationRequestV1 {
    private static final int MAGIC = 0x5655_5331; // "VUS1"
    private static final int VERSION = 1;
    private static final int HEADER_BYTES = 8;
    private static final int HEX128 = 32;
    private static final int SHA256 = 64;

    private static final byte START_CHALLENGE = 1;
    private static final byte START = 2;
    private static final byte START_CANCEL = 3;
    private static final byte HEARTBEAT = 4;
    private static final byte STOP = 5;

    private TypedUsageAuthorizationRequestV1() {}

    static byte[] encode(
            byte[] canonicalPayload,
            DualMachineEntitlementRecord entitlement,
            String authenticatedChannelBindingSha256)
            throws GeneralSecurityException {
        if (canonicalPayload == null || entitlement == null
                || authenticatedChannelBindingSha256 == null) {
            throw new GeneralSecurityException(
                    "typed usage signing context is unavailable");
        }
        try {
            DualMachineStrictJson.Fields fields =
                    DualMachineStrictJson.parseObject(canonicalPayload);
            String domain = fields.string("domain", 1, 80);
            if (DualMachineUsageAuthorizationContract
                    .USAGE_START_CHALLENGE_DOMAIN.equals(domain)) {
                return startChallenge(
                        canonicalPayload, fields, entitlement,
                        authenticatedChannelBindingSha256);
            }
            if (DualMachineUsageAuthorizationContract.USAGE_START_DOMAIN
                    .equals(domain)) {
                return start(
                        canonicalPayload, fields, entitlement,
                        authenticatedChannelBindingSha256);
            }
            if (DualMachineUsageAuthorizationContract
                    .USAGE_START_CANCEL_DOMAIN.equals(domain)) {
                return startCancel(
                        canonicalPayload, fields, entitlement,
                        authenticatedChannelBindingSha256);
            }
            if (DualMachineUsageAuthorizationContract
                    .USAGE_HEARTBEAT_DOMAIN.equals(domain)) {
                return heartbeat(
                        canonicalPayload, fields, entitlement,
                        authenticatedChannelBindingSha256);
            }
            if (DualMachineUsageAuthorizationContract.USAGE_STOP_DOMAIN
                    .equals(domain)) {
                return stop(
                        canonicalPayload, fields, entitlement,
                        authenticatedChannelBindingSha256);
            }
            throw new GeneralSecurityException(
                    "Host usage signing domain is not allowed");
        } catch (IOException | IllegalArgumentException failure) {
            throw new GeneralSecurityException(
                    "Host usage signing payload is malformed", failure);
        }
    }

    private static byte[] startChallenge(
            byte[] canonical,
            DualMachineStrictJson.Fields fields,
            DualMachineEntitlementRecord entitlement,
            String channelBinding) throws IOException,
            GeneralSecurityException {
        fields.requireExactly(
                "channel_binding_sha256", "domain", "entitlement_id",
                "pair_id", "protocol_version", "request_id",
                "request_nonce", "revocation_version");
        DualMachineUsageAuthorizationContract.UsageStartChallenge proof =
                new DualMachineUsageAuthorizationContract
                        .UsageStartChallenge();
        proof.channelBindingSha256 = fields.string(
                "channel_binding_sha256", SHA256, SHA256);
        proof.entitlementId = fields.string(
                "entitlement_id", HEX128, HEX128);
        proof.pairId = fields.string("pair_id", HEX128, HEX128);
        proof.protocolVersion = (int) fields.integer(
                "protocol_version", 2, 2);
        proof.requestId = fields.string("request_id", HEX128, HEX128);
        proof.requestNonce = fields.string(
                "request_nonce", HEX128, HEX128);
        proof.revocationVersion = fields.integer(
                "revocation_version", 1, Long.MAX_VALUE);
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .usageStartChallenge(proof);
        requireCanonicalAndContext(
                canonical, rebuilt, entitlement, channelBinding,
                proof.entitlementId, proof.pairId, proof.protocolVersion,
                proof.revocationVersion, proof.channelBindingSha256);
        ByteBuffer wire = header(START_CHALLENGE, HEADER_BYTES + 204);
        putAscii(wire, proof.channelBindingSha256, SHA256);
        putAscii(wire, proof.entitlementId, HEX128);
        putAscii(wire, proof.pairId, HEX128);
        wire.putInt(proof.protocolVersion);
        putAscii(wire, proof.requestId, HEX128);
        putAscii(wire, proof.requestNonce, HEX128);
        wire.putLong(proof.revocationVersion);
        return finish(wire);
    }

    private static byte[] start(
            byte[] canonical,
            DualMachineStrictJson.Fields fields,
            DualMachineEntitlementRecord entitlement,
            String channelBinding) throws IOException,
            GeneralSecurityException {
        fields.requireExactly(
                "android_frames_total", "android_runtime_ready",
                "channel_binding_sha256", "domain", "entitlement_id",
                "host_frames_total", "host_runtime_ready", "pair_id",
                "protocol_version", "request_id", "request_nonce",
                "revocation_version", "start_challenge_id",
                "start_challenge_token_sha256");
        DualMachineUsageAuthorizationContract.UsageStart proof =
                new DualMachineUsageAuthorizationContract.UsageStart();
        proof.androidFramesTotal = fields.integer(
                "android_frames_total", 0, Long.MAX_VALUE);
        proof.androidRuntimeReady = fields.bool("android_runtime_ready");
        proof.channelBindingSha256 = fields.string(
                "channel_binding_sha256", SHA256, SHA256);
        proof.entitlementId = fields.string(
                "entitlement_id", HEX128, HEX128);
        proof.hostFramesTotal = fields.integer(
                "host_frames_total", 0, Long.MAX_VALUE);
        proof.hostRuntimeReady = fields.bool("host_runtime_ready");
        proof.pairId = fields.string("pair_id", HEX128, HEX128);
        proof.protocolVersion = (int) fields.integer(
                "protocol_version", 2, 2);
        proof.requestId = fields.string("request_id", HEX128, HEX128);
        proof.requestNonce = fields.string(
                "request_nonce", HEX128, HEX128);
        proof.revocationVersion = fields.integer(
                "revocation_version", 1, Long.MAX_VALUE);
        proof.startChallengeId = fields.string(
                "start_challenge_id", HEX128, HEX128);
        proof.startChallengeTokenSha256 = fields.string(
                "start_challenge_token_sha256", SHA256, SHA256);
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .usageStart(proof);
        requireCanonicalAndContext(
                canonical, rebuilt, entitlement, channelBinding,
                proof.entitlementId, proof.pairId, proof.protocolVersion,
                proof.revocationVersion, proof.channelBindingSha256);
        ByteBuffer wire = header(START, HEADER_BYTES + 318);
        wire.putLong(proof.androidFramesTotal);
        wire.put((byte) (proof.androidRuntimeReady ? 1 : 0));
        putAscii(wire, proof.channelBindingSha256, SHA256);
        putAscii(wire, proof.entitlementId, HEX128);
        wire.putLong(proof.hostFramesTotal);
        wire.put((byte) (proof.hostRuntimeReady ? 1 : 0));
        putAscii(wire, proof.pairId, HEX128);
        wire.putInt(proof.protocolVersion);
        putAscii(wire, proof.requestId, HEX128);
        putAscii(wire, proof.requestNonce, HEX128);
        wire.putLong(proof.revocationVersion);
        putAscii(wire, proof.startChallengeId, HEX128);
        putAscii(wire, proof.startChallengeTokenSha256, SHA256);
        return finish(wire);
    }

    private static byte[] startCancel(
            byte[] canonical,
            DualMachineStrictJson.Fields fields,
            DualMachineEntitlementRecord entitlement,
            String channelBinding) throws IOException,
            GeneralSecurityException {
        fields.requireExactly(
                "channel_binding_sha256", "domain", "entitlement_id",
                "pair_id", "protocol_version", "request_id",
                "request_nonce", "revocation_version",
                "start_request_id");
        DualMachineUsageAuthorizationContract.UsageStartCancel proof =
                new DualMachineUsageAuthorizationContract
                        .UsageStartCancel();
        proof.channelBindingSha256 = fields.string(
                "channel_binding_sha256", SHA256, SHA256);
        proof.entitlementId = fields.string(
                "entitlement_id", HEX128, HEX128);
        proof.pairId = fields.string("pair_id", HEX128, HEX128);
        proof.protocolVersion = (int) fields.integer(
                "protocol_version", 2, 2);
        proof.requestId = fields.string("request_id", HEX128, HEX128);
        proof.requestNonce = fields.string(
                "request_nonce", HEX128, HEX128);
        proof.revocationVersion = fields.integer(
                "revocation_version", 1, Long.MAX_VALUE);
        proof.startRequestId = fields.string(
                "start_request_id", HEX128, HEX128);
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .usageStartCancel(proof);
        requireCanonicalAndContext(
                canonical, rebuilt, entitlement, channelBinding,
                proof.entitlementId, proof.pairId, proof.protocolVersion,
                proof.revocationVersion, proof.channelBindingSha256);
        ByteBuffer wire = header(START_CANCEL, HEADER_BYTES + 236);
        putAscii(wire, proof.channelBindingSha256, SHA256);
        putAscii(wire, proof.entitlementId, HEX128);
        putAscii(wire, proof.pairId, HEX128);
        wire.putInt(proof.protocolVersion);
        putAscii(wire, proof.requestId, HEX128);
        putAscii(wire, proof.requestNonce, HEX128);
        wire.putLong(proof.revocationVersion);
        putAscii(wire, proof.startRequestId, HEX128);
        return finish(wire);
    }

    private static byte[] heartbeat(
            byte[] canonical,
            DualMachineStrictJson.Fields fields,
            DualMachineEntitlementRecord entitlement,
            String channelBinding) throws IOException,
            GeneralSecurityException {
        fields.requireExactly(
                "android_frames_total", "channel_binding_sha256", "domain",
                "entitlement_id", "host_frames_total", "pair_id",
                "previous_lease_sha256", "protocol_version", "request_id",
                "request_nonce", "revocation_version", "sequence",
                "session_id");
        DualMachineUsageAuthorizationContract.UsageHeartbeat proof =
                new DualMachineUsageAuthorizationContract.UsageHeartbeat();
        proof.androidFramesTotal = fields.integer(
                "android_frames_total", 0, Long.MAX_VALUE);
        proof.channelBindingSha256 = fields.string(
                "channel_binding_sha256", SHA256, SHA256);
        proof.entitlementId = fields.string(
                "entitlement_id", HEX128, HEX128);
        proof.hostFramesTotal = fields.integer(
                "host_frames_total", 0, Long.MAX_VALUE);
        proof.pairId = fields.string("pair_id", HEX128, HEX128);
        proof.previousLeaseSha256 = fields.string(
                "previous_lease_sha256", SHA256, SHA256);
        proof.protocolVersion = (int) fields.integer(
                "protocol_version", 2, 2);
        proof.requestId = fields.string("request_id", HEX128, HEX128);
        proof.requestNonce = fields.string(
                "request_nonce", HEX128, HEX128);
        proof.revocationVersion = fields.integer(
                "revocation_version", 1, Long.MAX_VALUE);
        proof.sequence = fields.integer("sequence", 1, Long.MAX_VALUE);
        proof.sessionId = fields.string("session_id", HEX128, HEX128);
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .usageHeartbeat(proof);
        requireCanonicalAndContext(
                canonical, rebuilt, entitlement, channelBinding,
                proof.entitlementId, proof.pairId, proof.protocolVersion,
                proof.revocationVersion, proof.channelBindingSha256);
        ByteBuffer wire = header(HEARTBEAT, HEADER_BYTES + 324);
        wire.putLong(proof.androidFramesTotal);
        putAscii(wire, proof.channelBindingSha256, SHA256);
        putAscii(wire, proof.entitlementId, HEX128);
        wire.putLong(proof.hostFramesTotal);
        putAscii(wire, proof.pairId, HEX128);
        putAscii(wire, proof.previousLeaseSha256, SHA256);
        wire.putInt(proof.protocolVersion);
        putAscii(wire, proof.requestId, HEX128);
        putAscii(wire, proof.requestNonce, HEX128);
        wire.putLong(proof.revocationVersion);
        wire.putLong(proof.sequence);
        putAscii(wire, proof.sessionId, HEX128);
        return finish(wire);
    }

    private static byte[] stop(
            byte[] canonical,
            DualMachineStrictJson.Fields fields,
            DualMachineEntitlementRecord entitlement,
            String channelBinding) throws IOException,
            GeneralSecurityException {
        fields.requireExactly(
                "channel_binding_sha256", "domain", "entitlement_id",
                "pair_id", "previous_lease_sha256", "protocol_version",
                "request_id", "request_nonce", "revocation_version",
                "session_id");
        DualMachineUsageAuthorizationContract.UsageStop proof =
                new DualMachineUsageAuthorizationContract.UsageStop();
        proof.channelBindingSha256 = fields.string(
                "channel_binding_sha256", SHA256, SHA256);
        proof.entitlementId = fields.string(
                "entitlement_id", HEX128, HEX128);
        proof.pairId = fields.string("pair_id", HEX128, HEX128);
        proof.previousLeaseSha256 = fields.string(
                "previous_lease_sha256", SHA256, SHA256);
        proof.protocolVersion = (int) fields.integer(
                "protocol_version", 2, 2);
        proof.requestId = fields.string("request_id", HEX128, HEX128);
        proof.requestNonce = fields.string(
                "request_nonce", HEX128, HEX128);
        proof.revocationVersion = fields.integer(
                "revocation_version", 1, Long.MAX_VALUE);
        proof.sessionId = fields.string("session_id", HEX128, HEX128);
        byte[] rebuilt = DualMachineUsageAuthorizationContract
                .usageStop(proof);
        requireCanonicalAndContext(
                canonical, rebuilt, entitlement, channelBinding,
                proof.entitlementId, proof.pairId, proof.protocolVersion,
                proof.revocationVersion, proof.channelBindingSha256);
        ByteBuffer wire = header(STOP, HEADER_BYTES + 300);
        putAscii(wire, proof.channelBindingSha256, SHA256);
        putAscii(wire, proof.entitlementId, HEX128);
        putAscii(wire, proof.pairId, HEX128);
        putAscii(wire, proof.previousLeaseSha256, SHA256);
        wire.putInt(proof.protocolVersion);
        putAscii(wire, proof.requestId, HEX128);
        putAscii(wire, proof.requestNonce, HEX128);
        wire.putLong(proof.revocationVersion);
        putAscii(wire, proof.sessionId, HEX128);
        return finish(wire);
    }

    private static void requireCanonicalAndContext(
            byte[] supplied,
            byte[] rebuilt,
            DualMachineEntitlementRecord entitlement,
            String expectedChannelBinding,
            String entitlementId,
            String pairId,
            int protocolVersion,
            long revocationVersion,
            String channelBinding) throws GeneralSecurityException {
        try {
            if (!MessageDigest.isEqual(supplied, rebuilt)
                    || !entitlement.entitlementId.equals(entitlementId)
                    || !entitlement.pairId.equals(pairId)
                    || entitlement.protocolVersion != protocolVersion
                    || entitlement.revocationVersion != revocationVersion
                    || !expectedChannelBinding.equals(channelBinding)) {
                throw new GeneralSecurityException(
                        "typed usage signing context changed");
            }
        } finally {
            Arrays.fill(rebuilt, (byte) 0);
        }
    }

    private static ByteBuffer header(byte kind, int capacity) {
        return ByteBuffer.allocate(capacity)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(MAGIC)
                .put((byte) VERSION)
                .put(kind)
                .putShort((short) 0);
    }

    private static void putAscii(
            ByteBuffer destination, String value, int length)
            throws GeneralSecurityException {
        byte[] bytes = value == null
                ? null : value.getBytes(StandardCharsets.US_ASCII);
        if (bytes == null || bytes.length != length) {
            throw new GeneralSecurityException(
                    "typed usage signing field is malformed");
        }
        destination.put(bytes);
        Arrays.fill(bytes, (byte) 0);
    }

    private static byte[] finish(ByteBuffer destination)
            throws GeneralSecurityException {
        if (destination.hasRemaining()) {
            Arrays.fill(destination.array(), (byte) 0);
            throw new GeneralSecurityException(
                    "typed usage signing frame length is invalid");
        }
        return destination.array();
    }
}
