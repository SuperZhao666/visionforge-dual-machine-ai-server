package com.visionforge.inferencebenchmark.handshake;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Canonical dual proof-of-possession contract for pair-generation v1.
 *
 * <p>The two immutable payload owners are deliberately typed. Callers cannot
 * supply a digest, connection id or final claim bag: all derived fields are
 * rebuilt from the validated challenge request, server nonce and canonical
 * proposal before either device identity is allowed to sign.</p>
 */
public final class PairGenerationPopV1 {
    public static final int PROTOCOL_VERSION = 2;
    public static final int PROPOSAL_VERSION = 1;
    public static final int SHA256_BYTES = 32;
    public static final int NONCE_BYTES = 32;
    public static final int MAXIMUM_CANONICAL_PROPOSAL_BYTES = 503;

    private static final String CHALLENGE_REQUEST_DOMAIN =
            "visionforge-pair-generation-challenge-request-v1";
    private static final String FINAL_CREDENTIAL_PROOF_DOMAIN =
            "visionforge-pair-generation-final-credential-proof-v1";
    private static final String CONNECTION_ID_DERIVATION_DOMAIN =
            "visionforge-pair-generation-connection-id-derivation-v1";

    private PairGenerationPopV1() {
    }

    public static ChallengeRequest buildChallengeRequest(ChallengeFields fields)
            throws PopException {
        ChallengeFields checked = requireFields(fields);
        String canonical = "{"
                + "\"allocation_request_id\":\""
                + checked.allocationRequestId + "\","
                + "\"android_identity_spki_sha256\":\""
                + checked.androidIdentitySpkiSha256 + "\","
                + "\"binding_id\":\"" + checked.bindingId + "\","
                + "\"binding_revision\":" + checked.bindingRevision + ","
                + "\"domain\":\"" + CHALLENGE_REQUEST_DOMAIN + "\","
                + "\"entitlement_id\":\"" + checked.entitlementId + "\","
                + "\"host_identity_spki_sha256\":\""
                + checked.hostIdentitySpkiSha256 + "\","
                + "\"pair_id\":\"" + checked.pairId + "\","
                + "\"protocol_version\":" + PROTOCOL_VERSION + ","
                + "\"request_id\":\"" + checked.requestId + "\","
                + "\"revocation_version\":" + checked.revocationVersion
                + "}";
        byte[] canonicalBytes = strictAscii(canonical);
        return new ChallengeRequest(
                checked, canonicalBytes, sha256(canonicalBytes));
    }

    public static long deriveConnectionId(
            byte[] serverNonce,
            String challengeId,
            byte[] hostNonce,
            byte[] androidNonce,
            String pairId,
            String hostIdentitySpkiSha256,
            String androidIdentitySpkiSha256) throws PopException {
        byte[] checkedServerNonce = fixedNonzero(serverNonce, NONCE_BYTES);
        byte[] checkedHostNonce = fixedNonzero(hostNonce, NONCE_BYTES);
        byte[] checkedAndroidNonce = fixedNonzero(androidNonce, NONCE_BYTES);
        try {
            if (MessageDigest.isEqual(checkedHostNonce, checkedAndroidNonce)) {
                throw failure(ErrorCode.NONCE_ROLES_INVALID);
            }
            String checkedChallengeId = identifier(challengeId);
            String checkedPairId = identifier(pairId);
            String checkedHostIdentity = sha256Hex(hostIdentitySpkiSha256);
            String checkedAndroidIdentity = sha256Hex(androidIdentitySpkiSha256);
            if (constantTimeAsciiEqual(
                    checkedHostIdentity, checkedAndroidIdentity)) {
                throw failure(ErrorCode.IDENTITY_ROLES_INVALID);
            }
            String seed = "{"
                    + "\"android_identity_spki_sha256\":\""
                    + checkedAndroidIdentity + "\","
                    + "\"android_nonce\":\"" + hex(checkedAndroidNonce) + "\","
                    + "\"challenge_id\":\"" + checkedChallengeId + "\","
                    + "\"domain\":\"" + CONNECTION_ID_DERIVATION_DOMAIN + "\","
                    + "\"host_identity_spki_sha256\":\""
                    + checkedHostIdentity + "\","
                    + "\"host_nonce\":\"" + hex(checkedHostNonce) + "\","
                    + "\"pair_id\":\"" + checkedPairId + "\","
                    + "\"proposal_version\":" + PROPOSAL_VERSION + ","
                    + "\"protocol_version\":" + PROTOCOL_VERSION
                    + "}";
            byte[] digest = hmacSha256(
                    checkedServerNonce, strictAscii(seed));
            try {
                long connectionId = ByteBuffer.wrap(digest).getLong()
                        & Long.MAX_VALUE;
                if (connectionId == 0L) {
                    throw failure(ErrorCode.CONNECTION_ID_ZERO);
                }
                return connectionId;
            } finally {
                clear(digest);
            }
        } finally {
            clear(checkedServerNonce);
            clear(checkedHostNonce);
            clear(checkedAndroidNonce);
        }
    }

    public static FinalCredentialProof buildFinalCredentialProof(
            ChallengeRequest request,
            String challengeId,
            long challengeExpiresAtEpoch,
            byte[] serverNonce,
            PairGenerationProposalV1 proposal) throws PopException {
        ChallengeRequest checkedRequest = requireRequest(request);
        String checkedChallengeId = identifier(challengeId);
        long checkedExpiry = positiveSigned64(challengeExpiresAtEpoch);
        byte[] checkedServerNonce = fixedNonzero(serverNonce, NONCE_BYTES);
        byte[] proposalCanonical = null;
        byte[] proposalHash = null;
        byte[] serverNonceHash = null;
        try {
            PairGenerationProposalV1 checkedProposal = requireProposal(proposal);
            proposalCanonical = checkedProposal.canonicalEncoding();
            ChallengeFields fields = checkedRequest.fields;
            if (!fields.pairId.equals(checkedProposal.pairId())
                    || !constantTimeHexEqual(
                    fields.hostIdentitySpkiSha256,
                    checkedProposal.hostIdentitySpkiSha256())
                    || !constantTimeHexEqual(
                    fields.androidIdentitySpkiSha256,
                    checkedProposal.androidIdentitySpkiSha256())) {
                throw failure(ErrorCode.PROPOSAL_BINDING_INVALID);
            }
            long derivedConnectionId = deriveConnectionId(
                    checkedServerNonce,
                    checkedChallengeId,
                    checkedProposal.hostNonce(),
                    checkedProposal.androidNonce(),
                    fields.pairId,
                    fields.hostIdentitySpkiSha256,
                    fields.androidIdentitySpkiSha256);
            if (checkedProposal.connectionId() != derivedConnectionId) {
                throw failure(ErrorCode.CONNECTION_ID_MISMATCH);
            }
            proposalHash = sha256(proposalCanonical);
            serverNonceHash = sha256(checkedServerNonce);
            String requestHashHex = hex(checkedRequest.payloadSha256);
            String proposalHashHex = hex(proposalHash);
            String serverNonceHashHex = hex(serverNonceHash);
            String canonical = "{"
                    + "\"allocation_request_id\":\""
                    + fields.allocationRequestId + "\","
                    + "\"android_identity_spki_sha256\":\""
                    + fields.androidIdentitySpkiSha256 + "\","
                    + "\"binding_id\":\"" + fields.bindingId + "\","
                    + "\"binding_revision\":" + fields.bindingRevision + ","
                    + "\"challenge_expires_at_epoch\":"
                    + checkedExpiry + ","
                    + "\"challenge_id\":\"" + checkedChallengeId + "\","
                    + "\"challenge_request_id\":\""
                    + fields.requestId + "\","
                    + "\"challenge_request_payload_sha256\":\""
                    + requestHashHex + "\","
                    + "\"connection_id\":" + derivedConnectionId + ","
                    + "\"domain\":\"" + FINAL_CREDENTIAL_PROOF_DOMAIN + "\","
                    + "\"entitlement_id\":\"" + fields.entitlementId + "\","
                    + "\"host_identity_spki_sha256\":\""
                    + fields.hostIdentitySpkiSha256 + "\","
                    + "\"pair_id\":\"" + fields.pairId + "\","
                    + "\"proposal_version\":" + PROPOSAL_VERSION + ","
                    + "\"protocol_version\":" + PROTOCOL_VERSION + ","
                    + "\"revocation_version\":" + fields.revocationVersion + ","
                    + "\"server_nonce_sha256\":\""
                    + serverNonceHashHex + "\","
                    + "\"transcript_proposal_sha256\":\""
                    + proposalHashHex + "\"}"
                    ;
            byte[] canonicalBytes = strictAscii(canonical);
            return new FinalCredentialProof(
                    checkedRequest,
                    checkedChallengeId,
                    checkedExpiry,
                    derivedConnectionId,
                    serverNonceHashHex,
                    proposalHashHex,
                    canonicalBytes,
                    sha256(canonicalBytes));
        } finally {
            clear(checkedServerNonce);
            clear(proposalCanonical);
            clear(proposalHash);
            clear(serverNonceHash);
        }
    }

    public static final class ChallengeFields {
        public final String requestId;
        public final String allocationRequestId;
        public final String entitlementId;
        public final String pairId;
        public final String bindingId;
        public final long bindingRevision;
        public final long revocationVersion;
        public final String hostIdentitySpkiSha256;
        public final String androidIdentitySpkiSha256;

        public ChallengeFields(
                String requestId,
                String allocationRequestId,
                String entitlementId,
                String pairId,
                String bindingId,
                long bindingRevision,
                long revocationVersion,
                String hostIdentitySpkiSha256,
                String androidIdentitySpkiSha256) throws PopException {
            this.requestId = identifier(requestId);
            this.allocationRequestId = identifier(allocationRequestId);
            this.entitlementId = identifier(entitlementId);
            this.pairId = identifier(pairId);
            this.bindingId = identifier(bindingId);
            this.bindingRevision = positiveSigned64(bindingRevision);
            this.revocationVersion = positiveSigned64(revocationVersion);
            this.hostIdentitySpkiSha256 = sha256Hex(
                    hostIdentitySpkiSha256);
            this.androidIdentitySpkiSha256 = sha256Hex(
                    androidIdentitySpkiSha256);
            if (constantTimeAsciiEqual(
                    this.hostIdentitySpkiSha256,
                    this.androidIdentitySpkiSha256)) {
                throw failure(ErrorCode.IDENTITY_ROLES_INVALID);
            }
        }
    }

    public static final class ChallengeRequest {
        private final ChallengeFields fields;
        private final byte[] canonicalBytes;
        private final byte[] payloadSha256;

        private ChallengeRequest(
                ChallengeFields fields,
                byte[] canonicalBytes,
                byte[] payloadSha256) {
            this.fields = fields;
            this.canonicalBytes = canonicalBytes;
            this.payloadSha256 = payloadSha256;
        }

        public ChallengeFields fields() {
            return fields;
        }

        public byte[] canonicalBytes() {
            return canonicalBytes.clone();
        }

        public byte[] payloadSha256() {
            return payloadSha256.clone();
        }
    }

    public static final class FinalCredentialProof {
        private final ChallengeRequest challengeRequest;
        private final String challengeId;
        private final long challengeExpiresAtEpoch;
        private final long connectionId;
        private final String serverNonceSha256;
        private final String transcriptProposalSha256;
        private final byte[] canonicalBytes;
        private final byte[] payloadSha256;

        private FinalCredentialProof(
                ChallengeRequest challengeRequest,
                String challengeId,
                long challengeExpiresAtEpoch,
                long connectionId,
                String serverNonceSha256,
                String transcriptProposalSha256,
                byte[] canonicalBytes,
                byte[] payloadSha256) {
            this.challengeRequest = challengeRequest;
            this.challengeId = challengeId;
            this.challengeExpiresAtEpoch = challengeExpiresAtEpoch;
            this.connectionId = connectionId;
            this.serverNonceSha256 = serverNonceSha256;
            this.transcriptProposalSha256 = transcriptProposalSha256;
            this.canonicalBytes = canonicalBytes;
            this.payloadSha256 = payloadSha256;
        }

        public ChallengeRequest challengeRequest() {
            return challengeRequest;
        }

        public String challengeId() {
            return challengeId;
        }

        public long challengeExpiresAtEpoch() {
            return challengeExpiresAtEpoch;
        }

        public long connectionId() {
            return connectionId;
        }

        public String serverNonceSha256() {
            return serverNonceSha256;
        }

        public String transcriptProposalSha256() {
            return transcriptProposalSha256;
        }

        public byte[] canonicalBytes() {
            return canonicalBytes.clone();
        }

        public byte[] payloadSha256() {
            return payloadSha256.clone();
        }
    }

    public enum ErrorCode {
        REQUEST_INVALID("pair_generation_pop_request_invalid"),
        IDENTIFIER_INVALID("pair_generation_pop_identifier_invalid"),
        IDENTITY_HASH_INVALID("pair_generation_pop_identity_hash_invalid"),
        IDENTITY_ROLES_INVALID("pair_generation_pop_identity_roles_invalid"),
        SIGNED_64_INVALID("pair_generation_pop_signed_64_invalid"),
        NONCE_INVALID("pair_generation_pop_nonce_invalid"),
        NONCE_ROLES_INVALID("pair_generation_pop_nonce_roles_invalid"),
        PROPOSAL_INVALID("pair_generation_pop_proposal_invalid"),
        PROPOSAL_BINDING_INVALID("pair_generation_pop_proposal_binding_invalid"),
        REQUEST_INTEGRITY_INVALID("pair_generation_pop_request_integrity_invalid"),
        CONNECTION_ID_ZERO("pair_generation_pop_connection_id_zero"),
        CONNECTION_ID_MISMATCH("pair_generation_pop_connection_id_mismatch"),
        CRYPTO_UNAVAILABLE("pair_generation_pop_crypto_unavailable");

        private final String wireName;

        ErrorCode(String wireName) {
            this.wireName = wireName;
        }
    }

    public static final class PopException extends GeneralSecurityException {
        private static final long serialVersionUID = 1L;
        private final ErrorCode code;

        private PopException(ErrorCode code) {
            super(code.wireName);
            this.code = code;
        }

        public ErrorCode code() {
            return code;
        }
    }

    private static ChallengeFields requireFields(ChallengeFields fields)
            throws PopException {
        if (fields == null) throw failure(ErrorCode.REQUEST_INVALID);
        return new ChallengeFields(
                fields.requestId,
                fields.allocationRequestId,
                fields.entitlementId,
                fields.pairId,
                fields.bindingId,
                fields.bindingRevision,
                fields.revocationVersion,
                fields.hostIdentitySpkiSha256,
                fields.androidIdentitySpkiSha256);
    }

    private static ChallengeRequest requireRequest(ChallengeRequest request)
            throws PopException {
        if (request == null) throw failure(ErrorCode.REQUEST_INVALID);
        ChallengeRequest rebuilt = buildChallengeRequest(request.fields);
        if (!MessageDigest.isEqual(
                request.canonicalBytes, rebuilt.canonicalBytes)
                || !MessageDigest.isEqual(
                request.payloadSha256, rebuilt.payloadSha256)) {
            throw failure(ErrorCode.REQUEST_INTEGRITY_INVALID);
        }
        return rebuilt;
    }

    private static PairGenerationProposalV1 requireProposal(
            PairGenerationProposalV1 proposal) throws PopException {
        if (proposal == null) throw failure(ErrorCode.PROPOSAL_INVALID);
        byte[] canonical = proposal.canonicalEncoding();
        try {
            if (canonical.length == 0
                    || canonical.length > MAXIMUM_CANONICAL_PROPOSAL_BYTES) {
                throw failure(ErrorCode.PROPOSAL_INVALID);
            }
            PairGenerationProposalV1 reparsed =
                    PairGenerationProposalV1.parse(canonical);
            if (!MessageDigest.isEqual(
                    canonical, reparsed.canonicalEncoding())) {
                throw failure(ErrorCode.PROPOSAL_INVALID);
            }
            return reparsed;
        } catch (PairGenerationProposalV1.ProposalException rejected) {
            throw failure(ErrorCode.PROPOSAL_INVALID);
        } finally {
            clear(canonical);
        }
    }

    private static String identifier(String value) throws PopException {
        return lowerHex(value, 32, ErrorCode.IDENTIFIER_INVALID);
    }

    private static String sha256Hex(String value) throws PopException {
        return lowerHex(value, 64, ErrorCode.IDENTITY_HASH_INVALID);
    }

    private static String lowerHex(
            String value, int length, ErrorCode code) throws PopException {
        if (value == null || value.length() != length) throw failure(code);
        boolean nonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw failure(code);
            }
            nonzero |= character != '0';
        }
        if (!nonzero) throw failure(code);
        return value;
    }

    private static long positiveSigned64(long value) throws PopException {
        if (value <= 0L) throw failure(ErrorCode.SIGNED_64_INVALID);
        return value;
    }

    private static byte[] fixedNonzero(byte[] value, int length)
            throws PopException {
        if (value == null || value.length != length) {
            throw failure(ErrorCode.NONCE_INVALID);
        }
        byte[] copy = value.clone();
        boolean nonzero = false;
        for (byte current : copy) nonzero |= current != 0;
        if (!nonzero) {
            clear(copy);
            throw failure(ErrorCode.NONCE_INVALID);
        }
        return copy;
    }

    private static byte[] strictAscii(String value) throws PopException {
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        if (!value.equals(new String(encoded, StandardCharsets.US_ASCII))) {
            clear(encoded);
            throw failure(ErrorCode.REQUEST_INVALID);
        }
        return encoded;
    }

    private static byte[] sha256(byte[] value) throws PopException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            boolean nonzero = false;
            for (byte current : digest) nonzero |= current != 0;
            if (digest.length != SHA256_BYTES || !nonzero) {
                clear(digest);
                throw failure(ErrorCode.CRYPTO_UNAVAILABLE);
            }
            return digest;
        } catch (GeneralSecurityException providerFailure) {
            throw failure(ErrorCode.CRYPTO_UNAVAILABLE);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] message)
            throws PopException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] digest = mac.doFinal(message);
            if (digest.length != SHA256_BYTES) {
                clear(digest);
                throw failure(ErrorCode.CRYPTO_UNAVAILABLE);
            }
            return digest;
        } catch (GeneralSecurityException providerFailure) {
            throw failure(ErrorCode.CRYPTO_UNAVAILABLE);
        }
    }

    private static boolean constantTimeAsciiEqual(String left, String right) {
        byte[] leftBytes = left.getBytes(StandardCharsets.US_ASCII);
        byte[] rightBytes = right.getBytes(StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(leftBytes, rightBytes);
        } finally {
            clear(leftBytes);
            clear(rightBytes);
        }
    }

    private static boolean constantTimeHexEqual(
            String expectedHex, byte[] actualBytes) {
        byte[] expectedBytes = decodeHex(expectedHex);
        try {
            return MessageDigest.isEqual(expectedBytes, actualBytes);
        } finally {
            clear(expectedBytes);
        }
    }

    private static byte[] decodeHex(String value) {
        byte[] decoded = new byte[value.length() / 2];
        for (int index = 0; index < decoded.length; index++) {
            decoded[index] = (byte) ((Character.digit(
                    value.charAt(index * 2), 16) << 4)
                    | Character.digit(value.charAt(index * 2 + 1), 16));
        }
        return decoded;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte current : value) {
            result.append(Character.forDigit((current >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(current & 0x0f, 16));
        }
        return result.toString();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    private static PopException failure(ErrorCode code) {
        return new PopException(code);
    }
}
