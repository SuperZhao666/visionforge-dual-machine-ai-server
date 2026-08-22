package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Strict HTTP adapter for the independent dual-machine card sidecar.
 *
 * <p>Methods perform exactly one explicit POST each. There is no automatic
 * start, retry, heartbeat or stop behavior in this class.</p>
 */
public final class DualMachineSidecarHttpClient
        implements DualMachineSidecarPort {
    public interface PostJson {
        byte[] postJson(String apiPath, byte[] canonicalJson)
                throws IOException;
    }

    private static final String API_PREFIX = "/api/dual-machine/v1/";
    private static final String ACTIVATION_CHALLENGE_PATH =
            API_PREFIX + "license-activations/challenges";
    private static final String ACTIVATION_CONFIRM_PATH =
            API_PREFIX + "license-activations/confirm";
    private static final String PAIR_GENERATION_CHALLENGE_PATH =
            API_PREFIX + "pair-generations/challenges";
    private static final String PAIR_GENERATION_CREDENTIAL_PATH =
            API_PREFIX + "pair-generations/credentials";
    private static final String START_CHALLENGE_PATH =
            API_PREFIX + "usage-sessions/start-challenges";
    private static final String START_PATH =
            API_PREFIX + "usage-sessions/start";
    private static final String START_CANCELLATION_PATH =
            API_PREFIX + "usage-sessions/start-cancellations";
    private static final long MAXIMUM_LEASE_SECONDS = 10L;

    private final PostJson transport;

    public DualMachineSidecarHttpClient(
            DualMachineHttpsJsonTransport transport) {
        this(requireTransport(transport));
    }

    public DualMachineSidecarHttpClient(PostJson transport) {
        if (transport == null) {
            throw new IllegalArgumentException("transport is required");
        }
        this.transport = transport;
    }

    @Override
    public ActivationChallengeResponse createActivationChallenge(
            ActivationChallengeRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        byte[] response = post(
                ACTIVATION_CHALLENGE_PATH,
                activationChallengeJson(request));
        return parseActivationChallenge(response, request);
    }

    @Override
    public ActivationResponse confirmActivation(
            ActivationConfirmationRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parseActivation(post(
                ACTIVATION_CONFIRM_PATH,
                activationConfirmationJson(request)));
    }

    @Override
    public EntitlementStatusResponse fetchEntitlementStatus(
            EntitlementStatusRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        String path = API_PREFIX + "entitlements/"
                + request.proof.entitlementId + "/status";
        return parseEntitlementStatus(
                post(path, entitlementStatusJson(request)), request);
    }

    @Override
    public PairGenerationChallengeResponse createPairGenerationChallenge(
            PairGenerationChallengeRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parsePairGenerationChallenge(
                post(PAIR_GENERATION_CHALLENGE_PATH,
                        pairGenerationChallengeJson(request)),
                request);
    }

    @Override
    public PairGenerationCredentialResponse issuePairGenerationCredential(
            PairGenerationCredentialRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parsePairGenerationCredential(
                post(PAIR_GENERATION_CREDENTIAL_PATH,
                        pairGenerationCredentialJson(request)),
                request);
    }

    @Override
    public StartChallengeResponse createStartChallenge(
            StartChallengeRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parseStartChallenge(post(
                START_CHALLENGE_PATH,
                startChallengeJson(request)));
    }

    @Override
    public UsageLeaseResponse startUsage(StartUsageRequest request)
            throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parseUsageLease(
                post(START_PATH, startUsageJson(request)),
                request.proof,
                null,
                0L);
    }

    @Override
    public StartCancellationResponse cancelStart(
            StartCancellationRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        return parseStartCancellation(
                post(START_CANCELLATION_PATH,
                        startCancellationJson(request)),
                request);
    }

    @Override
    public UsageLeaseResponse heartbeat(HeartbeatRequest request)
            throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        String path = API_PREFIX + "usage-sessions/"
                + request.sessionId + "/heartbeat";
        return parseUsageLease(
                post(path, heartbeatJson(request)),
                request.proof,
                request.sessionId,
                request.sequence);
    }

    @Override
    public StopResponse stop(StopRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        String path = API_PREFIX + "usage-sessions/"
                + request.sessionId + "/stop";
        return parseStop(post(path, stopJson(request)), request);
    }

    private byte[] post(String path, byte[] request) throws IOException {
        try {
            return transport.postJson(path, request);
        } catch (DualMachineHttpsJsonTransport.SidecarHttpException rejected) {
            // Deliberately sever the cause so a server error body can never
            // enter exception rendering, crash reports or logs.
            throw new DualMachineSidecarPort.RejectedException(
                    rejected.statusCode,
                    safeRejectionCode(rejected.responseBody()));
        }
    }

    private static String safeRejectionCode(byte[] responseBody) {
        try {
            DualMachineStrictJson.Fields fields =
                    DualMachineStrictJson.parseObject(responseBody);
            fields.requireExactly("ok", "error");
            if (fields.bool("ok")) return "";
            String code = fields.string("error", 1, 64);
            if ("activation_challenge_invalid".equals(code)
                    || "license_bound_to_another_device".equals(code)
                    || "license_device_binding_inconsistent".equals(code)) {
                return code;
            }
            return "";
        } catch (IOException | RuntimeException malformed) {
            return "";
        }
    }

    private static ActivationChallengeResponse parseActivationChallenge(
            byte[] encoded,
            ActivationChallengeRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "activation_mode",
                "target_entitlement_id",
                "android_device_profile_sha256",
                "challenge_id",
                "challenge_token",
                "challenge_expires_at_epoch",
                "proof_payload_b64");
        requireOk(fields);
        String activationMode = fields.string(
                "activation_mode", 8, 11);
        if (!isActivationMode(activationMode)) {
            throw DualMachineStrictJson.contractError();
        }
        String targetEntitlementId = fields.string(
                "target_entitlement_id", 0, 32);
        if (DualMachineUsageAuthorizationContract.ACTIVATION_MODE_ACTIVATE
                .equals(activationMode)) {
            if (!targetEntitlementId.isEmpty()) {
                throw DualMachineStrictJson.contractError();
            }
        } else {
            targetEntitlementId = responseHex128(targetEntitlementId);
        }
        String profileSha256 = responseSha256(fields.string(
                "android_device_profile_sha256", 64, 64));
        byte[] profileJson = request.android.deviceProfile == null
                ? "{}".getBytes(StandardCharsets.UTF_8)
                : request.android.deviceProfile.canonicalJson();
        if (!profileSha256.equals(sha256Hex(profileJson))) {
            throw DualMachineStrictJson.contractError();
        }
        String challengeId = responseHex128(
                fields.string("challenge_id", 32, 32));
        String challengeToken = responseChallengeToken(
                fields.string("challenge_token", 43, 43));
        long expiresAt = fields.integer(
                "challenge_expires_at_epoch", 1L, Long.MAX_VALUE);
        byte[] suppliedProof = responseBase64(
                fields.string("proof_payload_b64", 4, 8192),
                1,
                DualMachinePairingIdentityCodec.MAX_PAYLOAD_BYTES);
        byte[] expectedProof = activationProof(
                request,
                challengeId,
                challengeToken,
                activationMode,
                targetEntitlementId,
                profileSha256);
        if (!MessageDigest.isEqual(suppliedProof, expectedProof)) {
            throw DualMachineStrictJson.contractError();
        }
        return new ActivationChallengeResponse(
                challengeId,
                challengeToken,
                expiresAt,
                activationMode,
                targetEntitlementId,
                profileSha256,
                expectedProof);
    }

    private static ActivationResponse parseActivation(byte[] encoded)
            throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "activation_id",
                "entitlement_id",
                "pair_id",
                "binding_id",
                "binding_revision",
                "pair_assurance_state",
                "status",
                "revocation_version",
                "credited_seconds",
                "remaining_seconds",
                "total_credited_seconds",
                "total_consumed_seconds",
                "billing_started",
                "activation_mode",
                "binding_updated",
                "authorization_kind",
                "product_key",
                "is_permanent");
        requireOk(fields);
        responseHex128(fields.string("activation_id", 32, 32));
        String entitlementId = responseHex128(
                fields.string("entitlement_id", 32, 32));
        String pairId = responseHex128(
                fields.string("pair_id", 32, 32));
        String bindingId = responseHex128(
                fields.string("binding_id", 32, 32));
        long bindingRevision = fields.integer(
                "binding_revision", 1L, Long.MAX_VALUE);
        String pairAssuranceState = fields.string(
                "pair_assurance_state", 6, 32);
        requireLiteral(pairAssuranceState, "active");
        requireLiteral(fields.string("status", 1, 16), "active");
        long revocationVersion = fields.integer(
                "revocation_version", 1L, Long.MAX_VALUE);
        String activationMode = fields.string(
                "activation_mode", 8, 11);
        boolean bindingUpdated = fields.bool("binding_updated");
        String authorizationKind = fields.string(
                "authorization_kind", 3, 32);
        String productKey = fields.string("product_key", 0, 32);
        boolean permanent = fields.bool("is_permanent");
        requireAuthorizationKind(authorizationKind, productKey, permanent);
        boolean deviceBinding = DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_BIND_DEVICE.equals(activationMode);
        if (!isActivationMode(activationMode)
                || deviceBinding != bindingUpdated) {
            throw DualMachineStrictJson.contractError();
        }
        long credited = fields.integer(
                "credited_seconds", 0L, Long.MAX_VALUE);
        long remaining = fields.integer(
                "remaining_seconds", 0L, Long.MAX_VALUE);
        long totalCredited = fields.integer(
                "total_credited_seconds", 0L, Long.MAX_VALUE);
        long totalConsumed = fields.integer(
                "total_consumed_seconds", 0L, Long.MAX_VALUE);
        boolean billingStarted = fields.bool("billing_started");
        if (billingStarted
                || credited > totalCredited
                || remaining > totalCredited
                || totalConsumed > totalCredited
                || totalCredited - remaining != totalConsumed
                || (permanent && (credited != 0L
                || remaining != 0L
                || totalCredited != 0L
                || totalConsumed != 0L))) {
            throw DualMachineStrictJson.contractError();
        }
        return new ActivationResponse(
                entitlementId,
                pairId,
                bindingId,
                bindingRevision,
                pairAssuranceState,
                revocationVersion,
                credited,
                remaining,
                totalCredited,
                totalConsumed,
                false,
                activationMode,
                bindingUpdated,
                authorizationKind,
                productKey,
                permanent);
    }

    private static EntitlementStatusResponse parseEntitlementStatus(
            byte[] encoded,
            EntitlementStatusRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "entitlement_id",
                "pair_id",
                "status",
                "revocation_version",
                "remaining_seconds",
                "total_credited_seconds",
                "total_consumed_seconds",
                "usage_session_status",
                "authorization_kind",
                "product_key",
                "is_permanent");
        requireOk(fields);
        String entitlementId = responseHex128(
                fields.string("entitlement_id", 32, 32));
        String pairId = responseHex128(
                fields.string("pair_id", 32, 32));
        String status = fields.string("status", 1, 16);
        if (!status.equals("active")
                && !status.equals("exhausted")
                && !status.equals("revoked")) {
            throw DualMachineStrictJson.contractError();
        }
        long revocationVersion = fields.integer(
                "revocation_version", 1L, Long.MAX_VALUE);
        String authorizationKind = fields.string(
                "authorization_kind", 3, 32);
        String productKey = fields.string("product_key", 0, 32);
        boolean permanent = fields.bool("is_permanent");
        requireAuthorizationKind(authorizationKind, productKey, permanent);
        long remaining = fields.integer(
                "remaining_seconds", 0L, Long.MAX_VALUE);
        long totalCredited = fields.integer(
                "total_credited_seconds", 0L, Long.MAX_VALUE);
        long totalConsumed = fields.integer(
                "total_consumed_seconds", 0L, Long.MAX_VALUE);
        String sessionStatus = fields.string(
                "usage_session_status", 0, 16);
        // Proof-rv compatibility: active/exhausted must echo the exact
        // request proof rv, while revoked may advance to a newer rv but
        // must never roll back below the request proof rv.
        boolean revocationCompatible = status.equals("revoked")
                ? revocationVersion >= request.proof.revocationVersion
                : revocationVersion == request.proof.revocationVersion;
        if ((!sessionStatus.isEmpty()
                && !sessionStatus.equals("active")
                && !sessionStatus.equals("ended"))
                || !entitlementId.equals(request.proof.entitlementId)
                || !pairId.equals(request.proof.pairId)
                || !revocationCompatible
                || remaining > totalCredited
                || totalConsumed > totalCredited
                || totalCredited - remaining != totalConsumed
                || (permanent && (remaining != 0L
                || totalCredited != 0L
                || totalConsumed != 0L
                || "exhausted".equals(status)))) {
            throw DualMachineStrictJson.contractError();
        }
        return new EntitlementStatusResponse(
                status,
                revocationVersion,
                remaining,
                totalCredited,
                totalConsumed,
                sessionStatus,
                authorizationKind,
                productKey,
                permanent);
    }

    private static PairGenerationChallengeResponse
            parsePairGenerationChallenge(
            byte[] encoded,
            PairGenerationChallengeRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "request_id",
                "allocation_request_id",
                "challenge_id",
                "pair_id",
                "binding_revision",
                "server_nonce",
                "challenge_expires_at_epoch");
        requireOk(fields);
        com.visionforge.inferencebenchmark.handshake.PairGenerationPopV1
                .ChallengeFields expected = request.proof.fields();
        String requestId = responseHex128(
                fields.string("request_id", 32, 32));
        String allocationRequestId = responseHex128(
                fields.string("allocation_request_id", 32, 32));
        String challengeId = responseHex128(
                fields.string("challenge_id", 32, 32));
        String pairId = responseHex128(
                fields.string("pair_id", 32, 32));
        long bindingRevision = fields.integer(
                "binding_revision", 1L, Long.MAX_VALUE);
        byte[] serverNonce = responseLowerHexBytes(
                fields.string("server_nonce", 64, 64), 32);
        long expiresAtEpoch = fields.integer(
                "challenge_expires_at_epoch", 1L, Long.MAX_VALUE);
        if (!expected.requestId.equals(requestId)
                || !expected.allocationRequestId.equals(allocationRequestId)
                || !expected.pairId.equals(pairId)
                || expected.bindingRevision != bindingRevision) {
            throw DualMachineStrictJson.contractError();
        }
        try {
            return new PairGenerationChallengeResponse(
                    requestId,
                    allocationRequestId,
                    challengeId,
                    pairId,
                    bindingRevision,
                    serverNonce,
                    expiresAtEpoch);
        } catch (IllegalArgumentException rejected) {
            throw DualMachineStrictJson.contractError();
        } finally {
            java.util.Arrays.fill(serverNonce, (byte) 0);
        }
    }

    private static PairGenerationCredentialResponse
            parsePairGenerationCredential(
            byte[] encoded,
            PairGenerationCredentialRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "allocation_request_id",
                "pair_id",
                "binding_revision",
                "generation",
                "connection_id",
                "transcript_proposal_sha256",
                "credential_token",
                "credential_sha256",
                "key_id",
                "credential_issued_at_epoch",
                "credential_not_before_epoch",
                "credential_expires_at_epoch");
        requireOk(fields);
        String allocationRequestId = responseHex128(
                fields.string("allocation_request_id", 32, 32));
        String pairId = responseHex128(
                fields.string("pair_id", 32, 32));
        long bindingRevision = fields.integer(
                "binding_revision", 1L, Long.MAX_VALUE);
        long generation = fields.integer(
                "generation", 1L, Long.MAX_VALUE);
        long connectionId = fields.integer(
                "connection_id", 1L, Long.MAX_VALUE);
        String proposalSha256 = responseSha256(fields.string(
                "transcript_proposal_sha256", 64, 64));
        String credentialToken = fields.string(
                "credential_token", 64, 8192);
        String credentialSha256 = responseSha256(fields.string(
                "credential_sha256", 64, 64));
        String keyId = responseLowerHex(
                fields.string("key_id", 16, 16), 16);
        long issuedAtEpoch = fields.integer(
                "credential_issued_at_epoch", 1L, Long.MAX_VALUE);
        long notBeforeEpoch = fields.integer(
                "credential_not_before_epoch", 1L, Long.MAX_VALUE);
        long expiresAtEpoch = fields.integer(
                "credential_expires_at_epoch", 1L, Long.MAX_VALUE);
        com.visionforge.inferencebenchmark.handshake.PairGenerationPopV1
                .ChallengeFields expected =
                request.proof.challengeRequest().fields();
        if (!expected.allocationRequestId.equals(allocationRequestId)
                || !expected.pairId.equals(pairId)
                || expected.bindingRevision != bindingRevision
                || request.proof.connectionId() != connectionId
                || !request.proof.transcriptProposalSha256().equals(
                proposalSha256)) {
            throw DualMachineStrictJson.contractError();
        }
        try {
            return new PairGenerationCredentialResponse(
                    allocationRequestId,
                    pairId,
                    bindingRevision,
                    generation,
                    connectionId,
                    proposalSha256,
                    credentialToken,
                    credentialSha256,
                    keyId,
                    issuedAtEpoch,
                    notBeforeEpoch,
                    expiresAtEpoch);
        } catch (IllegalArgumentException rejected) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static StartChallengeResponse parseStartChallenge(byte[] encoded)
            throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "challenge_id",
                "challenge_token",
                "challenge_expires_at_epoch",
                "billing_started");
        requireOk(fields);
        String challengeId = responseHex128(
                fields.string("challenge_id", 32, 32));
        String challengeToken = responseChallengeToken(
                fields.string("challenge_token", 43, 43));
        long expiresAt = fields.integer(
                "challenge_expires_at_epoch", 1L, Long.MAX_VALUE);
        if (fields.bool("billing_started")) {
            throw DualMachineStrictJson.contractError();
        }
        return new StartChallengeResponse(
                challengeId, challengeToken, expiresAt);
    }

    private static UsageLeaseResponse parseUsageLease(
            byte[] encoded,
            UsageProof requestProof,
            String expectedSessionId,
            long expectedSequence) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "entitlement_id",
                "pair_id",
                "session_id",
                "status",
                "sequence",
                "charged_seconds",
                "remaining_seconds",
                "total_consumed_seconds",
                "billing_started",
                "authorization_kind",
                "product_key",
                "is_permanent",
                "usage_lease",
                "usage_lease_sha256",
                "usage_lease_expires_at_epoch",
                "usage_lease_not_before_epoch",
                "usage_lease_ttl_seconds");
        requireOk(fields);
        String entitlementId = responseHex128(
                fields.string("entitlement_id", 32, 32));
        String pairId = responseHex128(
                fields.string("pair_id", 32, 32));
        String sessionId = responseHex128(
                fields.string("session_id", 32, 32));
        requireLiteral(fields.string("status", 1, 16), "active");
        long sequence = fields.integer(
                "sequence", 0L, Long.MAX_VALUE);
        String authorizationKind = fields.string(
                "authorization_kind", 3, 32);
        String productKey = fields.string("product_key", 0, 32);
        boolean permanent = fields.bool("is_permanent");
        requireAuthorizationKind(authorizationKind, productKey, permanent);
        long charged = fields.integer(
                "charged_seconds", 0L, MAXIMUM_LEASE_SECONDS);
        long remaining = fields.integer(
                "remaining_seconds", 0L, Long.MAX_VALUE);
        long totalConsumed = fields.integer(
                "total_consumed_seconds", 0L, Long.MAX_VALUE);
        boolean billingStarted = fields.bool("billing_started");
        String usageLease = responseUsageLease(
                fields.string("usage_lease", 256, 8192));
        String usageLeaseSha256 = responseSha256(
                fields.string("usage_lease_sha256", 64, 64));
        long expiresAt = fields.integer(
                "usage_lease_expires_at_epoch", 1L, Long.MAX_VALUE);
        long notBefore = fields.integer(
                "usage_lease_not_before_epoch", 1L, Long.MAX_VALUE);
        long ttl = fields.integer(
                "usage_lease_ttl_seconds", 1L, MAXIMUM_LEASE_SECONDS);
        String computedHash = sha256Hex(
                usageLease.getBytes(StandardCharsets.US_ASCII));
        if (!billingStarted
                || !entitlementId.equals(requestProof.entitlementId)
                || !pairId.equals(requestProof.pairId)
                || (expectedSessionId != null
                && !expectedSessionId.equals(sessionId))
                || sequence != expectedSequence
                || (permanent ? charged != 0L : charged != ttl)
                || (!permanent && totalConsumed < charged)
                || (permanent && (remaining != 0L
                || totalConsumed != 0L))
                || notBefore > Long.MAX_VALUE - ttl
                || notBefore + ttl != expiresAt
                || !MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.US_ASCII),
                usageLeaseSha256.getBytes(StandardCharsets.US_ASCII))) {
            throw DualMachineStrictJson.contractError();
        }
        return new UsageLeaseResponse(
                sessionId,
                sequence,
                charged,
                remaining,
                totalConsumed,
                usageLease,
                usageLeaseSha256,
                notBefore,
                expiresAt,
                ttl,
                true,
                authorizationKind,
                productKey,
                permanent);
    }

    private static StopResponse parseStop(
            byte[] encoded,
            StopRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "session_id",
                "status",
                "remaining_seconds",
                "charged_seconds",
                "billing_started",
                "authorization_kind",
                "is_permanent");
        requireOk(fields);
        String sessionId = responseHex128(
                fields.string("session_id", 32, 32));
        String status = fields.string("status", 1, 16);
        long remaining = fields.integer(
                "remaining_seconds", 0L, Long.MAX_VALUE);
        long charged = fields.integer(
                "charged_seconds", 0L, Long.MAX_VALUE);
        boolean billingStarted = fields.bool("billing_started");
        String authorizationKind = fields.string(
                "authorization_kind", 3, 32);
        boolean permanent = fields.bool("is_permanent");
        requireAuthorizationKind(authorizationKind, "", permanent);
        if (!sessionId.equals(request.sessionId)
                || !status.equals("ended")
                || charged != 0L
                || (permanent && remaining != 0L)) {
            throw DualMachineStrictJson.contractError();
        }
        return new StopResponse(
                sessionId,
                status,
                remaining,
                charged,
                billingStarted,
                authorizationKind,
                permanent);
    }

    private static StartCancellationResponse parseStartCancellation(
            byte[] encoded,
            StartCancellationRequest request) throws IOException {
        DualMachineStrictJson.Fields fields =
                DualMachineStrictJson.parseObject(encoded);
        fields.requireExactly(
                "ok",
                "start_request_id",
                "session_id",
                "session_status",
                "remaining_seconds",
                "charged_seconds",
                "billing_started",
                "authorization_kind",
                "is_permanent");
        requireOk(fields);
        String startRequestId = responseHex128(
                fields.string("start_request_id", 32, 32));
        String sessionId = fields.string("session_id", 0, 32);
        if (!sessionId.isEmpty()) sessionId = responseHex128(sessionId);
        String sessionStatus = fields.string(
                "session_status", 5, 16);
        long remaining = fields.integer(
                "remaining_seconds", 0L, Long.MAX_VALUE);
        long charged = fields.integer("charged_seconds", 0L, 0L);
        boolean billingStarted = fields.bool("billing_started");
        String authorizationKind = fields.string(
                "authorization_kind", 3, 32);
        boolean permanent = fields.bool("is_permanent");
        requireAuthorizationKind(authorizationKind, "", permanent);
        if (!startRequestId.equals(request.startRequestId)) {
            throw DualMachineStrictJson.contractError();
        }
        try {
            return new StartCancellationResponse(
                    startRequestId,
                    sessionId,
                    sessionStatus,
                    remaining,
                    charged,
                    billingStarted,
                    authorizationKind,
                    permanent);
        } catch (IllegalArgumentException invalid) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static byte[] activationProof(
            ActivationChallengeRequest request,
            String challengeId,
            String challengeToken,
            String activationMode,
            String targetEntitlementId,
            String profileSha256) throws IOException {
        try {
            DualMachineUsageAuthorizationContract.ActivationConfirmation proof =
                    new DualMachineUsageAuthorizationContract
                            .ActivationConfirmation();
            proof.activationMode = activationMode;
            proof.androidClientVersion = request.android.clientVersion;
            proof.androidDeviceCode = request.android.deviceCode;
            proof.androidDeviceProfileSha256 = profileSha256;
            proof.androidKeySha256 =
                    DualMachinePairingIdentityCodec
                            .fingerprintHexFromBase64(
                                    request.android
                                            .identityPublicKeyBase64);
            proof.challengeId = challengeId;
            proof.challengeTokenSha256 = sha256Hex(
                    challengeToken.getBytes(StandardCharsets.US_ASCII));
            proof.hostClientVersion = request.host.clientVersion;
            proof.hostDeviceCode = request.host.deviceCode;
            proof.hostKeySha256 =
                    DualMachinePairingIdentityCodec
                            .fingerprintHexFromBase64(
                                    request.host.identityPublicKeyBase64);
            proof.pairId = request.pairId;
            proof.protocolVersion = request.protocolVersion;
            proof.requestId = request.requestId;
            proof.targetEntitlementId = targetEntitlementId;
            return DualMachineUsageAuthorizationContract
                    .activationConfirmation(proof);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static byte[] activationChallengeJson(
            ActivationChallengeRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.object("android", peerJson(request.android));
        if (request.android.deviceProfile != null) {
            writer.object(
                    "android_device_profile",
                    request.android.deviceProfile.canonicalJson());
        }
        writer.string("card_code", request.cardCode);
        writer.object("host", peerJson(request.host));
        writer.string("pair_id", request.pairId);
        writer.number("protocol_version", request.protocolVersion);
        writer.string("request_id", request.requestId);
        return writer.finish();
    }

    private static byte[] activationConfirmationJson(
            ActivationConfirmationRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.string(
                "android_signature_b64",
                request.androidSignatureBase64);
        writer.string("challenge_id", request.challengeId);
        writer.string("challenge_token", request.challengeToken);
        writer.string("host_signature_b64", request.hostSignatureBase64);
        return writer.finish();
    }

    private static byte[] entitlementStatusJson(
            EntitlementStatusRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        return writer.finish();
    }

    private static byte[] pairGenerationChallengeJson(
            PairGenerationChallengeRequest request) {
        com.visionforge.inferencebenchmark.handshake.PairGenerationPopV1
                .ChallengeFields fields = request.proof.fields();
        JsonWriter writer = new JsonWriter();
        writer.string("allocation_request_id", fields.allocationRequestId);
        writer.string(
                "android_signature_b64", request.androidSignatureBase64);
        writer.string("binding_id", fields.bindingId);
        writer.number("binding_revision", fields.bindingRevision);
        writer.string("entitlement_id", fields.entitlementId);
        writer.string("host_signature_b64", request.hostSignatureBase64);
        writer.string("pair_id", fields.pairId);
        writer.number("protocol_version", DualMachineSidecarPort.PROTOCOL_VERSION);
        writer.string("request_id", fields.requestId);
        writer.number("revocation_version", fields.revocationVersion);
        return writer.finish();
    }

    private static byte[] pairGenerationCredentialJson(
            PairGenerationCredentialRequest request) {
        com.visionforge.inferencebenchmark.handshake.PairGenerationPopV1
                .ChallengeFields fields =
                request.proof.challengeRequest().fields();
        JsonWriter writer = new JsonWriter();
        writer.string("allocation_request_id", fields.allocationRequestId);
        writer.string(
                "android_signature_b64", request.androidSignatureBase64);
        writer.string("binding_id", fields.bindingId);
        writer.number("binding_revision", fields.bindingRevision);
        writer.string("challenge_id", request.challenge.challengeId);
        writer.string("entitlement_id", fields.entitlementId);
        writer.string("host_signature_b64", request.hostSignatureBase64);
        writer.string("pair_id", fields.pairId);
        writer.string(
                "proposal_b64",
                Base64.getEncoder().encodeToString(
                        request.proposal.canonicalEncoding()));
        writer.number("protocol_version", DualMachineSidecarPort.PROTOCOL_VERSION);
        writer.number("revocation_version", fields.revocationVersion);
        writer.string(
                "server_nonce",
                DualMachineSidecarValues.hex(
                        request.challenge.serverNonce()));
        return writer.finish();
    }

    private static byte[] startChallengeJson(
            StartChallengeRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string(
                "channel_binding_sha256",
                request.channelBindingSha256);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_id", request.requestId);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        return writer.finish();
    }

    private static byte[] startUsageJson(StartUsageRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.number(
                "android_frames_total",
                request.androidFramesTotal);
        writer.bool(
                "android_runtime_ready",
                request.androidRuntimeReady);
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string(
                "channel_binding_sha256",
                request.channelBindingSha256);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.number("host_frames_total", request.hostFramesTotal);
        writer.bool("host_runtime_ready", request.hostRuntimeReady);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_id", request.requestId);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        writer.string("start_challenge_id", request.startChallengeId);
        writer.string(
                "start_challenge_token",
                request.startChallengeToken);
        return writer.finish();
    }

    private static byte[] heartbeatJson(HeartbeatRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.number(
                "android_frames_total",
                request.androidFramesTotal);
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string(
                "channel_binding_sha256",
                request.channelBindingSha256);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.number("host_frames_total", request.hostFramesTotal);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.string("previous_lease", request.previousLease);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_id", request.requestId);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        writer.number("sequence", request.sequence);
        writer.string("session_id", request.sessionId);
        return writer.finish();
    }

    private static byte[] startCancellationJson(
            StartCancellationRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string(
                "channel_binding_sha256",
                request.channelBindingSha256);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_id", request.requestId);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        writer.string("start_request_id", request.startRequestId);
        return writer.finish();
    }

    private static byte[] stopJson(StopRequest request) {
        JsonWriter writer = new JsonWriter();
        writer.string(
                "android_signature_b64",
                request.proof.androidSignatureBase64);
        writer.string(
                "channel_binding_sha256",
                request.channelBindingSha256);
        writer.string("entitlement_id", request.proof.entitlementId);
        writer.string(
                "host_signature_b64",
                request.proof.hostSignatureBase64);
        writer.string("pair_id", request.proof.pairId);
        writer.string("previous_lease", request.previousLease);
        writer.number("protocol_version", request.proof.protocolVersion);
        writer.string("request_id", request.requestId);
        writer.string("request_nonce", request.requestNonce);
        writer.number(
                "revocation_version",
                request.proof.revocationVersion);
        writer.string("session_id", request.sessionId);
        return writer.finish();
    }

    private static byte[] peerJson(PeerIdentity identity) {
        JsonWriter writer = new JsonWriter();
        writer.string("client_version", identity.clientVersion);
        writer.string("device_code", identity.deviceCode);
        writer.string(
                "identity_public_key_b64",
                identity.identityPublicKeyBase64);
        return writer.finish();
    }

    private static void requireOk(DualMachineStrictJson.Fields fields)
            throws IOException {
        if (!fields.bool("ok")) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static boolean isActivationMode(String value) {
        return DualMachineUsageAuthorizationContract.ACTIVATION_MODE_ACTIVATE
                .equals(value)
                || DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_REACTIVATE.equals(value)
                || DualMachineUsageAuthorizationContract
                .ACTIVATION_MODE_BIND_DEVICE.equals(value);
    }

    private static String responseHex128(String value) throws IOException {
        try {
            return DualMachineSidecarValues.hex128(value, "responseId");
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static String responseSha256(String value) throws IOException {
        try {
            return DualMachineSidecarValues.sha256(
                    value, "responseSha256");
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static String responseLowerHex(String value, int length)
            throws IOException {
        try {
            return DualMachineSidecarValues.lowerHex(
                    value, length, "responseHex");
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static byte[] responseLowerHexBytes(String value, int bytes)
            throws IOException {
        String checked = responseLowerHex(value, bytes * 2);
        byte[] decoded = new byte[bytes];
        for (int index = 0; index < bytes; index++) {
            decoded[index] = (byte) ((Character.digit(
                    checked.charAt(index * 2), 16) << 4)
                    | Character.digit(
                    checked.charAt(index * 2 + 1), 16));
        }
        return decoded;
    }

    private static String responseChallengeToken(String value)
            throws IOException {
        try {
            return DualMachineSidecarValues.challengeToken(value);
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static String responseUsageLease(String value)
            throws IOException {
        try {
            return DualMachineSidecarValues.usageLease(
                    value, "responseLease");
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static byte[] responseBase64(
            String value,
            int minimumBytes,
            int maximumBytes) throws IOException {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length < minimumBytes
                    || decoded.length > maximumBytes
                    || !Base64.getEncoder().encodeToString(decoded)
                    .equals(value)) {
                throw DualMachineStrictJson.contractError();
            }
            return decoded;
        } catch (IllegalArgumentException exception) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static void requireLiteral(String actual, String expected)
            throws IOException {
        if (!expected.equals(actual)) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static void requireAuthorizationKind(
            String authorizationKind,
            String productKey,
            boolean permanent) throws IOException {
        boolean supported = "day".equals(authorizationKind)
                || "week".equals(authorizationKind)
                || "month".equals(authorizationKind)
                || "permanent".equals(authorizationKind);
        if (!supported
                || (!productKey.isEmpty()
                && !authorizationKind.equals(productKey))
                || permanent != "permanent".equals(authorizationKind)) {
            throw DualMachineStrictJson.contractError();
        }
    }

    private static String sha256Hex(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value);
            StringBuilder hex = new StringBuilder(64);
            for (byte octet : digest) {
                hex.append(Character.forDigit((octet >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(octet & 0x0f, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable", exception);
        }
    }

    private static PostJson requireTransport(
            DualMachineHttpsJsonTransport value) {
        if (value == null) {
            throw new IllegalArgumentException("transport is required");
        }
        return value::postJson;
    }

    private static final class JsonWriter {
        private final StringBuilder destination =
                new StringBuilder(1024).append('{');
        private boolean first = true;
        private boolean finished;

        void string(String name, String value) {
            fieldName(name);
            DualMachineStrictJson.quoted(destination, value);
        }

        void number(String name, long value) {
            if (value < 0L) {
                throw new IllegalArgumentException(
                        "JSON number must not be negative");
            }
            fieldName(name);
            destination.append(value);
        }

        void bool(String name, boolean value) {
            fieldName(name);
            destination.append(value);
        }

        void object(String name, byte[] encodedObject) {
            if (encodedObject == null || encodedObject.length < 2
                    || encodedObject[0] != '{'
                    || encodedObject[encodedObject.length - 1] != '}') {
                throw new IllegalArgumentException(
                        "nested JSON object is invalid");
            }
            fieldName(name);
            destination.append(new String(
                    encodedObject, StandardCharsets.UTF_8));
        }

        byte[] finish() {
            if (finished) {
                throw new IllegalStateException(
                        "JSON writer is already finished");
            }
            finished = true;
            destination.append('}');
            return DualMachineStrictJson.utf8(destination);
        }

        private void fieldName(String name) {
            if (finished) {
                throw new IllegalStateException(
                        "JSON writer is already finished");
            }
            if (!first) {
                destination.append(',');
            }
            first = false;
            DualMachineStrictJson.quoted(destination, name);
            destination.append(':');
        }
    }
}
