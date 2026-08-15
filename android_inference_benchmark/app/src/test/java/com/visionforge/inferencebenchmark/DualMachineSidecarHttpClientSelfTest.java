package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

/** Contract, billing-boundary and hostile-response checks for the sidecar client. */
public final class DualMachineSidecarHttpClientSelfTest {
    private static final String REQUEST_ID =
            "00112233445566778899aabbccddeeff";
    private static final String PAIR_ID =
            "112233445566778899aabbccddeeff00";
    private static final String ENTITLEMENT_ID =
            "2233445566778899aabbccddeeff0011";
    private static final String SESSION_ID =
            "33445566778899aabbccddeeff001122";
    private static final String CHALLENGE_ID =
            "445566778899aabbccddeeff00112233";
    private static final String NONCE =
            "5566778899aabbccddeeff0011223344";
    private static final String CANCEL_REQUEST_ID =
            "66778899aabbccddeeff001122334455";
    private static final String CANCEL_NONCE =
            "778899aabbccddeeff00112233445566";
    private static final String CHANNEL_BINDING = repeat("a", 64);
    private static final String SIGNATURE =
            Base64.getEncoder().encodeToString(new byte[8]);
    private static final String CHALLENGE_TOKEN =
            Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(new byte[32]);
    private static final String CARD_CODE =
            "VFD2-9FW4B-TVHCV-B7EKW-YHVHR-E77GF-Z5MYW";
    private static final String USAGE_LEASE =
            repeat("a", 80) + "." + repeat("b", 80) + "."
                    + repeat("c", 100);

    private DualMachineSidecarHttpClientSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        deviceProfileIsCanonicalAndContainsNoRawPrivilegedIdentifier();
        goldenRequestsAreDeterministicAndExplicit();
        acceptsReactivationWireContract();
        rejectsInvalidRequestValuesBeforeNetwork();
        rejectsAllZeroIdentifiersAndDigests();
        rejectsBillingBoundaryViolations();
        rejectsMalformedResponses();
        rejectsMismatchedActivationProof();
        serverErrorBodyNeverEntersExceptionText();
        safeServerErrorCodesArePreserved();
        revocationVersionCompatibility();
        acceptsPermanentWireContract();
        System.out.println("ANDROID_DUAL_MACHINE_SIDECAR_CLIENT_OK");
    }

    private static void acceptsPermanentWireContract() throws Exception {
        Fixtures fixtures = fixtures();
        FakeTransport transport = new FakeTransport();
        DualMachineSidecarHttpClient client =
                new DualMachineSidecarHttpClient(transport);

        transport.response = permanentActivationResponse();
        DualMachineSidecarPort.ActivationResponse activation =
                client.confirmActivation(fixtures.activationConfirmation);
        check(activation.permanent);
        check(activation.creditedSeconds == 0L);
        check(activation.remainingSeconds == 0L);

        transport.response = permanentStatusResponse();
        DualMachineSidecarPort.EntitlementStatusResponse status =
                client.fetchEntitlementStatus(fixtures.status);
        check(status.permanent);
        check(status.status.equals("active"));

        transport.response = permanentUsageResponse(0L, 1000L);
        DualMachineSidecarPort.UsageLeaseResponse start =
                client.startUsage(fixtures.start);
        check(start.permanent);
        check(start.chargedSeconds == 0L);
        check(start.billingStarted);

        transport.response = permanentUsageResponse(1L, 1005L);
        DualMachineSidecarPort.UsageLeaseResponse heartbeat =
                client.heartbeat(fixtures.heartbeat);
        check(heartbeat.permanent);
        check(heartbeat.totalConsumedSeconds == 0L);

        transport.response = permanentStartCancellationResponse();
        DualMachineSidecarPort.StartCancellationResponse cancellation =
                client.cancelStart(fixtures.startCancellation);
        check(cancellation.permanent);
        check(cancellation.billingStarted);
        check(cancellation.sessionId.equals(SESSION_ID));

        transport.response = permanentStopResponse();
        DualMachineSidecarPort.StopResponse stop =
                client.stop(fixtures.stop);
        check(stop.permanent);
        check(stop.billingStarted);
    }

    private static void acceptsReactivationWireContract() throws Exception {
        Fixtures fixtures = fixtures();
        FakeTransport transport = new FakeTransport();
        DualMachineSidecarHttpClient client =
                new DualMachineSidecarHttpClient(transport);

        transport.response = activationChallengeResponse(
                fixtures, "reactivate", ENTITLEMENT_ID, false);
        DualMachineSidecarPort.ActivationChallengeResponse challenge =
                client.createActivationChallenge(fixtures.activationChallenge);
        check(challenge.activationMode.equals("reactivate"));
        check(challenge.targetEntitlementId.equals(ENTITLEMENT_ID));

        transport.response = activationResponse(
                "reactivate", false, false);
        DualMachineSidecarPort.ActivationResponse activation =
                client.confirmActivation(fixtures.activationConfirmation);
        check(activation.activationMode.equals("reactivate"));
        check(!activation.bindingUpdated);
        check(activation.entitlementId.equals(ENTITLEMENT_ID));
        check(activation.creditedSeconds == 3600L);
    }

    private static void
            deviceProfileIsCanonicalAndContainsNoRawPrivilegedIdentifier() {
        DualMachineAndroidDeviceProfile profile =
                new DualMachineAndroidDeviceProfile(
                        "Qualcomm",
                        "OnePlus",
                        "PJZ110",
                        "pineapple",
                        "PJZ110",
                        "qcom",
                        "15",
                        35,
                        List.of("arm64-v8a", "armeabi-v7a"),
                        repeat("d", 64));
        String json = new String(
                profile.canonicalJson(), StandardCharsets.UTF_8);
        check(json.equals(
                "{\"brand\":\"OnePlus\",\"device\":\"pineapple\","
                        + "\"device_fingerprint\":\"" + repeat("d", 64)
                        + "\",\"hardware\":\"qcom\","
                        + "\"manufacturer\":\"Qualcomm\","
                        + "\"model\":\"PJZ110\",\"os_release\":\"15\","
                        + "\"product\":\"PJZ110\",\"sdk_int\":35,"
                        + "\"supported_abis\":[\"arm64-v8a\","
                        + "\"armeabi-v7a\"]}"));
        check(profile.canonicalSha256().matches("[0-9a-f]{64}"));
        String lower = json.toLowerCase(java.util.Locale.ROOT);
        check(!lower.contains("android_id"));
        check(!lower.contains("imei"));
        check(!lower.contains("serial"));
    }

    private static void revocationVersionCompatibility() throws Exception {
        Fixtures fixtures = fixtures();
        // A revoked response may carry a newer rv than the request proof.
        DualMachineSidecarPort.EntitlementStatusResponse revoked =
                fetchStatus(
                        fixtures.status,
                        statusResponse("revoked", 2L, 0L, 3600L, 3600L));
        check(revoked.status.equals("revoked"));
        check(revoked.revocationVersion == 2L);
        // A revoked response must never roll back below the request rv.
        expectRejected(() -> fetchStatus(
                statusRequest(2L),
                statusResponse("revoked", 1L, 0L, 3600L, 3600L)));
        // Active and exhausted responses must echo the exact request rv.
        expectRejected(() -> fetchStatus(
                fixtures.status,
                statusResponse("active", 2L, 3600L, 3600L, 0L)));
        expectRejected(() -> fetchStatus(
                fixtures.status,
                statusResponse("exhausted", 2L, 0L, 3600L, 3600L)));
        DualMachineSidecarPort.EntitlementStatusResponse exhausted =
                fetchStatus(
                        fixtures.status,
                        statusResponse("exhausted", 1L, 0L, 3600L, 3600L));
        check(exhausted.status.equals("exhausted"));
        check(exhausted.revocationVersion == 1L);
    }

    private static DualMachineSidecarPort.EntitlementStatusRequest
            statusRequest(long revocationVersion) {
        return new DualMachineSidecarPort.EntitlementStatusRequest(
                new DualMachineSidecarPort.UsageProof(
                        ENTITLEMENT_ID,
                        PAIR_ID,
                        revocationVersion,
                        SIGNATURE,
                        SIGNATURE),
                NONCE);
    }

    private static DualMachineSidecarPort.EntitlementStatusResponse
            fetchStatus(
                    DualMachineSidecarPort.EntitlementStatusRequest request,
                    byte[] response) throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        return new DualMachineSidecarHttpClient(transport)
                .fetchEntitlementStatus(request);
    }

    private static void rejectsInvalidRequestValuesBeforeNetwork()
            throws Exception {
        Fixtures fixtures = fixtures();
        expectInvalid(() -> new DualMachineSidecarPort.PeerIdentity(
                "lowercase-device",
                "2.0",
                fixtures.host.identityPublicKeyBase64));
        expectInvalid(() ->
                new DualMachineSidecarPort.ActivationChallengeRequest(
                        REQUEST_ID,
                        PAIR_ID,
                        "VFD2-invalid",
                        fixtures.host,
                        fixtures.android));
        expectInvalid(() -> new DualMachineSidecarPort.UsageProof(
                ENTITLEMENT_ID,
                PAIR_ID,
                1L,
                "not-base64",
                SIGNATURE));
        expectInvalid(() -> new DualMachineSidecarPort.StartUsageRequest(
                fixtures.status.proof,
                REQUEST_ID,
                NONCE,
                CHANNEL_BINDING,
                -1L,
                0L,
                CHALLENGE_ID,
                CHALLENGE_TOKEN));
        expectInvalid(() ->
                new DualMachineSidecarPort.StartCancellationRequest(
                        fixtures.status.proof,
                        REQUEST_ID,
                        NONCE,
                        REQUEST_ID,
                        CHANNEL_BINDING));
        String invalidLease = repeat("a", 81) + "."
                + repeat("b", 80) + "." + repeat("c", 100);
        expectInvalid(() -> new DualMachineSidecarPort.StopRequest(
                fixtures.status.proof,
                SESSION_ID,
                REQUEST_ID,
                NONCE,
                CHANNEL_BINDING,
                invalidLease));
    }

    private static void rejectsAllZeroIdentifiersAndDigests()
            throws Exception {
        String zeroId = repeat("0", 32);
        String zeroSha256 = repeat("0", 64);
        expectInvalid(() -> DualMachineSidecarValues.hex128(
                zeroId, "zeroId"));
        expectInvalid(() -> DualMachineSidecarValues.sha256(
                zeroSha256, "zeroSha256"));

        Fixtures fixtures = fixtures();
        String activation = new String(
                activationResponse(false), StandardCharsets.UTF_8);
        expectRejected(() -> callActivation(
                fixtures,
                bytes(activation.replace(
                        "\"activation_id\":\"" + CHALLENGE_ID + "\"",
                        "\"activation_id\":\"" + zeroId + "\""))));

        String startChallenge = new String(
                startChallengeResponse(false), StandardCharsets.UTF_8);
        expectRejected(() -> callStartChallenge(
                fixtures,
                bytes(startChallenge.replace(
                        "\"challenge_id\":\"" + CHALLENGE_ID + "\"",
                        "\"challenge_id\":\"" + zeroId + "\""))));
    }

    private static void goldenRequestsAreDeterministicAndExplicit()
            throws Exception {
        Fixtures fixtures = fixtures();
        FakeTransport transport = new FakeTransport();
        DualMachineSidecarHttpClient client =
                new DualMachineSidecarHttpClient(transport);

        transport.response = activationChallengeResponse(fixtures, false);
        client.createActivationChallenge(fixtures.activationChallenge);
        check(transport.path.equals(
                "/api/dual-machine/v1/license-activations/challenges"));
        check(transport.requestText().equals(
                "{\"android\":{\"client_version\":\"2.0\","
                        + "\"device_code\":\"ANDROID-DEVICE\","
                        + "\"identity_public_key_b64\":\""
                        + fixtures.android.identityPublicKeyBase64
                        + "\"},\"card_code\":\"" + CARD_CODE
                        + "\",\"host\":{\"client_version\":\"2.0\","
                        + "\"device_code\":\"HOST-DEVICE\","
                        + "\"identity_public_key_b64\":\""
                        + fixtures.host.identityPublicKeyBase64
                        + "\"},\"pair_id\":\"" + PAIR_ID
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + REQUEST_ID + "\"}"));

        transport.response = activationResponse(false);
        client.confirmActivation(fixtures.activationConfirmation);
        check(transport.path.equals(
                "/api/dual-machine/v1/license-activations/confirm"));
        check(transport.requestText().equals(
                "{\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"challenge_id\":\"" + CHALLENGE_ID
                        + "\",\"challenge_token\":\"" + CHALLENGE_TOKEN
                        + "\",\"host_signature_b64\":\"" + SIGNATURE
                        + "\"}"));

        transport.response = statusResponse();
        client.fetchEntitlementStatus(fixtures.status);
        check(transport.path.equals(
                "/api/dual-machine/v1/entitlements/"
                        + ENTITLEMENT_ID + "/status"));
        check(transport.requestText().equals(
                "{\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"protocol_version\":2,\"request_nonce\":\""
                        + NONCE + "\",\"revocation_version\":1}"));

        transport.response = startChallengeResponse(false);
        client.createStartChallenge(fixtures.startChallenge);
        check(transport.path.equals(
                "/api/dual-machine/v1/usage-sessions/start-challenges"));
        check(transport.requestText().equals(
                "{\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"channel_binding_sha256\":\""
                        + CHANNEL_BINDING
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + REQUEST_ID + "\",\"request_nonce\":\"" + NONCE
                        + "\",\"revocation_version\":1}"));

        transport.response = usageResponse(0L, true, 5L, 1000L);
        client.startUsage(fixtures.start);
        check(transport.path.equals(
                "/api/dual-machine/v1/usage-sessions/start"));
        check(transport.requestText().equals(
                "{\"android_frames_total\":0,"
                        + "\"android_runtime_ready\":true,"
                        + "\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"channel_binding_sha256\":\""
                        + CHANNEL_BINDING
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_frames_total\":0,"
                        + "\"host_runtime_ready\":true,"
                        + "\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + REQUEST_ID + "\",\"request_nonce\":\"" + NONCE
                        + "\",\"revocation_version\":1,"
                        + "\"start_challenge_id\":\"" + CHALLENGE_ID
                        + "\",\"start_challenge_token\":\""
                        + CHALLENGE_TOKEN + "\"}"));

        transport.response = startCancellationResponse(
                "", "not_started", 3600L, false, 0L);
        client.cancelStart(fixtures.startCancellation);
        check(transport.path.equals(
                "/api/dual-machine/v1/usage-sessions/start-cancellations"));
        check(transport.requestText().equals(
                "{\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"channel_binding_sha256\":\""
                        + CHANNEL_BINDING
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + CANCEL_REQUEST_ID + "\",\"request_nonce\":\""
                        + CANCEL_NONCE
                        + "\",\"revocation_version\":1,"
                        + "\"start_request_id\":\"" + REQUEST_ID
                        + "\"}"));

        transport.response = usageResponse(1L, true, 5L, 1005L);
        client.heartbeat(fixtures.heartbeat);
        check(transport.path.equals(
                "/api/dual-machine/v1/usage-sessions/" + SESSION_ID
                        + "/heartbeat"));
        check(transport.requestText().equals(
                "{\"android_frames_total\":12,"
                        + "\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"channel_binding_sha256\":\""
                        + CHANNEL_BINDING
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_frames_total\":11,"
                        + "\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"previous_lease\":\"" + USAGE_LEASE
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + REQUEST_ID + "\",\"request_nonce\":\"" + NONCE
                        + "\",\"revocation_version\":1,\"sequence\":1,"
                        + "\"session_id\":\"" + SESSION_ID + "\"}"));

        transport.response = stopResponse(0L);
        client.stop(fixtures.stop);
        check(transport.path.equals(
                "/api/dual-machine/v1/usage-sessions/" + SESSION_ID
                        + "/stop"));
        check(transport.requestText().equals(
                "{\"android_signature_b64\":\"" + SIGNATURE
                        + "\",\"channel_binding_sha256\":\""
                        + CHANNEL_BINDING
                        + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                        + "\",\"host_signature_b64\":\"" + SIGNATURE
                        + "\",\"pair_id\":\"" + PAIR_ID
                        + "\",\"previous_lease\":\"" + USAGE_LEASE
                        + "\",\"protocol_version\":2,\"request_id\":\""
                        + REQUEST_ID + "\",\"request_nonce\":\"" + NONCE
                        + "\",\"revocation_version\":1,\"session_id\":\""
                        + SESSION_ID + "\"}"));
        check(transport.callCount == 8);
    }

    private static void rejectsBillingBoundaryViolations() throws Exception {
        Fixtures fixtures = fixtures();
        expectRejected(() -> callActivation(
                fixtures, activationResponse(true)));
        expectRejected(() -> callStart(
                fixtures, usageResponse(0L, false, 5L, 1000L)));
        expectRejected(() -> callStart(
                fixtures, usageResponse(0L, true, 0L, 1000L)));
        expectRejected(() -> callStartChallenge(
                fixtures, startChallengeResponse(true)));
        expectRejected(() -> callStartCancellation(
                fixtures,
                startCancellationResponse(
                        "", "not_started", 3600L, true, 0L)));
        expectRejected(() -> callStartCancellation(
                fixtures,
                startCancellationResponse(
                        SESSION_ID, "ended", 3595L, true, 1L)));
        expectRejected(() -> callStop(fixtures, stopResponse(1L)));
    }

    private static void rejectsMalformedResponses() throws Exception {
        Fixtures fixtures = fixtures();
        String valid = new String(statusResponse(), StandardCharsets.UTF_8);
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.substring(0, valid.length() - 1)
                        + ",\"unexpected\":1}")));
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.replaceFirst(
                        "\\{\"ok\":true",
                        "{\"ok\":true,\"ok\":true"))));
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.replace(
                        "\"remaining_seconds\":3600",
                        "\"remaining_seconds\":9223372036854775808"))));
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.replace(
                        "\"remaining_seconds\":3600",
                        "\"remaining_seconds\":\"3600\""))));
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.replace(
                        "\"remaining_seconds\":3600",
                        "\"remaining_seconds\":3600.0"))));
        expectRejected(() -> callStatus(
                fixtures, bytes(valid.replace(
                        ",\"usage_session_status\":\"\"",
                        ""))));
        expectRejected(() -> callStop(
                fixtures,
                bytes(new String(
                        stopResponse(0L), StandardCharsets.UTF_8)
                        .replace("\"charged_seconds\":0",
                                "\"charged_seconds\":-0"))));
        expectRejected(() -> callStartCancellation(
                fixtures,
                startCancellationResponse(
                        "", "ended", 3595L, true, 0L)));
        expectRejected(() -> callStartCancellation(
                fixtures,
                startCancellationResponse(
                        SESSION_ID, "not_started", 3600L, false, 0L)));
        expectRejected(() -> callStartCancellation(
                fixtures,
                bytes(new String(
                        startCancellationResponse(
                                "", "not_started", 3600L, false, 0L),
                        StandardCharsets.UTF_8).replace(
                        "\"start_request_id\":\"" + REQUEST_ID + "\"",
                        "\"start_request_id\":\"" + SESSION_ID + "\""))));
    }

    private static void rejectsMismatchedActivationProof()
            throws Exception {
        Fixtures fixtures = fixtures();
        expectRejected(() -> {
            FakeTransport transport = new FakeTransport();
            transport.response = activationChallengeResponse(fixtures, true);
            new DualMachineSidecarHttpClient(transport)
                    .createActivationChallenge(fixtures.activationChallenge);
        });
    }

    private static void serverErrorBodyNeverEntersExceptionText()
            throws Exception {
        Fixtures fixtures = fixtures();
        String secretBody =
                "{\"ok\":false,\"error\":\"CARD-VFD2-SECRET\"}";
        DualMachineSidecarHttpClient client =
                new DualMachineSidecarHttpClient((path, request) -> {
                    throw new DualMachineHttpsJsonTransport
                            .SidecarHttpException(
                                    409,
                                    secretBody.getBytes(
                                            StandardCharsets.UTF_8));
                });
        try {
            client.fetchEntitlementStatus(fixtures.status);
            throw new AssertionError("server rejection was accepted");
        } catch (DualMachineSidecarPort.RejectedException expected) {
            check(expected.statusCode == 409);
            check(!expected.toString().contains("CARD-VFD2-SECRET"));
            check(expected.getCause() == null);
        }
    }

    private static void safeServerErrorCodesArePreserved() throws Exception {
        check(rejectedSafeCode("license_bound_to_another_device")
                .equals("license_bound_to_another_device"));
        check(rejectedSafeCode("license_device_binding_inconsistent")
                .equals("license_device_binding_inconsistent"));
        check(rejectedSafeCode("activation_challenge_invalid")
                .equals("activation_challenge_invalid"));
        check(rejectedSafeCode("CARD-VFD2-SECRET").isEmpty());
    }

    private static String rejectedSafeCode(String errorCode) throws Exception {
        Fixtures fixtures = fixtures();
        String body = "{\"ok\":false,\"error\":\"" + errorCode + "\"}";
        DualMachineSidecarHttpClient client =
                new DualMachineSidecarHttpClient((path, request) -> {
                    throw new DualMachineHttpsJsonTransport.SidecarHttpException(
                            409, body.getBytes(StandardCharsets.UTF_8));
                });
        try {
            client.fetchEntitlementStatus(fixtures.status);
            throw new AssertionError("server rejection was accepted");
        } catch (DualMachineSidecarPort.RejectedException rejected) {
            return rejected.safeErrorCode;
        }
    }

    private static void callActivation(Fixtures fixtures, byte[] response)
            throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport)
                .confirmActivation(fixtures.activationConfirmation);
    }

    private static void callStatus(Fixtures fixtures, byte[] response)
            throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport)
                .fetchEntitlementStatus(fixtures.status);
    }

    private static void callStartChallenge(
            Fixtures fixtures,
            byte[] response) throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport)
                .createStartChallenge(fixtures.startChallenge);
    }

    private static void callStart(Fixtures fixtures, byte[] response)
            throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport)
                .startUsage(fixtures.start);
    }

    private static void callStop(Fixtures fixtures, byte[] response)
            throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport).stop(fixtures.stop);
    }

    private static void callStartCancellation(
            Fixtures fixtures,
            byte[] response) throws IOException {
        FakeTransport transport = new FakeTransport();
        transport.response = response;
        new DualMachineSidecarHttpClient(transport)
                .cancelStart(fixtures.startCancellation);
    }

    private static byte[] activationChallengeResponse(
            Fixtures fixtures,
            boolean corruptProof) throws Exception {
        return activationChallengeResponse(
                fixtures, "activate", "", corruptProof);
    }

    private static byte[] activationChallengeResponse(
            Fixtures fixtures,
            String activationMode,
            String targetEntitlementId,
            boolean corruptProof) throws Exception {
        DualMachineUsageAuthorizationContract.ActivationConfirmation proof =
                new DualMachineUsageAuthorizationContract
                        .ActivationConfirmation();
        String profileSha256 = sha256Hex("{}");
        proof.activationMode = activationMode;
        proof.androidClientVersion = fixtures.android.clientVersion;
        proof.androidDeviceCode = fixtures.android.deviceCode;
        proof.androidDeviceProfileSha256 = profileSha256;
        proof.androidKeySha256 = DualMachinePairingIdentityCodec
                .fingerprintHexFromBase64(
                        fixtures.android.identityPublicKeyBase64);
        proof.challengeId = CHALLENGE_ID;
        proof.challengeTokenSha256 = sha256Hex(CHALLENGE_TOKEN);
        proof.hostClientVersion = fixtures.host.clientVersion;
        proof.hostDeviceCode = fixtures.host.deviceCode;
        proof.hostKeySha256 = DualMachinePairingIdentityCodec
                .fingerprintHexFromBase64(
                        fixtures.host.identityPublicKeyBase64);
        proof.pairId = PAIR_ID;
        proof.protocolVersion = 2;
        proof.requestId = REQUEST_ID;
        proof.targetEntitlementId = targetEntitlementId;
        byte[] payload = DualMachineUsageAuthorizationContract
                .activationConfirmation(proof);
        if (corruptProof) {
            payload = payload.clone();
            payload[payload.length - 1] ^= 1;
        }
        return bytes("{\"ok\":true,\"activation_mode\":\""
                + activationMode + "\","
                + "\"target_entitlement_id\":\""
                + targetEntitlementId + "\","
                + "\"android_device_profile_sha256\":\""
                + profileSha256 + "\",\"challenge_id\":\"" + CHALLENGE_ID
                + "\",\"challenge_token\":\"" + CHALLENGE_TOKEN
                + "\",\"challenge_expires_at_epoch\":1700000120,"
                + "\"proof_payload_b64\":\""
                + Base64.getEncoder().encodeToString(payload) + "\"}");
    }

    private static byte[] activationResponse(boolean billingStarted) {
        return activationResponse("activate", false, billingStarted);
    }

    private static byte[] activationResponse(
            String activationMode,
            boolean bindingUpdated,
            boolean billingStarted) {
        return bytes("{\"ok\":true,\"activation_id\":\"" + CHALLENGE_ID
                + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"status\":\"active\",\"revocation_version\":1,"
                + "\"activation_mode\":\"" + activationMode + "\","
                + "\"binding_updated\":" + bindingUpdated + ","
                + "\"authorization_kind\":\"day\","
                + "\"product_key\":\"day\",\"is_permanent\":false,"
                + "\"credited_seconds\":3600,\"remaining_seconds\":3600,"
                + "\"total_credited_seconds\":3600,"
                + "\"total_consumed_seconds\":0,\"billing_started\":"
                + billingStarted + "}");
    }

    private static byte[] permanentActivationResponse() {
        return bytes("{\"ok\":true,\"activation_id\":\"" + CHALLENGE_ID
                + "\",\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"status\":\"active\",\"revocation_version\":1,"
                + "\"activation_mode\":\"activate\","
                + "\"binding_updated\":false,"
                + "\"authorization_kind\":\"permanent\","
                + "\"product_key\":\"permanent\","
                + "\"is_permanent\":true,\"credited_seconds\":0,"
                + "\"remaining_seconds\":0,\"total_credited_seconds\":0,"
                + "\"total_consumed_seconds\":0,"
                + "\"billing_started\":false}");
    }

    private static byte[] statusResponse() {
        return statusResponse("active", 1L, 3600L, 3600L, 0L);
    }

    private static byte[] statusResponse(
            String status,
            long revocationVersion,
            long remaining,
            long totalCredited,
            long totalConsumed) {
        return bytes("{\"ok\":true,\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"status\":\"" + status
                + "\",\"revocation_version\":" + revocationVersion
                + ",\"authorization_kind\":\"day\","
                + "\"product_key\":\"day\",\"is_permanent\":false"
                + ",\"remaining_seconds\":" + remaining
                + ",\"total_credited_seconds\":" + totalCredited
                + ",\"total_consumed_seconds\":" + totalConsumed
                + ",\"usage_session_status\":\"\"}");
    }

    private static byte[] permanentStatusResponse() {
        return bytes("{\"ok\":true,\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"status\":\"active\",\"revocation_version\":1,"
                + "\"authorization_kind\":\"permanent\","
                + "\"product_key\":\"permanent\","
                + "\"is_permanent\":true,\"remaining_seconds\":0,"
                + "\"total_credited_seconds\":0,"
                + "\"total_consumed_seconds\":0,"
                + "\"usage_session_status\":\"\"}");
    }

    private static byte[] startChallengeResponse(boolean billingStarted) {
        return bytes("{\"ok\":true,\"challenge_id\":\"" + CHALLENGE_ID
                + "\",\"challenge_token\":\"" + CHALLENGE_TOKEN
                + "\",\"challenge_expires_at_epoch\":1700000120,"
                + "\"billing_started\":" + billingStarted + "}");
    }

    private static byte[] usageResponse(
            long sequence,
            boolean billingStarted,
            long chargedSeconds,
            long notBefore) throws Exception {
        long ttl = chargedSeconds == 0L ? 5L : chargedSeconds;
        long expiresAt = notBefore + ttl;
        long totalConsumed = sequence == 0L ? 5L : 10L;
        long remaining = 3600L - totalConsumed;
        return bytes("{\"ok\":true,\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"session_id\":\"" + SESSION_ID
                + "\",\"status\":\"active\",\"sequence\":" + sequence
                + ",\"authorization_kind\":\"day\","
                + "\"product_key\":\"day\",\"is_permanent\":false"
                + ",\"charged_seconds\":" + chargedSeconds
                + ",\"remaining_seconds\":" + remaining
                + ",\"total_consumed_seconds\":" + totalConsumed
                + ",\"billing_started\":" + billingStarted
                + ",\"usage_lease\":\"" + USAGE_LEASE
                + "\",\"usage_lease_sha256\":\""
                + sha256Hex(USAGE_LEASE)
                + "\",\"usage_lease_expires_at_epoch\":" + expiresAt
                + ",\"usage_lease_not_before_epoch\":" + notBefore
                + ",\"usage_lease_ttl_seconds\":" + ttl + "}");
    }

    private static byte[] permanentUsageResponse(
            long sequence,
            long notBefore) throws Exception {
        long ttl = 5L;
        return bytes("{\"ok\":true,\"entitlement_id\":\"" + ENTITLEMENT_ID
                + "\",\"pair_id\":\"" + PAIR_ID
                + "\",\"session_id\":\"" + SESSION_ID
                + "\",\"status\":\"active\",\"sequence\":" + sequence
                + ",\"authorization_kind\":\"permanent\","
                + "\"product_key\":\"permanent\","
                + "\"is_permanent\":true,\"charged_seconds\":0,"
                + "\"remaining_seconds\":0,\"total_consumed_seconds\":0,"
                + "\"billing_started\":true,\"usage_lease\":\""
                + USAGE_LEASE + "\",\"usage_lease_sha256\":\""
                + sha256Hex(USAGE_LEASE)
                + "\",\"usage_lease_expires_at_epoch\":"
                + (notBefore + ttl)
                + ",\"usage_lease_not_before_epoch\":" + notBefore
                + ",\"usage_lease_ttl_seconds\":" + ttl + "}");
    }

    private static byte[] stopResponse(long chargedSeconds) {
        return bytes("{\"ok\":true,\"session_id\":\"" + SESSION_ID
                + "\",\"status\":\"ended\",\"remaining_seconds\":3595,"
                + "\"charged_seconds\":" + chargedSeconds
                + ",\"billing_started\":true,"
                + "\"authorization_kind\":\"day\","
                + "\"is_permanent\":false}");
    }

    private static byte[] startCancellationResponse(
            String sessionId,
            String status,
            long remainingSeconds,
            boolean billingStarted,
            long chargedSeconds) {
        return bytes("{\"ok\":true,\"start_request_id\":\"" + REQUEST_ID
                + "\",\"session_id\":\"" + sessionId
                + "\",\"session_status\":\"" + status
                + "\",\"remaining_seconds\":" + remainingSeconds
                + ",\"charged_seconds\":" + chargedSeconds
                + ",\"billing_started\":" + billingStarted
                + ",\"authorization_kind\":\"day\","
                + "\"is_permanent\":false}");
    }

    private static byte[] permanentStartCancellationResponse() {
        return bytes("{\"ok\":true,\"start_request_id\":\"" + REQUEST_ID
                + "\",\"session_id\":\"" + SESSION_ID
                + "\",\"session_status\":\"ended\","
                + "\"remaining_seconds\":0,\"charged_seconds\":0,"
                + "\"billing_started\":true,"
                + "\"authorization_kind\":\"permanent\","
                + "\"is_permanent\":true}");
    }

    private static byte[] permanentStopResponse() {
        return bytes("{\"ok\":true,\"session_id\":\"" + SESSION_ID
                + "\",\"status\":\"ended\",\"remaining_seconds\":0,"
                + "\"charged_seconds\":0,\"billing_started\":true,"
                + "\"authorization_kind\":\"permanent\","
                + "\"is_permanent\":true}");
    }

    private static Fixtures fixtures() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        DualMachineSidecarPort.PeerIdentity host =
                new DualMachineSidecarPort.PeerIdentity(
                        "HOST-DEVICE",
                        "2.0",
                        Base64.getEncoder().encodeToString(
                                generator.generateKeyPair()
                                        .getPublic().getEncoded()));
        DualMachineSidecarPort.PeerIdentity android =
                new DualMachineSidecarPort.PeerIdentity(
                        "ANDROID-DEVICE",
                        "2.0",
                        Base64.getEncoder().encodeToString(
                                generator.generateKeyPair()
                                        .getPublic().getEncoded()));
        DualMachineSidecarPort.UsageProof proof =
                new DualMachineSidecarPort.UsageProof(
                        ENTITLEMENT_ID,
                        PAIR_ID,
                        1L,
                        SIGNATURE,
                        SIGNATURE);
        return new Fixtures(
                host,
                android,
                new DualMachineSidecarPort.ActivationChallengeRequest(
                        REQUEST_ID, PAIR_ID, CARD_CODE, host, android),
                new DualMachineSidecarPort.ActivationConfirmationRequest(
                        CHALLENGE_ID,
                        CHALLENGE_TOKEN,
                        SIGNATURE,
                        SIGNATURE),
                new DualMachineSidecarPort.EntitlementStatusRequest(
                        proof, NONCE),
                new DualMachineSidecarPort.StartChallengeRequest(
                        proof,
                        REQUEST_ID,
                        NONCE,
                        CHANNEL_BINDING),
                new DualMachineSidecarPort.StartUsageRequest(
                        proof,
                        REQUEST_ID,
                        NONCE,
                        CHANNEL_BINDING,
                        0L,
                        0L,
                        CHALLENGE_ID,
                        CHALLENGE_TOKEN),
                new DualMachineSidecarPort.StartCancellationRequest(
                        proof,
                        CANCEL_REQUEST_ID,
                        CANCEL_NONCE,
                        REQUEST_ID,
                        CHANNEL_BINDING),
                new DualMachineSidecarPort.HeartbeatRequest(
                        proof,
                        SESSION_ID,
                        REQUEST_ID,
                        NONCE,
                        CHANNEL_BINDING,
                        1L,
                        11L,
                        12L,
                        USAGE_LEASE),
                new DualMachineSidecarPort.StopRequest(
                        proof,
                        SESSION_ID,
                        REQUEST_ID,
                        NONCE,
                        CHANNEL_BINDING,
                        USAGE_LEASE));
    }

    private static String sha256Hex(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
        StringBuilder result = new StringBuilder(64);
        for (byte octet : digest) {
            result.append(Character.forDigit((octet >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(octet & 0x0f, 16));
        }
        return result.toString();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) {
            result.append(value);
        }
        return result.toString();
    }

    private static void expectRejected(CheckedRunnable action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid sidecar response was accepted");
        } catch (IOException expected) {
            check(!expected.toString().contains(CARD_CODE));
            check(!expected.toString().contains(USAGE_LEASE));
        }
    }

    private static void expectInvalid(Runnable action) {
        try {
            action.run();
            throw new AssertionError("invalid request value was accepted");
        } catch (IllegalArgumentException expected) {
            check(!expected.toString().contains(CARD_CODE));
            check(!expected.toString().contains(USAGE_LEASE));
        }
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("check failed");
        }
    }

    private interface CheckedRunnable {
        void run() throws Exception;
    }

    private static final class FakeTransport
            implements DualMachineSidecarHttpClient.PostJson {
        byte[] response;
        String path;
        byte[] request;
        int callCount;

        @Override
        public byte[] postJson(String apiPath, byte[] canonicalJson) {
            path = apiPath;
            request = canonicalJson.clone();
            callCount++;
            return response.clone();
        }

        String requestText() {
            return new String(request, StandardCharsets.UTF_8);
        }
    }

    private static final class Fixtures {
        final DualMachineSidecarPort.PeerIdentity host;
        final DualMachineSidecarPort.PeerIdentity android;
        final DualMachineSidecarPort.ActivationChallengeRequest
                activationChallenge;
        final DualMachineSidecarPort.ActivationConfirmationRequest
                activationConfirmation;
        final DualMachineSidecarPort.EntitlementStatusRequest status;
        final DualMachineSidecarPort.StartChallengeRequest startChallenge;
        final DualMachineSidecarPort.StartUsageRequest start;
        final DualMachineSidecarPort.StartCancellationRequest
                startCancellation;
        final DualMachineSidecarPort.HeartbeatRequest heartbeat;
        final DualMachineSidecarPort.StopRequest stop;

        Fixtures(
                DualMachineSidecarPort.PeerIdentity host,
                DualMachineSidecarPort.PeerIdentity android,
                DualMachineSidecarPort.ActivationChallengeRequest
                        activationChallenge,
                DualMachineSidecarPort.ActivationConfirmationRequest
                        activationConfirmation,
                DualMachineSidecarPort.EntitlementStatusRequest status,
                DualMachineSidecarPort.StartChallengeRequest startChallenge,
                DualMachineSidecarPort.StartUsageRequest start,
                DualMachineSidecarPort.StartCancellationRequest
                        startCancellation,
                DualMachineSidecarPort.HeartbeatRequest heartbeat,
                DualMachineSidecarPort.StopRequest stop) {
            this.host = host;
            this.android = android;
            this.activationChallenge = activationChallenge;
            this.activationConfirmation = activationConfirmation;
            this.status = status;
            this.startChallenge = startChallenge;
            this.start = start;
            this.startCancellation = startCancellation;
            this.heartbeat = heartbeat;
            this.stop = stop;
        }
    }
}
