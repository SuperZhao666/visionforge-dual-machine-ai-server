package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;

public final class DualMachineUsageAuthorizationContractSelfTest {
    private DualMachineUsageAuthorizationContractSelfTest() {
    }

    public static void main(String[] args) {
        String h1 = "1".repeat(32);
        String h2 = "2".repeat(32);
        String h3 = "3".repeat(32);
        String h4 = "4".repeat(32);
        String s5 = "5".repeat(64);
        String s7 = "7".repeat(64);
        String activationTokenSha256 =
                "d066a4f4c1bea1ab8d47372ded551bc3f1d06dcba0608d179c4a6d2844fec548";
        String startTokenSha256 =
                "e2ae1865c75fe404f1e7b3049aab3c729bc5114998665ea2ff7aaa68cb0e9381";
        String previousLeaseSha256 =
                "292c06e5943f1f0f623acbb683d00c6b5b6ecd5359336fdf7f0f124f1f387434";

        DualMachineUsageAuthorizationContract.ActivationConfirmation activation =
                new DualMachineUsageAuthorizationContract.ActivationConfirmation();
        activation.activationMode = "activate";
        activation.androidClientVersion = "1.0.0";
        activation.androidDeviceCode = "ANDROID-ABC";
        activation.androidDeviceProfileSha256 = s7;
        activation.androidKeySha256 = s5;
        activation.challengeId = h1;
        activation.challengeTokenSha256 = activationTokenSha256;
        activation.hostClientVersion = "17.8.81";
        activation.hostDeviceCode = "HOST-XYZ";
        activation.hostKeySha256 = s7;
        activation.pairId = h2;
        activation.requestId = h3;
        activation.targetEntitlementId = "";
        check(text(DualMachineUsageAuthorizationContract
                .activationConfirmation(activation)).equals(
                "{\"activation_mode\":\"activate\","
                        + "\"android_client_version\":\"1.0.0\","
                        + "\"android_device_code\":\"ANDROID-ABC\","
                        + "\"android_device_profile_sha256\":\"" + s7
                        + "\","
                        + "\"android_key_sha256\":\"" + s5
                        + "\",\"challenge_id\":\"" + h1
                        + "\",\"challenge_token_sha256\":\"" + activationTokenSha256
                        + "\",\"domain\":\"visionforge-dual-machine-card-activate-v1\","
                        + "\"host_client_version\":\"17.8.81\","
                        + "\"host_device_code\":\"HOST-XYZ\","
                        + "\"host_key_sha256\":\"" + s7
                        + "\",\"pair_id\":\"" + h2
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"target_entitlement_id\":\"\"}"));

        activation.activationMode = "reactivate";
        activation.targetEntitlementId = h4;
        String reactivationPayload = text(
                DualMachineUsageAuthorizationContract
                        .activationConfirmation(activation));
        check(reactivationPayload.startsWith(
                "{\"activation_mode\":\"reactivate\","));
        check(reactivationPayload.endsWith(
                "\"target_entitlement_id\":\"" + h4 + "\"}"));
        activation.activationMode = "activate";
        activation.targetEntitlementId = "";

        DualMachineUsageAuthorizationContract.UsageStartChallenge challenge =
                new DualMachineUsageAuthorizationContract.UsageStartChallenge();
        challenge.channelBindingSha256 = s5;
        challenge.entitlementId = h1;
        challenge.pairId = h2;
        challenge.requestId = h3;
        challenge.requestNonce = h4;
        challenge.revocationVersion = 9L;
        check(text(DualMachineUsageAuthorizationContract
                .usageStartChallenge(challenge)).equals(
                "{\"channel_binding_sha256\":\"" + s5
                        + "\",\"domain\":\"visionforge-dual-machine-usage-start-challenge-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"pair_id\":\"" + h2
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9}"));

        DualMachineUsageAuthorizationContract.UsageStart start =
                new DualMachineUsageAuthorizationContract.UsageStart();
        start.androidFramesTotal = 11L;
        start.androidRuntimeReady = true;
        start.channelBindingSha256 = s5;
        start.entitlementId = h1;
        start.hostFramesTotal = 12L;
        start.hostRuntimeReady = true;
        start.pairId = h2;
        start.requestId = h3;
        start.requestNonce = h4;
        start.revocationVersion = 9L;
        start.startChallengeId = h4;
        start.startChallengeTokenSha256 = startTokenSha256;
        check(text(DualMachineUsageAuthorizationContract.usageStart(start)).equals(
                "{\"android_frames_total\":11,\"android_runtime_ready\":true,"
                        + "\"channel_binding_sha256\":\"" + s5
                        + "\",\"domain\":\"visionforge-dual-machine-usage-start-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"host_frames_total\":12,\"host_runtime_ready\":true,"
                        + "\"pair_id\":\"" + h2
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9,\"start_challenge_id\":\"" + h4
                        + "\",\"start_challenge_token_sha256\":\""
                        + startTokenSha256 + "\"}"));

        DualMachineUsageAuthorizationContract.UsageStartCancel startCancel =
                new DualMachineUsageAuthorizationContract.UsageStartCancel();
        startCancel.channelBindingSha256 = s5;
        startCancel.entitlementId = h1;
        startCancel.pairId = h2;
        startCancel.requestId = h3;
        startCancel.requestNonce = h4;
        startCancel.revocationVersion = 9L;
        startCancel.startRequestId = h2;
        check(text(DualMachineUsageAuthorizationContract
                .usageStartCancel(startCancel)).equals(
                "{\"channel_binding_sha256\":\"" + s5
                        + "\",\"domain\":\"visionforge-dual-machine-usage-start-cancel-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"pair_id\":\"" + h2
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9,\"start_request_id\":\""
                        + h2 + "\"}"));

        DualMachineUsageAuthorizationContract.UsageHeartbeat heartbeat =
                new DualMachineUsageAuthorizationContract.UsageHeartbeat();
        heartbeat.androidFramesTotal = 21L;
        heartbeat.channelBindingSha256 = s5;
        heartbeat.entitlementId = h1;
        heartbeat.hostFramesTotal = 22L;
        heartbeat.pairId = h2;
        heartbeat.previousLeaseSha256 = previousLeaseSha256;
        heartbeat.requestId = h3;
        heartbeat.requestNonce = h4;
        heartbeat.revocationVersion = 9L;
        heartbeat.sequence = 1L;
        heartbeat.sessionId = h4;
        check(text(DualMachineUsageAuthorizationContract
                .usageHeartbeat(heartbeat)).equals(
                "{\"android_frames_total\":21,\"channel_binding_sha256\":\"" + s5
                        + "\",\"domain\":\"visionforge-dual-machine-usage-heartbeat-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"host_frames_total\":22,\"pair_id\":\"" + h2
                        + "\",\"previous_lease_sha256\":\"" + previousLeaseSha256
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9,\"sequence\":1,\"session_id\":\""
                        + h4 + "\"}"));

        DualMachineUsageAuthorizationContract.UsageStop stop =
                new DualMachineUsageAuthorizationContract.UsageStop();
        stop.channelBindingSha256 = s5;
        stop.entitlementId = h1;
        stop.pairId = h2;
        stop.previousLeaseSha256 = previousLeaseSha256;
        stop.requestId = h3;
        stop.requestNonce = h4;
        stop.revocationVersion = 9L;
        stop.sessionId = h4;
        check(text(DualMachineUsageAuthorizationContract.usageStop(stop)).equals(
                "{\"channel_binding_sha256\":\"" + s5
                        + "\",\"domain\":\"visionforge-dual-machine-usage-stop-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"pair_id\":\"" + h2
                        + "\",\"previous_lease_sha256\":\"" + previousLeaseSha256
                        + "\",\"protocol_version\":2,\"request_id\":\"" + h3
                        + "\",\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9,\"session_id\":\"" + h4 + "\"}"));

        DualMachineUsageAuthorizationContract.EntitlementStatus status =
                new DualMachineUsageAuthorizationContract.EntitlementStatus();
        status.entitlementId = h1;
        status.pairId = h2;
        status.requestNonce = h4;
        status.revocationVersion = 9L;
        check(text(DualMachineUsageAuthorizationContract
                .entitlementStatus(status)).equals(
                "{\"domain\":\"visionforge-dual-machine-entitlement-status-v1\","
                        + "\"entitlement_id\":\"" + h1
                        + "\",\"pair_id\":\"" + h2
                        + "\",\"protocol_version\":2,\"request_nonce\":\"" + h4
                        + "\",\"revocation_version\":9}"));

        DualMachineUsageAuthorizationContract.UsageStart invalid =
                new DualMachineUsageAuthorizationContract.UsageStart();
        invalid.entitlementId = h1;
        invalid.pairId = h2;
        invalid.channelBindingSha256 = s5;
        invalid.requestId = h3;
        invalid.requestNonce = h4;
        invalid.revocationVersion = 1L;
        invalid.startChallengeId = h4;
        invalid.startChallengeTokenSha256 = startTokenSha256;
        expectIllegalArgument(() ->
                DualMachineUsageAuthorizationContract.usageStart(invalid));
        invalid.androidRuntimeReady = true;
        invalid.hostRuntimeReady = true;
        check(DualMachineUsageAuthorizationContract.usageStart(invalid).length > 0);

        String zero128 = "0".repeat(32);
        String zero256 = "0".repeat(64);
        activation.targetEntitlementId = h4;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .activationConfirmation(activation));
        activation.activationMode = "reactivate";
        activation.targetEntitlementId = "";
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .activationConfirmation(activation));
        activation.targetEntitlementId = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .activationConfirmation(activation));
        activation.activationMode = "bind_device";
        activation.targetEntitlementId = h4;
        check(DualMachineUsageAuthorizationContract
                .activationConfirmation(activation).length > 0);
        activation.targetEntitlementId = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .activationConfirmation(activation));
        activation.activationMode = "activate";
        activation.targetEntitlementId = "";
        activation.androidKeySha256 = zero256;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .activationConfirmation(activation));
        challenge.entitlementId = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageStartChallenge(challenge));
        challenge.entitlementId = h1;
        challenge.channelBindingSha256 = zero256;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageStartChallenge(challenge));
        challenge.channelBindingSha256 = s5;
        challenge.requestNonce = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageStartChallenge(challenge));
        invalid.startChallengeTokenSha256 = zero256;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageStart(invalid));
        heartbeat.previousLeaseSha256 = zero256;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageHeartbeat(heartbeat));
        stop.sessionId = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .usageStop(stop));
        status.requestNonce = zero128;
        expectIllegalArgument(() -> DualMachineUsageAuthorizationContract
                .entitlementStatus(status));

        System.out.println("ANDROID_USAGE_AUTHORIZATION_CONTRACT_OK");
    }

    private static String text(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("contract assertion failed");
    }

    private static void expectIllegalArgument(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
        }
    }
}
