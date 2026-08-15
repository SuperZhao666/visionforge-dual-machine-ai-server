package com.visionforge.inferencebenchmark;

/**
 * Dependency-free canonical payload contract for the independent dual-machine
 * card sidecar. Both devices reconstruct these bytes from structured fields;
 * neither side signs arbitrary peer-supplied bytes.
 */
public final class DualMachineUsageAuthorizationContract {
    public static final int PROTOCOL_VERSION = 2;
    public static final String ACTIVATION_MODE_ACTIVATE = "activate";
    public static final String ACTIVATION_MODE_REACTIVATE = "reactivate";
    public static final String ACTIVATION_MODE_BIND_DEVICE = "bind_device";
    public static final String ACTIVATION_CONFIRM_DOMAIN =
            "visionforge-dual-machine-card-activate-v1";
    public static final String USAGE_START_CHALLENGE_DOMAIN =
            "visionforge-dual-machine-usage-start-challenge-v1";
    public static final String USAGE_START_DOMAIN =
            "visionforge-dual-machine-usage-start-v1";
    public static final String USAGE_START_CANCEL_DOMAIN =
            "visionforge-dual-machine-usage-start-cancel-v1";
    public static final String USAGE_HEARTBEAT_DOMAIN =
            "visionforge-dual-machine-usage-heartbeat-v1";
    public static final String USAGE_STOP_DOMAIN =
            "visionforge-dual-machine-usage-stop-v1";
    public static final String ENTITLEMENT_STATUS_DOMAIN =
            "visionforge-dual-machine-entitlement-status-v1";

    private static final int HEX_128_CHARACTERS = 32;
    private static final int SHA256_CHARACTERS = 64;
    private static final int MAXIMUM_DEVICE_CODE_CHARACTERS = 128;
    private static final int MAXIMUM_CLIENT_VERSION_CHARACTERS = 80;

    private DualMachineUsageAuthorizationContract() {
    }

    public static byte[] activationConfirmation(ActivationConfirmation proof) {
        requireActivationMode(
                proof.activationMode, proof.targetEntitlementId);
        requireClientVersion(proof.androidClientVersion, "androidClientVersion");
        requireDeviceCode(proof.androidDeviceCode, "androidDeviceCode");
        requireHex(
                proof.androidDeviceProfileSha256,
                SHA256_CHARACTERS,
                "androidDeviceProfileSha256");
        requireHex(proof.androidKeySha256, SHA256_CHARACTERS, "androidKeySha256");
        requireHex(proof.challengeId, HEX_128_CHARACTERS, "challengeId");
        requireHex(proof.challengeTokenSha256, SHA256_CHARACTERS,
                "challengeTokenSha256");
        requireClientVersion(proof.hostClientVersion, "hostClientVersion");
        requireDeviceCode(proof.hostDeviceCode, "hostDeviceCode");
        requireHex(proof.hostKeySha256, SHA256_CHARACTERS, "hostKeySha256");
        requireHex(proof.pairId, HEX_128_CHARACTERS, "pairId");
        requireProtocolVersion(proof.protocolVersion);
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        StringBuilder payload = begin();
        stringField(payload, "activation_mode", proof.activationMode, true);
        stringField(payload, "android_client_version", proof.androidClientVersion, false);
        stringField(payload, "android_device_code", proof.androidDeviceCode, false);
        stringField(payload, "android_device_profile_sha256",
                proof.androidDeviceProfileSha256, false);
        stringField(payload, "android_key_sha256", proof.androidKeySha256, false);
        stringField(payload, "challenge_id", proof.challengeId, false);
        stringField(payload, "challenge_token_sha256",
                proof.challengeTokenSha256, false);
        stringField(payload, "domain", ACTIVATION_CONFIRM_DOMAIN, false);
        stringField(payload, "host_client_version", proof.hostClientVersion, false);
        stringField(payload, "host_device_code", proof.hostDeviceCode, false);
        stringField(payload, "host_key_sha256", proof.hostKeySha256, false);
        stringField(payload, "pair_id", proof.pairId, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "target_entitlement_id",
                proof.targetEntitlementId, false);
        return finish(payload);
    }

    private static void requireActivationMode(
            String activationMode,
            String targetEntitlementId) {
        String target = targetEntitlementId == null
                ? "" : targetEntitlementId;
        if (ACTIVATION_MODE_ACTIVATE.equals(activationMode)) {
            if (!target.isEmpty()) {
                throw new IllegalArgumentException(
                        "initial activation target must be empty");
            }
            return;
        }
        if (!ACTIVATION_MODE_REACTIVATE.equals(activationMode)
                && !ACTIVATION_MODE_BIND_DEVICE.equals(activationMode)) {
            throw new IllegalArgumentException(
                    "activationMode is invalid");
        }
        requireHex(target, HEX_128_CHARACTERS, "targetEntitlementId");
    }

    public static byte[] usageStartChallenge(UsageStartChallenge proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        requireHex(proof.channelBindingSha256, SHA256_CHARACTERS,
                "channelBindingSha256");
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        StringBuilder payload = begin();
        stringField(payload, "channel_binding_sha256",
                proof.channelBindingSha256, true);
        stringField(payload, "domain", USAGE_START_CHALLENGE_DOMAIN, false);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        stringField(payload, "pair_id", proof.pairId, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        return finish(payload);
    }

    public static byte[] usageStart(UsageStart proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        if (!proof.androidRuntimeReady || !proof.hostRuntimeReady
                || proof.androidFramesTotal < 0L || proof.hostFramesTotal < 0L) {
            throw new IllegalArgumentException(
                    "both runtimes must be ready with non-negative baselines");
        }
        requireHex(proof.channelBindingSha256, SHA256_CHARACTERS,
                "channelBindingSha256");
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        requireHex(proof.startChallengeId, HEX_128_CHARACTERS,
                "startChallengeId");
        requireHex(proof.startChallengeTokenSha256, SHA256_CHARACTERS,
                "startChallengeTokenSha256");
        StringBuilder payload = begin();
        numberField(payload, "android_frames_total", proof.androidFramesTotal, true);
        booleanField(payload, "android_runtime_ready",
                proof.androidRuntimeReady, false);
        stringField(payload, "channel_binding_sha256",
                proof.channelBindingSha256, false);
        stringField(payload, "domain", USAGE_START_DOMAIN, false);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        numberField(payload, "host_frames_total", proof.hostFramesTotal, false);
        booleanField(payload, "host_runtime_ready", proof.hostRuntimeReady, false);
        stringField(payload, "pair_id", proof.pairId, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        stringField(payload, "start_challenge_id", proof.startChallengeId, false);
        stringField(payload, "start_challenge_token_sha256",
                proof.startChallengeTokenSha256, false);
        return finish(payload);
    }

    public static byte[] usageStartCancel(UsageStartCancel proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        requireHex(proof.channelBindingSha256, SHA256_CHARACTERS,
                "channelBindingSha256");
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        requireHex(proof.startRequestId, HEX_128_CHARACTERS,
                "startRequestId");
        StringBuilder payload = begin();
        stringField(payload, "channel_binding_sha256",
                proof.channelBindingSha256, true);
        stringField(payload, "domain", USAGE_START_CANCEL_DOMAIN, false);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        stringField(payload, "pair_id", proof.pairId, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        stringField(payload, "start_request_id", proof.startRequestId, false);
        return finish(payload);
    }

    public static byte[] usageHeartbeat(UsageHeartbeat proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        if (proof.androidFramesTotal < 0L || proof.hostFramesTotal < 0L
                || proof.sequence <= 0L) {
            throw new IllegalArgumentException("heartbeat counters are invalid");
        }
        requireHex(proof.channelBindingSha256, SHA256_CHARACTERS,
                "channelBindingSha256");
        requireHex(proof.previousLeaseSha256, SHA256_CHARACTERS,
                "previousLeaseSha256");
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        requireHex(proof.sessionId, HEX_128_CHARACTERS, "sessionId");
        StringBuilder payload = begin();
        numberField(payload, "android_frames_total", proof.androidFramesTotal, true);
        stringField(payload, "channel_binding_sha256",
                proof.channelBindingSha256, false);
        stringField(payload, "domain", USAGE_HEARTBEAT_DOMAIN, false);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        numberField(payload, "host_frames_total", proof.hostFramesTotal, false);
        stringField(payload, "pair_id", proof.pairId, false);
        stringField(payload, "previous_lease_sha256",
                proof.previousLeaseSha256, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        numberField(payload, "sequence", proof.sequence, false);
        stringField(payload, "session_id", proof.sessionId, false);
        return finish(payload);
    }

    public static byte[] usageStop(UsageStop proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        requireHex(proof.channelBindingSha256, SHA256_CHARACTERS,
                "channelBindingSha256");
        requireHex(proof.previousLeaseSha256, SHA256_CHARACTERS,
                "previousLeaseSha256");
        requireHex(proof.requestId, HEX_128_CHARACTERS, "requestId");
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        requireHex(proof.sessionId, HEX_128_CHARACTERS, "sessionId");
        StringBuilder payload = begin();
        stringField(payload, "channel_binding_sha256",
                proof.channelBindingSha256, true);
        stringField(payload, "domain", USAGE_STOP_DOMAIN, false);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        stringField(payload, "pair_id", proof.pairId, false);
        stringField(payload, "previous_lease_sha256",
                proof.previousLeaseSha256, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_id", proof.requestId, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        stringField(payload, "session_id", proof.sessionId, false);
        return finish(payload);
    }

    public static byte[] entitlementStatus(EntitlementStatus proof) {
        requireCommonUsage(proof.entitlementId, proof.pairId,
                proof.protocolVersion, proof.revocationVersion);
        requireHex(proof.requestNonce, HEX_128_CHARACTERS, "requestNonce");
        StringBuilder payload = begin();
        stringField(payload, "domain", ENTITLEMENT_STATUS_DOMAIN, true);
        stringField(payload, "entitlement_id", proof.entitlementId, false);
        stringField(payload, "pair_id", proof.pairId, false);
        numberField(payload, "protocol_version", proof.protocolVersion, false);
        stringField(payload, "request_nonce", proof.requestNonce, false);
        numberField(payload, "revocation_version", proof.revocationVersion, false);
        return finish(payload);
    }

    private static void requireCommonUsage(String entitlementId, String pairId,
                                           int protocolVersion,
                                           long revocationVersion) {
        requireHex(entitlementId, HEX_128_CHARACTERS, "entitlementId");
        requireHex(pairId, HEX_128_CHARACTERS, "pairId");
        requireProtocolVersion(protocolVersion);
        if (revocationVersion <= 0L) {
            throw new IllegalArgumentException("revocationVersion must be positive");
        }
    }

    private static void requireProtocolVersion(int protocolVersion) {
        if (protocolVersion != PROTOCOL_VERSION) {
            throw new IllegalArgumentException("unsupported protocol version");
        }
    }

    private static void requireHex(String value, int length, String name) {
        if (value == null || value.length() != length) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        boolean nonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(name + " is not lowercase hex");
            }
            nonzero = nonzero || character != '0';
        }
        if (!nonzero) {
            throw new IllegalArgumentException(name + " must not be all zero");
        }
    }

    private static void requireDeviceCode(String value, String name) {
        if (value == null || value.isEmpty()
                || value.length() > MAXIMUM_DEVICE_CODE_CHARACTERS) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '_'
                    || character == ':' || character == '-')) {
                throw new IllegalArgumentException(name + " has invalid characters");
            }
        }
    }

    private static void requireClientVersion(String value, String name) {
        if (value == null || value.isEmpty()
                || value.length() > MAXIMUM_CLIENT_VERSION_CHARACTERS) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        boolean digitSeen = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character >= '0' && character <= '9') {
                digitSeen = true;
            } else if (character != '.' && character != '-'
                    && character != '+' && character != '_'
                    && !(character >= 'A' && character <= 'Z')
                    && !(character >= 'a' && character <= 'z')) {
                throw new IllegalArgumentException(name + " has invalid characters");
            }
        }
        if (!digitSeen) {
            throw new IllegalArgumentException(name + " must contain a digit");
        }
    }

    private static StringBuilder begin() {
        return new StringBuilder(512).append('{');
    }

    private static byte[] finish(StringBuilder payload) {
        payload.append('}');
        return payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void stringField(StringBuilder destination, String key,
                                    String value, boolean first) {
        separator(destination, first);
        quoted(destination, key);
        destination.append(':');
        quoted(destination, value);
    }

    private static void numberField(StringBuilder destination, String key,
                                    long value, boolean first) {
        if (value < 0L) throw new IllegalArgumentException(key + " must not be negative");
        separator(destination, first);
        quoted(destination, key);
        destination.append(':').append(value);
    }

    private static void booleanField(StringBuilder destination, String key,
                                     boolean value, boolean first) {
        separator(destination, first);
        quoted(destination, key);
        destination.append(':').append(value);
    }

    private static void separator(StringBuilder destination, boolean first) {
        if (!first) destination.append(',');
    }

    private static void quoted(StringBuilder destination, String value) {
        destination.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"':
                    destination.append("\\\"");
                    break;
                case '\\':
                    destination.append("\\\\");
                    break;
                case '\b':
                    destination.append("\\b");
                    break;
                case '\f':
                    destination.append("\\f");
                    break;
                case '\n':
                    destination.append("\\n");
                    break;
                case '\r':
                    destination.append("\\r");
                    break;
                case '\t':
                    destination.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        destination.append(String.format(java.util.Locale.ROOT,
                                "\\u%04x", (int) character));
                    } else {
                        destination.append(character);
                    }
                    break;
            }
        }
        destination.append('"');
    }

    public static final class ActivationConfirmation {
        public String activationMode;
        public String androidClientVersion;
        public String androidDeviceCode;
        public String androidDeviceProfileSha256;
        public String androidKeySha256;
        public String challengeId;
        public String challengeTokenSha256;
        public String hostClientVersion;
        public String hostDeviceCode;
        public String hostKeySha256;
        public String pairId;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String targetEntitlementId;
    }

    public static final class UsageStartChallenge {
        public String channelBindingSha256;
        public String entitlementId;
        public String pairId;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String requestNonce;
        public long revocationVersion;
    }

    public static final class UsageStart {
        public long androidFramesTotal;
        public boolean androidRuntimeReady;
        public String channelBindingSha256;
        public String entitlementId;
        public long hostFramesTotal;
        public boolean hostRuntimeReady;
        public String pairId;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String requestNonce;
        public long revocationVersion;
        public String startChallengeId;
        public String startChallengeTokenSha256;
    }

    public static final class UsageStartCancel {
        public String channelBindingSha256;
        public String entitlementId;
        public String pairId;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String requestNonce;
        public long revocationVersion;
        public String startRequestId;
    }

    public static final class UsageHeartbeat {
        public long androidFramesTotal;
        public String channelBindingSha256;
        public String entitlementId;
        public long hostFramesTotal;
        public String pairId;
        public String previousLeaseSha256;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String requestNonce;
        public long revocationVersion;
        public long sequence;
        public String sessionId;
    }

    public static final class UsageStop {
        public String channelBindingSha256;
        public String entitlementId;
        public String pairId;
        public String previousLeaseSha256;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestId;
        public String requestNonce;
        public long revocationVersion;
        public String sessionId;
    }

    public static final class EntitlementStatus {
        public String entitlementId;
        public String pairId;
        public int protocolVersion = PROTOCOL_VERSION;
        public String requestNonce;
        public long revocationVersion;
    }
}
