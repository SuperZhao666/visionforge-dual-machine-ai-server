package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Explicit, account-free card and metered-usage boundary for the independent
 * dual-machine sidecar.
 *
 * <p>Every network action is a separate method. Implementations must never
 * turn activation, status inspection or challenge creation into an implicit
 * formal start or heartbeat.</p>
 */
public interface DualMachineSidecarPort {
    int PROTOCOL_VERSION = 2;

    /**
     * Bounded sidecar rejection. The response body is deliberately discarded;
     * only an allow-listed error code may cross the transport boundary.
     */
    final class RejectedException extends IOException {
        public final int statusCode;
        public final String safeErrorCode;

        RejectedException(int statusCode) {
            this(statusCode, "");
        }

        RejectedException(int statusCode, String safeErrorCode) {
            super("dual-machine sidecar rejected the request (HTTP "
                    + statusCode + ")");
            this.statusCode = statusCode;
            this.safeErrorCode = safeErrorCode == null ? "" : safeErrorCode;
        }
    }

    ActivationChallengeResponse createActivationChallenge(
            ActivationChallengeRequest request) throws IOException;

    ActivationResponse confirmActivation(
            ActivationConfirmationRequest request) throws IOException;

    EntitlementStatusResponse fetchEntitlementStatus(
            EntitlementStatusRequest request) throws IOException;

    StartChallengeResponse createStartChallenge(
            StartChallengeRequest request) throws IOException;

    UsageLeaseResponse startUsage(StartUsageRequest request)
            throws IOException;

    StartCancellationResponse cancelStart(StartCancellationRequest request)
            throws IOException;

    UsageLeaseResponse heartbeat(HeartbeatRequest request)
            throws IOException;

    StopResponse stop(StopRequest request) throws IOException;

    final class PeerIdentity {
        public final String deviceCode;
        public final String clientVersion;
        public final String identityPublicKeyBase64;
        public final DualMachineAndroidDeviceProfile deviceProfile;

        public PeerIdentity(
                String deviceCode,
                String clientVersion,
                String identityPublicKeyBase64) {
            this(deviceCode, clientVersion, identityPublicKeyBase64, null);
        }

        public PeerIdentity(
                String deviceCode,
                String clientVersion,
                String identityPublicKeyBase64,
                DualMachineAndroidDeviceProfile deviceProfile) {
            this.deviceCode = DualMachineSidecarValues.deviceCode(deviceCode);
            this.clientVersion =
                    DualMachineSidecarValues.clientVersion(clientVersion);
            this.identityPublicKeyBase64 =
                    DualMachineSidecarValues.identityPublicKey(
                            identityPublicKeyBase64);
            this.deviceProfile = deviceProfile;
        }
    }

    final class ActivationChallengeRequest {
        public final String requestId;
        public final String pairId;
        public final int protocolVersion;
        public final String cardCode;
        public final PeerIdentity host;
        public final PeerIdentity android;

        public ActivationChallengeRequest(
                String requestId,
                String pairId,
                String cardCode,
                PeerIdentity host,
                PeerIdentity android) {
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.pairId = DualMachineSidecarValues.hex128(pairId, "pairId");
            this.protocolVersion = PROTOCOL_VERSION;
            this.cardCode = DualMachineSidecarValues.cardCode(cardCode);
            if (host == null || android == null) {
                throw new IllegalArgumentException(
                        "both peer identities are required");
            }
            if (host.identityPublicKeyBase64.equals(
                    android.identityPublicKeyBase64)) {
                throw new IllegalArgumentException(
                        "peer identities must differ");
            }
            this.host = host;
            this.android = android;
        }
    }

    final class ActivationConfirmationRequest {
        public final String challengeId;
        public final String challengeToken;
        public final String hostSignatureBase64;
        public final String androidSignatureBase64;

        public ActivationConfirmationRequest(
                String challengeId,
                String challengeToken,
                String hostSignatureBase64,
                String androidSignatureBase64) {
            this.challengeId = DualMachineSidecarValues.hex128(
                    challengeId, "challengeId");
            this.challengeToken = DualMachineSidecarValues.challengeToken(
                    challengeToken);
            this.hostSignatureBase64 = DualMachineSidecarValues.signature(
                    hostSignatureBase64, "hostSignatureBase64");
            this.androidSignatureBase64 = DualMachineSidecarValues.signature(
                    androidSignatureBase64, "androidSignatureBase64");
        }
    }

    final class UsageProof {
        public final String entitlementId;
        public final String pairId;
        public final int protocolVersion;
        public final long revocationVersion;
        public final String hostSignatureBase64;
        public final String androidSignatureBase64;

        public UsageProof(
                String entitlementId,
                String pairId,
                long revocationVersion,
                String hostSignatureBase64,
                String androidSignatureBase64) {
            this.entitlementId = DualMachineSidecarValues.hex128(
                    entitlementId, "entitlementId");
            this.pairId = DualMachineSidecarValues.hex128(pairId, "pairId");
            this.protocolVersion = PROTOCOL_VERSION;
            if (revocationVersion <= 0L) {
                throw new IllegalArgumentException(
                        "revocationVersion must be positive");
            }
            this.revocationVersion = revocationVersion;
            this.hostSignatureBase64 = DualMachineSidecarValues.signature(
                    hostSignatureBase64, "hostSignatureBase64");
            this.androidSignatureBase64 = DualMachineSidecarValues.signature(
                    androidSignatureBase64, "androidSignatureBase64");
        }
    }

    final class EntitlementStatusRequest {
        public final UsageProof proof;
        public final String requestNonce;

        public EntitlementStatusRequest(
                UsageProof proof,
                String requestNonce) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
        }
    }

    final class StartChallengeRequest {
        public final UsageProof proof;
        public final String requestId;
        public final String requestNonce;
        public final String channelBindingSha256;

        public StartChallengeRequest(
                UsageProof proof,
                String requestId,
                String requestNonce,
                String channelBindingSha256) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
        }
    }

    final class StartUsageRequest {
        public final UsageProof proof;
        public final String requestId;
        public final String requestNonce;
        public final String channelBindingSha256;
        public final boolean hostRuntimeReady;
        public final boolean androidRuntimeReady;
        public final long hostFramesTotal;
        public final long androidFramesTotal;
        public final String startChallengeId;
        public final String startChallengeToken;

        public StartUsageRequest(
                UsageProof proof,
                String requestId,
                String requestNonce,
                String channelBindingSha256,
                long hostFramesTotal,
                long androidFramesTotal,
                String startChallengeId,
                String startChallengeToken) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
            this.hostRuntimeReady = true;
            this.androidRuntimeReady = true;
            this.hostFramesTotal = DualMachineSidecarValues.counter(
                    hostFramesTotal, "hostFramesTotal");
            this.androidFramesTotal = DualMachineSidecarValues.counter(
                    androidFramesTotal, "androidFramesTotal");
            this.startChallengeId = DualMachineSidecarValues.hex128(
                    startChallengeId, "startChallengeId");
            this.startChallengeToken =
                    DualMachineSidecarValues.challengeToken(
                            startChallengeToken);
        }
    }

    final class HeartbeatRequest {
        public final UsageProof proof;
        public final String sessionId;
        public final String requestId;
        public final String requestNonce;
        public final String channelBindingSha256;
        public final long sequence;
        public final long hostFramesTotal;
        public final long androidFramesTotal;
        public final String previousLease;

        public HeartbeatRequest(
                UsageProof proof,
                String sessionId,
                String requestId,
                String requestNonce,
                String channelBindingSha256,
                long sequence,
                long hostFramesTotal,
                long androidFramesTotal,
                String previousLease) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.sessionId = DualMachineSidecarValues.hex128(
                    sessionId, "sessionId");
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
            if (sequence <= 0L) {
                throw new IllegalArgumentException(
                        "sequence must be positive");
            }
            this.sequence = sequence;
            this.hostFramesTotal = DualMachineSidecarValues.counter(
                    hostFramesTotal, "hostFramesTotal");
            this.androidFramesTotal = DualMachineSidecarValues.counter(
                    androidFramesTotal, "androidFramesTotal");
            this.previousLease = DualMachineSidecarValues.usageLease(
                    previousLease, "previousLease");
        }
    }

    final class StartCancellationRequest {
        public final UsageProof proof;
        public final String requestId;
        public final String requestNonce;
        public final String startRequestId;
        public final String channelBindingSha256;

        public StartCancellationRequest(
                UsageProof proof,
                String requestId,
                String requestNonce,
                String startRequestId,
                String channelBindingSha256) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
            this.startRequestId = DualMachineSidecarValues.hex128(
                    startRequestId, "startRequestId");
            if (this.requestId.equals(this.requestNonce)
                    || this.requestId.equals(this.startRequestId)
                    || this.requestNonce.equals(this.startRequestId)) {
                throw new IllegalArgumentException(
                        "start cancellation identifiers must differ");
            }
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
        }
    }

    final class StopRequest {
        public final UsageProof proof;
        public final String sessionId;
        public final String requestId;
        public final String requestNonce;
        public final String channelBindingSha256;
        public final String previousLease;

        public StopRequest(
                UsageProof proof,
                String sessionId,
                String requestId,
                String requestNonce,
                String channelBindingSha256,
                String previousLease) {
            this.proof = DualMachineSidecarValues.proof(proof);
            this.sessionId = DualMachineSidecarValues.hex128(
                    sessionId, "sessionId");
            this.requestId = DualMachineSidecarValues.hex128(
                    requestId, "requestId");
            this.requestNonce = DualMachineSidecarValues.hex128(
                    requestNonce, "requestNonce");
            this.channelBindingSha256 = DualMachineSidecarValues.sha256(
                    channelBindingSha256, "channelBindingSha256");
            this.previousLease = DualMachineSidecarValues.usageLease(
                    previousLease, "previousLease");
        }
    }

    final class ActivationChallengeResponse {
        public final String challengeId;
        public final String challengeToken;
        public final long expiresAtEpoch;
        public final String activationMode;
        public final String targetEntitlementId;
        public final String androidDeviceProfileSha256;
        private final byte[] proofPayload;

        ActivationChallengeResponse(
                String challengeId,
                String challengeToken,
                long expiresAtEpoch,
                String activationMode,
                String targetEntitlementId,
                String androidDeviceProfileSha256,
                byte[] proofPayload) {
            this.challengeId = challengeId;
            this.challengeToken = challengeToken;
            this.expiresAtEpoch = expiresAtEpoch;
            if (!DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_ACTIVATE.equals(activationMode)
                    && !DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_REACTIVATE.equals(activationMode)
                    && !DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_BIND_DEVICE.equals(activationMode)) {
                throw new IllegalArgumentException(
                        "activation mode is invalid");
            }
            this.activationMode = activationMode;
            String target = targetEntitlementId == null
                    ? "" : targetEntitlementId;
            if (DualMachineUsageAuthorizationContract
                    .ACTIVATION_MODE_ACTIVATE.equals(activationMode)) {
                if (!target.isEmpty()) {
                    throw new IllegalArgumentException(
                            "initial activation target must be empty");
                }
                this.targetEntitlementId = "";
            } else {
                this.targetEntitlementId = DualMachineSidecarValues.hex128(
                        target, "targetEntitlementId");
            }
            this.androidDeviceProfileSha256 =
                    DualMachineSidecarValues.sha256(
                            androidDeviceProfileSha256,
                            "androidDeviceProfileSha256");
            if (proofPayload == null || proofPayload.length == 0) {
                throw new IllegalArgumentException(
                        "activation proof payload is required");
            }
            this.proofPayload = proofPayload.clone();
        }

        public byte[] proofPayload() {
            return proofPayload.clone();
        }
    }

    final class ActivationResponse {
        public final String entitlementId;
        public final String pairId;
        public final long revocationVersion;
        public final long creditedSeconds;
        public final long remainingSeconds;
        public final long totalCreditedSeconds;
        public final long totalConsumedSeconds;
        public final boolean billingStarted;
        public final String activationMode;
        public final boolean bindingUpdated;
        public final String authorizationKind;
        public final String productKey;
        public final boolean permanent;

        ActivationResponse(
                String entitlementId,
                String pairId,
                long revocationVersion,
                long creditedSeconds,
                long remainingSeconds,
                long totalCreditedSeconds,
                long totalConsumedSeconds,
                boolean billingStarted) {
            this(
                    entitlementId,
                    pairId,
                    revocationVersion,
                    creditedSeconds,
                    remainingSeconds,
                    totalCreditedSeconds,
                    totalConsumedSeconds,
                    billingStarted,
                    DualMachineUsageAuthorizationContract
                            .ACTIVATION_MODE_ACTIVATE,
                    false,
                    "day",
                    "day",
                    false);
        }

        ActivationResponse(
                String entitlementId,
                String pairId,
                long revocationVersion,
                long creditedSeconds,
                long remainingSeconds,
                long totalCreditedSeconds,
                long totalConsumedSeconds,
                boolean billingStarted,
                String activationMode,
                boolean bindingUpdated,
                String authorizationKind,
                String productKey,
                boolean permanent) {
            this.entitlementId = entitlementId;
            this.pairId = pairId;
            this.revocationVersion = revocationVersion;
            this.creditedSeconds = creditedSeconds;
            this.remainingSeconds = remainingSeconds;
            this.totalCreditedSeconds = totalCreditedSeconds;
            this.totalConsumedSeconds = totalConsumedSeconds;
            this.billingStarted = billingStarted;
            this.activationMode = activationMode;
            this.bindingUpdated = bindingUpdated;
            this.authorizationKind = authorizationKind;
            this.productKey = productKey;
            this.permanent = permanent;
        }
    }

    final class EntitlementStatusResponse {
        public final String status;
        public final long revocationVersion;
        public final long remainingSeconds;
        public final long totalCreditedSeconds;
        public final long totalConsumedSeconds;
        public final String usageSessionStatus;
        public final String authorizationKind;
        public final String productKey;
        public final boolean permanent;

        EntitlementStatusResponse(
                String status,
                long revocationVersion,
                long remainingSeconds,
                long totalCreditedSeconds,
                long totalConsumedSeconds,
                String usageSessionStatus) {
            this(
                    status,
                    revocationVersion,
                    remainingSeconds,
                    totalCreditedSeconds,
                    totalConsumedSeconds,
                    usageSessionStatus,
                    "day",
                    "day",
                    false);
        }

        EntitlementStatusResponse(
                String status,
                long revocationVersion,
                long remainingSeconds,
                long totalCreditedSeconds,
                long totalConsumedSeconds,
                String usageSessionStatus,
                String authorizationKind,
                String productKey,
                boolean permanent) {
            this.status = status;
            this.revocationVersion = revocationVersion;
            this.remainingSeconds = remainingSeconds;
            this.totalCreditedSeconds = totalCreditedSeconds;
            this.totalConsumedSeconds = totalConsumedSeconds;
            this.usageSessionStatus = usageSessionStatus;
            this.authorizationKind = authorizationKind;
            this.productKey = productKey;
            this.permanent = permanent;
        }
    }

    final class StartChallengeResponse {
        public final String challengeId;
        public final String challengeToken;
        public final long expiresAtEpoch;

        StartChallengeResponse(
                String challengeId,
                String challengeToken,
                long expiresAtEpoch) {
            this.challengeId = challengeId;
            this.challengeToken = challengeToken;
            this.expiresAtEpoch = expiresAtEpoch;
        }
    }

    final class UsageLeaseResponse {
        public final String sessionId;
        public final long sequence;
        public final long chargedSeconds;
        public final long remainingSeconds;
        public final long totalConsumedSeconds;
        public final String usageLease;
        public final String usageLeaseSha256;
        public final long notBeforeEpoch;
        public final long expiresAtEpoch;
        public final long ttlSeconds;
        public final boolean billingStarted;
        public final String authorizationKind;
        public final String productKey;
        public final boolean permanent;

        UsageLeaseResponse(
                String sessionId,
                long sequence,
                long chargedSeconds,
                long remainingSeconds,
                long totalConsumedSeconds,
                String usageLease,
                String usageLeaseSha256,
                long notBeforeEpoch,
                long expiresAtEpoch,
                long ttlSeconds,
                boolean billingStarted) {
            this(
                    sessionId,
                    sequence,
                    chargedSeconds,
                    remainingSeconds,
                    totalConsumedSeconds,
                    usageLease,
                    usageLeaseSha256,
                    notBeforeEpoch,
                    expiresAtEpoch,
                    ttlSeconds,
                    billingStarted,
                    "day",
                    "day",
                    false);
        }

        UsageLeaseResponse(
                String sessionId,
                long sequence,
                long chargedSeconds,
                long remainingSeconds,
                long totalConsumedSeconds,
                String usageLease,
                String usageLeaseSha256,
                long notBeforeEpoch,
                long expiresAtEpoch,
                long ttlSeconds,
                boolean billingStarted,
                String authorizationKind,
                String productKey,
                boolean permanent) {
            this.sessionId = sessionId;
            this.sequence = sequence;
            this.chargedSeconds = chargedSeconds;
            this.remainingSeconds = remainingSeconds;
            this.totalConsumedSeconds = totalConsumedSeconds;
            this.usageLease = usageLease;
            this.usageLeaseSha256 = usageLeaseSha256;
            this.notBeforeEpoch = notBeforeEpoch;
            this.expiresAtEpoch = expiresAtEpoch;
            this.ttlSeconds = ttlSeconds;
            this.billingStarted = billingStarted;
            this.authorizationKind = authorizationKind;
            this.productKey = productKey;
            this.permanent = permanent;
        }
    }

    final class StopResponse {
        public final String sessionId;
        public final String status;
        public final long remainingSeconds;
        public final long chargedSeconds;
        public final boolean billingStarted;
        public final String authorizationKind;
        public final boolean permanent;

        StopResponse(
                String sessionId,
                String status,
                long remainingSeconds) {
            this(
                    sessionId,
                    status,
                    remainingSeconds,
                    0L,
                    false,
                    "day",
                    false);
        }

        StopResponse(
                String sessionId,
                String status,
                long remainingSeconds,
                long chargedSeconds,
                boolean billingStarted,
                String authorizationKind,
                boolean permanent) {
            this.sessionId = sessionId;
            this.status = status;
            this.remainingSeconds = remainingSeconds;
            this.chargedSeconds = chargedSeconds;
            this.billingStarted = billingStarted;
            this.authorizationKind = authorizationKind;
            this.permanent = permanent;
        }
    }

    final class StartCancellationResponse {
        public final String startRequestId;
        public final String sessionId;
        public final String sessionStatus;
        public final long remainingSeconds;
        public final long chargedSeconds;
        public final boolean billingStarted;
        public final String authorizationKind;
        public final boolean permanent;

        StartCancellationResponse(
                String startRequestId,
                String sessionId,
                String sessionStatus,
                long remainingSeconds,
                long chargedSeconds,
                boolean billingStarted,
                String authorizationKind,
                boolean permanent) {
            this.startRequestId = DualMachineSidecarValues.hex128(
                    startRequestId, "startRequestId");
            String normalizedSessionId = sessionId == null ? "" : sessionId;
            if (!normalizedSessionId.isEmpty()) {
                normalizedSessionId = DualMachineSidecarValues.hex128(
                        normalizedSessionId, "sessionId");
            }
            boolean notStarted = "not_started".equals(sessionStatus);
            boolean terminalSession = "ended".equals(sessionStatus)
                    || "exhausted".equals(sessionStatus)
                    || "revoked".equals(sessionStatus);
            if ((!notStarted && !terminalSession)
                    || notStarted != normalizedSessionId.isEmpty()
                    || billingStarted == notStarted
                    || chargedSeconds != 0L) {
                throw new IllegalArgumentException(
                        "start cancellation response is inconsistent");
            }
            this.sessionId = normalizedSessionId;
            this.sessionStatus = sessionStatus;
            this.remainingSeconds = DualMachineSidecarValues.counter(
                    remainingSeconds, "remainingSeconds");
            this.chargedSeconds = chargedSeconds;
            this.billingStarted = billingStarted;
            this.authorizationKind =
                    DualMachineSidecarValues.authorizationKind(
                            authorizationKind, permanent);
            this.permanent = permanent;
        }
    }
}

final class DualMachineSidecarValues {
    private DualMachineSidecarValues() {
    }

    static DualMachineSidecarPort.UsageProof proof(
            DualMachineSidecarPort.UsageProof value) {
        if (value == null) {
            throw new IllegalArgumentException("usage proof is required");
        }
        return value;
    }

    static String hex128(String value, String name) {
        return lowerHex(value, 32, name);
    }

    static String sha256(String value, String name) {
        return lowerHex(value, 64, name);
    }

    static String lowerHex(String value, int length, String name) {
        if (value == null || value.length() != length) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        boolean containsNonzero = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'))) {
                throw new IllegalArgumentException(
                        name + " is not lowercase hex");
            }
            containsNonzero |= character != '0';
        }
        if (!containsNonzero) {
            throw new IllegalArgumentException(name + " must not be all zero");
        }
        return value;
    }

    static String deviceCode(String value) {
        if (value == null || value.isEmpty() || value.length() > 128) {
            throw new IllegalArgumentException(
                    "deviceCode has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= '0' && character <= '9')
                    || character == '.' || character == '_'
                    || character == ':' || character == '-')) {
                throw new IllegalArgumentException(
                        "deviceCode must be canonical uppercase ASCII");
            }
        }
        return value;
    }

    static String clientVersion(String value) {
        if (value == null || value.length() < 3 || value.length() > 80) {
            throw new IllegalArgumentException(
                    "clientVersion has invalid length");
        }
        String[] components = value.split("\\.", -1);
        if (components.length < 2 || components.length > 4) {
            throw new IllegalArgumentException(
                    "clientVersion must have two to four components");
        }
        for (String component : components) {
            if (component.isEmpty() || component.length() > 6
                    || (component.length() > 1
                    && component.charAt(0) == '0')) {
                throw new IllegalArgumentException(
                        "clientVersion is not canonical");
            }
            int number = 0;
            for (int index = 0; index < component.length(); index++) {
                char character = component.charAt(index);
                if (character < '0' || character > '9') {
                    throw new IllegalArgumentException(
                            "clientVersion is not numeric");
                }
                number = number * 10 + (character - '0');
            }
            if (number > 999_999) {
                throw new IllegalArgumentException(
                        "clientVersion component is too large");
            }
        }
        return value;
    }

    static String identityPublicKey(String value) {
        try {
            byte[] key = DualMachinePairingIdentityCodec
                    .decodePublicKeyBase64(value);
            return DualMachinePairingIdentityCodec
                    .encodePublicKeyBase64(key);
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "identityPublicKeyBase64 is invalid");
        }
    }

    static String cardCode(String value) {
        return DualMachineCardCode.normalizeAndValidate(value);
    }

    static String challengeToken(String value) {
        if (value == null || value.length() != 43) {
            throw new IllegalArgumentException(
                    "challengeToken has invalid length");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '_' || character == '-')) {
                throw new IllegalArgumentException(
                        "challengeToken is not Base64url");
            }
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            if (!Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(decoded).equals(value)) {
                throw new IllegalArgumentException(
                        "challengeToken is not canonical Base64url");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "challengeToken is not canonical Base64url");
        }
        return value;
    }

    static String signature(String value, String name) {
        if (value == null || value.length() < 8 || value.length() > 256) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length < 8
                    || decoded.length
                    > DualMachinePairingIdentityCodec.MAX_SIGNATURE_DER_BYTES
                    || !Base64.getEncoder().encodeToString(decoded)
                    .equals(value)) {
                throw new IllegalArgumentException(
                        name + " is not canonical Base64");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    name + " is not canonical Base64");
        }
        return value;
    }

    static long counter(long value, String name) {
        if (value < 0L) {
            throw new IllegalArgumentException(
                    name + " must not be negative");
        }
        return value;
    }

    static String authorizationKind(String value, boolean permanent) {
        boolean supported = "day".equals(value)
                || "week".equals(value)
                || "month".equals(value)
                || "permanent".equals(value);
        if (!supported || permanent != "permanent".equals(value)) {
            throw new IllegalArgumentException(
                    "authorizationKind is invalid");
        }
        return value;
    }

    static String usageLease(String value, String name) {
        if (value == null || value.length() < 256 || value.length() > 8192) {
            throw new IllegalArgumentException(name + " has invalid length");
        }
        int firstDot = value.indexOf('.');
        int secondDot = firstDot < 0 ? -1 : value.indexOf('.', firstDot + 1);
        if (firstDot <= 0 || secondDot <= firstDot + 1
                || secondDot >= value.length() - 1
                || value.indexOf('.', secondDot + 1) >= 0) {
            throw new IllegalArgumentException(name + " is not a JWT");
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!((character >= 'A' && character <= 'Z')
                    || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9')
                    || character == '_' || character == '-'
                    || character == '.')) {
                throw new IllegalArgumentException(
                        name + " is not canonical Base64url");
            }
        }
        requireBase64UrlSegment(value.substring(0, firstDot), name);
        requireBase64UrlSegment(
                value.substring(firstDot + 1, secondDot), name);
        requireBase64UrlSegment(value.substring(secondDot + 1), name);
        return value;
    }

    private static void requireBase64UrlSegment(String value, String name) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            if (!Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(decoded).equals(value)) {
                throw new IllegalArgumentException(
                        name + " has a non-canonical JWT segment");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    name + " has a non-canonical JWT segment");
        }
    }
}
