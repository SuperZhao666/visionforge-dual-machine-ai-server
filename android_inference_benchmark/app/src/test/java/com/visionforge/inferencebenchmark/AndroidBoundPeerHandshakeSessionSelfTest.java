package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1Exception;
import com.visionforge.inferencebenchmark.handshake.FreshP256KeyAgreement;
import com.visionforge.inferencebenchmark.handshake.HandshakeTranscriptV1;
import com.visionforge.inferencebenchmark.handshake.PeerHandshakeSecrets;
import com.visionforge.inferencebenchmark.handshake.PendingPeerHandshakeConfirmation;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Executable JVM contract for the Android entitlement-bound handshake owner. */
public final class AndroidBoundPeerHandshakeSessionSelfTest {
    private static final String PAIR_ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private static final String OTHER_PAIR_ID = "cccccccccccccccccccccccccccccccc";
    private static final String ENTITLEMENT_ID =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String ANDROID_ALIAS =
            "visionforge-bound-peer-fixture";
    private static final byte[] HOST_IPV4 = {
        (byte) 192, (byte) 168, 55, 1
    };
    private static final byte[] ANDROID_IPV4 = {
        (byte) 192, (byte) 168, 55, 2
    };
    private static final BigInteger P256_ORDER = new BigInteger(
            "ffffffff00000000ffffffffffffffff"
                    + "bce6faada7179e84f3b9cac2fc632551",
            16);

    private static final Class<?> TYPED_IDENTITY_CLASS =
            findTypedIdentityClass();
    private static final Method PRIVATE_BIND_METHOD = findPrivateBindMethod();

    private AndroidBoundPeerHandshakeSessionSelfTest() {}

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 0, "self-test accepts no arguments");
        verifiesCorrectBoundFlowAndConfirmedCopies();
        verifiesPairAndIdentityFailuresBurnFreshEphemeral();
        verifiesSignatureFailuresBurnFreshEphemeral();
        verifiesEphemeralAndTypedSignerFailuresBurnFreshEphemeral();
        verifiesFinishedGatesAndTerminalClose();
        verifiesRoleReflectionCannotReachBinding();
        verifiesProductionApiSurfaceAndRawSignerVisibility();
        System.out.println("AndroidBoundPeerHandshakeSessionSelfTest: PASS");
    }

    private static void verifiesCorrectBoundFlowAndConfirmedCopies()
            throws Exception {
        try (Scenario scenario = Scenario.create()) {
            AndroidBoundPeerHandshakeSession android = scenario.bind();
            requireFreshBurned(
                    scenario.androidEphemeral,
                    "successful bind must consume Android ephemeral");
            byte[] canonical = scenario.transcript.canonicalEncoding();
            byte[] firstSignature = android.androidTranscriptSignature();
            byte[] secondSignature = android.androidTranscriptSignature();
            try {
                require(
                        DualMachinePairingIdentityCodec.verify(
                                scenario.androidIdentity.getPublic().getEncoded(),
                                canonical,
                                firstSignature),
                        "Android signature must verify for exact checked transcript");
                firstSignature[0] ^= 1;
                require(
                        !Arrays.equals(firstSignature, secondSignature),
                        "Android signature accessor must return a defensive copy");
            } finally {
                clear(canonical);
                clear(firstSignature);
                clear(secondSignature);
            }

            try (PendingPeerHandshakeConfirmation hostPending =
                            scenario.hostEphemeral.deriveAfterPeerIdentityVerified(
                                    scenario.transcript,
                                    AuthenticatedPeerHandshakeV1.Role.HOST)) {
                byte[] androidFinished = null;
                byte[] hostFinished = null;
                try {
                    androidFinished = android.createAndroidFinished();
                    hostFinished = hostPending.createLocalFinishedMac();
                    ConfirmedAndroidPeerSession confirmed = null;
                    try (PeerHandshakeSecrets hostSecrets =
                                    hostPending.confirmPeerFinishedMac(androidFinished)) {
                        confirmed = android.confirmHostFinished(hostFinished);
                        requireConfirmedMetadata(scenario, confirmed);
                        requireMatchingSecrets(hostSecrets, confirmed);
                        requireDefensiveCopies(confirmed);
                        expectRejectedWithoutCause(
                                android::androidTranscriptSignature,
                                "bound wrapper must close after confirmation");
                        confirmed.close();
                        expectRejectedWithoutCause(
                                confirmed::channelBindingSha256,
                                "confirmed wrapper must fail closed after close");
                    } finally {
                        if (confirmed != null) confirmed.close();
                    }
                } finally {
                    clear(androidFinished);
                    clear(hostFinished);
                }
            }
        }
    }

    private static void verifiesPairAndIdentityFailuresBurnFreshEphemeral()
            throws Exception {
        try (Scenario scenario = Scenario.create()) {
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.record(true, ANDROID_ALIAS, scenario.androidFingerprint()),
                    scenario.transcript,
                    scenario.hostSignature,
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "revoked entitlement");
        }
        try (Scenario scenario = Scenario.create()) {
            HandshakeTranscriptV1 emptyPair = scenario.transcript(
                    "", scenario.hostHash(), scenario.androidHash(),
                    scenario.androidPublic());
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    emptyPair,
                    scenario.signHost(emptyPair),
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "empty pairing-only transcript");
        }
        try (Scenario scenario = Scenario.create()) {
            HandshakeTranscriptV1 wrongPair = scenario.transcript(
                    OTHER_PAIR_ID,
                    scenario.hostHash(),
                    scenario.androidHash(),
                    scenario.androidPublic());
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    wrongPair,
                    scenario.signHost(wrongPair),
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "pair mismatch");
        }
        try (Scenario scenario = Scenario.create()) {
            byte[] wrongHostHash = nonZeroHash(0x31);
            HandshakeTranscriptV1 wrongHost = scenario.transcript(
                    PAIR_ID,
                    wrongHostHash,
                    scenario.androidHash(),
                    scenario.androidPublic());
            try {
                expectBindRejectedAndFreshBurned(
                        scenario,
                        scenario.entitlement,
                        wrongHost,
                        scenario.signHost(wrongHost),
                        scenario.identity(scenario.androidIdentity.getPrivate()),
                        "Host transcript hash mismatch");
            } finally {
                clear(wrongHostHash);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            byte[] wrongAndroidHash = nonZeroHash(0x71);
            HandshakeTranscriptV1 wrongAndroid = scenario.transcript(
                    PAIR_ID,
                    scenario.hostHash(),
                    wrongAndroidHash,
                    scenario.androidPublic());
            try {
                expectBindRejectedAndFreshBurned(
                        scenario,
                        scenario.entitlement,
                        wrongAndroid,
                        scenario.signHost(wrongAndroid),
                        scenario.identity(scenario.androidIdentity.getPrivate()),
                        "Android transcript hash mismatch");
            } finally {
                clear(wrongAndroidHash);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.record(
                            false,
                            "different-bound-alias",
                            scenario.androidFingerprint()),
                    scenario.transcript,
                    scenario.hostSignature,
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "Android alias mismatch");
        }
        try (Scenario scenario = Scenario.create()) {
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.record(
                            false,
                            ANDROID_ALIAS,
                            lowercaseHex(nonZeroHash(0x51))),
                    scenario.transcript,
                    scenario.hostSignature,
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "Android entitlement fingerprint mismatch");
        }
        try (Scenario scenario = Scenario.create()) {
            KeyPair substitutedIdentity = generateIdentity();
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    scenario.transcript,
                    scenario.hostSignature,
                    newTypedIdentity(
                            ANDROID_ALIAS,
                            substitutedIdentity.getPublic().getEncoded(),
                            substitutedIdentity.getPrivate()),
                    "substituted Android identity SPKI");
        }
    }

    private static void verifiesSignatureFailuresBurnFreshEphemeral()
            throws Exception {
        try (Scenario scenario = Scenario.create()) {
            byte[] wrongSignature = scenario.hostSignature.clone();
            wrongSignature[wrongSignature.length - 1] ^= 1;
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    scenario.transcript,
                    wrongSignature,
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "wrong Host signature");
            clear(wrongSignature);
        }
        try (Scenario scenario = Scenario.create()) {
            HandshakeTranscriptV1 changedTranscript = scenario.transcriptBuilder(
                    PAIR_ID,
                    scenario.hostHash(),
                    scenario.androidHash(),
                    scenario.androidPublic())
                    .connectionId(0x1020304050607081L)
                    .build();
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    changedTranscript,
                    scenario.hostSignature,
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "Host signature from another transcript");
        }
        try (Scenario scenario = Scenario.create()) {
            byte[] highS = toHighSSignature(scenario.hostSignature);
            try {
                expectBindRejectedAndFreshBurned(
                        scenario,
                        scenario.entitlement,
                        scenario.transcript,
                        highS,
                        scenario.identity(scenario.androidIdentity.getPrivate()),
                        "high-S Host signature");
            } finally {
                clear(highS);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    scenario.transcript,
                    new byte[] {0x30},
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "malformed Host signature");
        }
        try (Scenario scenario = Scenario.create()) {
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    scenario.transcript,
                    new byte[
                            DualMachinePairingIdentityCodec
                                    .MAX_SIGNATURE_DER_BYTES + 1],
                    scenario.identity(scenario.androidIdentity.getPrivate()),
                    "oversized Host signature");
        }
    }

    private static void verifiesEphemeralAndTypedSignerFailuresBurnFreshEphemeral()
            throws Exception {
        try (Scenario scenario = Scenario.create();
                FreshP256KeyAgreement unrelated =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement()) {
            byte[] unrelatedPublic = unrelated.publicKeySec1();
            HandshakeTranscriptV1 wrongEphemeral = scenario.transcript(
                    PAIR_ID,
                    scenario.hostHash(),
                    scenario.androidHash(),
                    unrelatedPublic);
            byte[] signature = scenario.signHost(wrongEphemeral);
            try {
                expectBindRejectedAndFreshBurned(
                        scenario,
                        scenario.entitlement,
                        wrongEphemeral,
                        signature,
                        scenario.identity(scenario.androidIdentity.getPrivate()),
                        "Android ephemeral mismatch");
            } finally {
                clear(unrelatedPublic);
                clear(signature);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            KeyPair wrongSigner = generateIdentity();
            expectBindRejectedAndFreshBurned(
                    scenario,
                    scenario.entitlement,
                    scenario.transcript,
                    scenario.hostSignature,
                    scenario.identity(wrongSigner.getPrivate()),
                    "Android signature self-verification failure");
        }
        FreshP256KeyAgreement noStoreEphemeral =
                AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
        try (Scenario scenario = Scenario.create()) {
            expectRejectedWithoutCause(
                    () -> AndroidBoundPeerHandshakeSession.bindExpectedPair(
                            scenario.entitlement,
                            null,
                            noStoreEphemeral,
                            scenario.transcript,
                            scenario.hostSignature),
                    "public path must reject a missing concrete store");
            requireFreshBurned(
                    noStoreEphemeral,
                    "missing concrete store must burn fresh ephemeral");
        } finally {
            noStoreEphemeral.close();
        }
    }

    private static void verifiesFinishedGatesAndTerminalClose() throws Exception {
        try (Scenario scenario = Scenario.create()) {
            AndroidBoundPeerHandshakeSession bound = scenario.bind();
            expectRejectedWithoutCause(
                    () -> bound.confirmHostFinished(new byte[32]),
                    "Host Finished before Android Finished must fail closed");
            expectRejectedWithoutCause(
                    bound::createAndroidFinished,
                    "premature confirmation must close pending state");
        }
        try (Scenario scenario = Scenario.create()) {
            AndroidBoundPeerHandshakeSession bound = scenario.bind();
            byte[] first = bound.createAndroidFinished();
            try {
                expectRejectedWithoutCause(
                        bound::createAndroidFinished,
                        "Android Finished must be single-use");
                expectRejectedWithoutCause(
                        () -> bound.confirmHostFinished(new byte[32]),
                        "duplicate Android Finished must close pending state");
            } finally {
                clear(first);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            AndroidBoundPeerHandshakeSession bound = scenario.bind();
            byte[] androidFinished = bound.createAndroidFinished();
            try {
                byte[] wrongHostFinished = new byte[32];
                Arrays.fill(wrongHostFinished, (byte) 0x5a);
                expectRejectedWithoutCause(
                        () -> bound.confirmHostFinished(wrongHostFinished),
                        "wrong Host Finished must fail closed");
                expectRejectedWithoutCause(
                        bound::androidTranscriptSignature,
                        "wrong Host Finished must close bound state");
                clear(wrongHostFinished);
            } finally {
                clear(androidFinished);
            }
        }
        try (Scenario scenario = Scenario.create()) {
            AndroidBoundPeerHandshakeSession bound = scenario.bind();
            bound.close();
            bound.close();
            expectRejectedWithoutCause(
                    bound::androidTranscriptSignature,
                    "explicit close must be idempotent and terminal");
        }
    }

    private static void verifiesRoleReflectionCannotReachBinding()
            throws Exception {
        KeyPair identity = generateIdentity();
        byte[] identityHash = sha256(identity.getPublic().getEncoded());
        try (FreshP256KeyAgreement host =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement android =
                        AuthenticatedPeerHandshakeV1
                                .generateFreshEphemeralKeyAgreement()) {
            byte[] hostPublic = host.publicKeySec1();
            byte[] androidPublic = android.publicKeySec1();
            try {
                expectIllegalArgument(
                        () -> baseTranscriptBuilder(
                                PAIR_ID,
                                identityHash,
                                identityHash,
                                hostPublic,
                                androidPublic).build(),
                        "role-reflected identity hash must be rejected by typed transcript");
            } finally {
                clear(hostPublic);
                clear(androidPublic);
            }
        } finally {
            clear(identityHash);
        }
    }

    private static void verifiesProductionApiSurfaceAndRawSignerVisibility()
            throws Exception {
        Set<String> boundPublic = publicDeclaredMethodNames(
                AndroidBoundPeerHandshakeSession.class);
        require(
                boundPublic.equals(new HashSet<>(Arrays.asList(
                        "bindExpectedPair",
                        "androidTranscriptSignature",
                        "createAndroidFinished",
                        "confirmHostFinished",
                        "close"))),
                "bound wrapper public API must stay narrow: " + boundPublic);
        Set<String> confirmedPublic = publicDeclaredMethodNames(
                ConfirmedAndroidPeerSession.class);
        require(
                confirmedPublic.equals(new HashSet<>(Arrays.asList(
                        "pairId",
                        "connectionId",
                        "sessionGeneration",
                        "transportKind",
                        "hostIpv4",
                        "androidIpv4",
                        "videoPort",
                        "controlPort",
                        "transcriptHashSha256",
                        "channelBindingSha256",
                        "channelBindingLowercaseHex",
                        "controlHostToAndroidMaterial",
                        "controlAndroidToHostMaterial",
                        "presenceHostToAndroidMaterial",
                        "videoHostToAndroidMaterial",
                        "idrAndroidToHostMaterial",
                        "mouseHostToAndroidMaterial",
                        "close"))),
                "confirmed wrapper API must expose only bound metadata and copies");
        for (Method method : ConfirmedAndroidPeerSession.class.getDeclaredMethods()) {
            require(
                    method.getReturnType() != PeerHandshakeSecrets.class,
                    "confirmed wrapper must never return its underlying key owner");
        }

        Method rawSigner = AndroidPairingIdentityStore.class.getDeclaredMethod(
                "sign", byte[].class);
        Method typedSigner = AndroidPairingIdentityStore.class.getDeclaredMethod(
                "signHandshakeTranscript",
                HandshakeTranscriptV1.class,
                DualMachineEntitlementRecord.class);
        require(
                !Modifier.isPublic(rawSigner.getModifiers()),
                "raw identity signer must not be public");
        require(
                !Modifier.isPublic(typedSigner.getModifiers()),
                "typed identity signer is internal to the bound wrapper");
        require(
                Modifier.isPrivate(TYPED_IDENTITY_CLASS.getModifiers()),
                "typed identity port must remain private");
        require(
                Modifier.isPrivate(PRIVATE_BIND_METHOD.getModifiers()),
                "generic typed bind path must remain private");
    }

    private static void requireConfirmedMetadata(
            Scenario scenario, ConfirmedAndroidPeerSession confirmed)
            throws Exception {
        require(PAIR_ID.equals(confirmed.pairId()), "confirmed pair mismatch");
        require(
                confirmed.connectionId() == scenario.transcript.connectionId(),
                "confirmed connection mismatch");
        require(
                confirmed.sessionGeneration()
                        == scenario.transcript.sessionGeneration(),
                "confirmed generation mismatch");
        require(
                confirmed.transportKind()
                        == AuthenticatedPeerHandshakeV1.TransportKind.CAT6,
                "confirmed transport mismatch");
        require(Arrays.equals(HOST_IPV4, confirmed.hostIpv4()),
                "confirmed Host route mismatch");
        require(Arrays.equals(ANDROID_IPV4, confirmed.androidIpv4()),
                "confirmed Android route mismatch");
        require(confirmed.videoPort() == 45678, "confirmed video port mismatch");
        require(confirmed.controlPort() == 45679, "confirmed control port mismatch");
        byte[] expectedHash = scenario.transcript.transcriptHashSha256();
        byte[] actualHash = confirmed.transcriptHashSha256();
        try {
            require(MessageDigest.isEqual(expectedHash, actualHash),
                    "confirmed transcript hash mismatch");
        } finally {
            clear(expectedHash);
            clear(actualHash);
        }
    }

    private static void requireMatchingSecrets(
            PeerHandshakeSecrets host, ConfirmedAndroidPeerSession android)
            throws Exception {
        requireEqualAndClear(
                host.controlHostToAndroidMaterial(),
                android.controlHostToAndroidMaterial(), "Host control material");
        requireEqualAndClear(
                host.controlAndroidToHostMaterial(),
                android.controlAndroidToHostMaterial(), "Android control material");
        requireEqualAndClear(
                host.presenceHostToAndroidMaterial(),
                android.presenceHostToAndroidMaterial(), "presence material");
        requireEqualAndClear(
                host.videoHostToAndroidMaterial(),
                android.videoHostToAndroidMaterial(), "video material");
        requireEqualAndClear(
                host.idrAndroidToHostMaterial(),
                android.idrAndroidToHostMaterial(), "IDR material");
        requireEqualAndClear(
                host.mouseHostToAndroidMaterial(),
                android.mouseHostToAndroidMaterial(), "mouse material");
        requireEqualAndClear(
                host.channelBindingSha256(),
                android.channelBindingSha256(), "channel binding");
    }

    private static void requireDefensiveCopies(ConfirmedAndroidPeerSession confirmed)
            throws Exception {
        byte[] first = confirmed.controlHostToAndroidMaterial();
        byte[] second = confirmed.controlHostToAndroidMaterial();
        byte[] firstRoute = confirmed.hostIpv4();
        byte[] secondRoute = confirmed.hostIpv4();
        byte[] firstHash = confirmed.transcriptHashSha256();
        byte[] secondHash = confirmed.transcriptHashSha256();
        try {
            first[0] ^= 1;
            firstRoute[0] ^= 1;
            firstHash[0] ^= 1;
            require(!Arrays.equals(first, second),
                    "secret material must be defensive");
            require(!Arrays.equals(firstRoute, secondRoute),
                    "route metadata must be defensive");
            require(!Arrays.equals(firstHash, secondHash),
                    "transcript hash must be defensive");
        } finally {
            clear(first);
            clear(second);
            clear(firstRoute);
            clear(secondRoute);
            clear(firstHash);
            clear(secondHash);
        }
    }

    private static void expectBindRejectedAndFreshBurned(
            Scenario scenario,
            DualMachineEntitlementRecord record,
            HandshakeTranscriptV1 transcript,
            byte[] signature,
            Object identity,
            String label) throws Exception {
        expectRejectedWithoutCause(
                () -> invokePrivateBind(
                        record,
                        identity,
                        scenario.androidEphemeral,
                        transcript,
                        signature),
                label + " must fail closed");
        requireFreshBurned(
                scenario.androidEphemeral,
                label + " must burn Android ephemeral");
    }

    private static AndroidBoundPeerHandshakeSession invokePrivateBind(
            DualMachineEntitlementRecord record,
            Object identity,
            FreshP256KeyAgreement fresh,
            HandshakeTranscriptV1 transcript,
            byte[] signature) throws Exception {
        try {
            return (AndroidBoundPeerHandshakeSession) PRIVATE_BIND_METHOD.invoke(
                    null, record, identity, fresh, transcript, signature);
        } catch (InvocationTargetException invocationFailure) {
            Throwable cause = invocationFailure.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new AssertionError("unexpected bind failure", cause);
        }
    }

    private static Object newTypedIdentity(
            String alias, byte[] spki, PrivateKey signingKey) {
        byte[] ownedSpki = spki.clone();
        return Proxy.newProxyInstance(
                AndroidBoundPeerHandshakeSessionSelfTest.class.getClassLoader(),
                new Class<?>[] {TYPED_IDENTITY_CLASS},
                (proxy, method, arguments) -> {
                    switch (method.getName()) {
                        case "alias":
                            return alias;
                        case "publicKeySpkiDer":
                            return ownedSpki.clone();
                        case "signTranscript":
                            HandshakeTranscriptV1 transcript =
                                    (HandshakeTranscriptV1) arguments[0];
                            byte[] canonical = transcript.canonicalEncoding();
                            try {
                                return DualMachinePairingIdentityCodec.sign(
                                        signingKey, canonical);
                            } finally {
                                clear(canonical);
                            }
                        case "toString":
                            return "typed-identity-fixture";
                        case "hashCode":
                            return System.identityHashCode(proxy);
                        case "equals":
                            return proxy == arguments[0];
                        default:
                            throw new AssertionError(
                                    "unexpected typed identity method: " + method);
                    }
                });
    }

    private static Class<?> findTypedIdentityClass() {
        for (Class<?> candidate :
                AndroidBoundPeerHandshakeSession.class.getDeclaredClasses()) {
            if (candidate.getSimpleName().equals("TranscriptIdentity")) {
                return candidate;
            }
        }
        throw new AssertionError("private typed identity boundary is missing");
    }

    private static Method findPrivateBindMethod() {
        try {
            Method method = AndroidBoundPeerHandshakeSession.class.getDeclaredMethod(
                    "bindWithTypedIdentity",
                    DualMachineEntitlementRecord.class,
                    TYPED_IDENTITY_CLASS,
                    FreshP256KeyAgreement.class,
                    HandshakeTranscriptV1.class,
                    byte[].class);
            method.setAccessible(true);
            return method;
        } catch (ReflectiveOperationException failure) {
            throw new AssertionError("private typed bind path is missing", failure);
        }
    }

    private static Set<String> publicDeclaredMethodNames(Class<?> type) {
        Set<String> names = new HashSet<>();
        for (Method method : type.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && !method.isSynthetic()) {
                names.add(method.getName());
            }
        }
        return names;
    }

    private static HandshakeTranscriptV1.Builder baseTranscriptBuilder(
            String pairId,
            byte[] hostIdentityHash,
            byte[] androidIdentityHash,
            byte[] hostEphemeral,
            byte[] androidEphemeral) {
        return AuthenticatedPeerHandshakeV1.newTranscriptBuilder()
                .hostIdentitySpkiSha256(hostIdentityHash)
                .androidIdentitySpkiSha256(androidIdentityHash)
                .hostEphemeralPublicKey(hostEphemeral)
                .androidEphemeralPublicKey(androidEphemeral)
                .hostNonce(nonZeroHash(0x41))
                .androidNonce(nonZeroHash(0x61))
                .connectionId(0x1020304050607080L)
                .sessionGeneration(0x0102030405060708L)
                .transportKind(AuthenticatedPeerHandshakeV1.TransportKind.CAT6)
                .hostIpv4(HOST_IPV4)
                .androidIpv4(ANDROID_IPV4)
                .videoPort(45678)
                .controlPort(45679)
                .pairId(pairId)
                .hostRuntimeVersion("17.8.47")
                .androidRuntimeVersion("17.8.47");
    }

    private static KeyPair generateIdentity() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(
                DualMachinePairingIdentityCodec.CURVE_NAME));
        return generator.generateKeyPair();
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static byte[] nonZeroHash(int start) {
        byte[] value = new byte[32];
        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (start + index);
        }
        return value;
    }

    private static String lowercaseHex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte current : value) {
            result.append(Character.forDigit((current >>> 4) & 0x0f, 16));
            result.append(Character.forDigit(current & 0x0f, 16));
        }
        return result.toString();
    }

    private static byte[] toHighSSignature(byte[] lowS) {
        int offset = 0;
        require((lowS[offset++] & 0xff) == 0x30,
                "fixture signature must be DER sequence");
        int sequenceLength = lowS[offset++] & 0xff;
        require(sequenceLength == lowS.length - 2,
                "fixture signature must use short DER length");
        require((lowS[offset++] & 0xff) == 0x02,
                "fixture signature must contain r");
        int rLength = lowS[offset++] & 0xff;
        byte[] r = Arrays.copyOfRange(lowS, offset, offset + rLength);
        offset += rLength;
        require((lowS[offset++] & 0xff) == 0x02,
                "fixture signature must contain s");
        int sLength = lowS[offset++] & 0xff;
        byte[] s = Arrays.copyOfRange(lowS, offset, offset + sLength);
        BigInteger highSValue = P256_ORDER.subtract(new BigInteger(1, s));
        byte[] highS = highSValue.toByteArray();
        int payloadLength = 2 + r.length + 2 + highS.length;
        byte[] encoded = new byte[payloadLength + 2];
        int output = 0;
        encoded[output++] = 0x30;
        encoded[output++] = (byte) payloadLength;
        encoded[output++] = 0x02;
        encoded[output++] = (byte) r.length;
        System.arraycopy(r, 0, encoded, output, r.length);
        output += r.length;
        encoded[output++] = 0x02;
        encoded[output++] = (byte) highS.length;
        System.arraycopy(highS, 0, encoded, output, highS.length);
        clear(r);
        clear(s);
        clear(highS);
        return encoded;
    }

    private static void requireFreshBurned(
            FreshP256KeyAgreement fresh, String message) throws Exception {
        try {
            fresh.publicKeySec1();
            throw new AssertionError(message);
        } catch (AuthenticatedPeerHandshakeV1Exception expected) {
            require(
                    expected.reason()
                            == AuthenticatedPeerHandshakeV1Exception.Reason.CLOSED,
                    message + " (unexpected reason)");
            require(expected.getCause() == null,
                    message + " (provider cause leaked)");
        }
    }

    private static void requireEqualAndClear(
            byte[] left, byte[] right, String label) {
        try {
            require(MessageDigest.isEqual(left, right), label + " mismatch");
        } finally {
            clear(left);
            clear(right);
        }
    }

    private static void expectRejectedWithoutCause(
            ThrowingOperation operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (GeneralSecurityException expected) {
            require(expected.getCause() == null,
                    message + " (provider cause leaked)");
        }
    }

    private static void expectIllegalArgument(
            ThrowingOperation operation, String message) throws Exception {
        try {
            operation.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException expected) {
            require(expected.getCause() == null,
                    message + " (unexpected cause)");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }

    @FunctionalInterface
    private interface ThrowingOperation {
        void run() throws Exception;
    }

    private static final class Scenario implements AutoCloseable {
        private final KeyPair hostIdentity;
        private final KeyPair androidIdentity;
        private final FreshP256KeyAgreement hostEphemeral;
        private final FreshP256KeyAgreement androidEphemeral;
        private final DualMachineEntitlementRecord entitlement;
        private final HandshakeTranscriptV1 transcript;
        private final byte[] hostSignature;

        private Scenario(
                KeyPair hostIdentity,
                KeyPair androidIdentity,
                FreshP256KeyAgreement hostEphemeral,
                FreshP256KeyAgreement androidEphemeral,
                DualMachineEntitlementRecord entitlement,
                HandshakeTranscriptV1 transcript,
                byte[] hostSignature) {
            this.hostIdentity = hostIdentity;
            this.androidIdentity = androidIdentity;
            this.hostEphemeral = hostEphemeral;
            this.androidEphemeral = androidEphemeral;
            this.entitlement = entitlement;
            this.transcript = transcript;
            this.hostSignature = hostSignature;
        }

        private static Scenario create() throws Exception {
            KeyPair hostIdentity = generateIdentity();
            KeyPair androidIdentity = generateIdentity();
            FreshP256KeyAgreement hostEphemeral =
                    AuthenticatedPeerHandshakeV1
                            .generateFreshEphemeralKeyAgreement();
            FreshP256KeyAgreement androidEphemeral =
                    AuthenticatedPeerHandshakeV1
                            .generateFreshEphemeralKeyAgreement();
            byte[] hostHash = sha256(hostIdentity.getPublic().getEncoded());
            byte[] androidHash = sha256(androidIdentity.getPublic().getEncoded());
            byte[] hostPublic = hostEphemeral.publicKeySec1();
            byte[] androidPublic = androidEphemeral.publicKeySec1();
            try {
                HandshakeTranscriptV1 transcript = baseTranscriptBuilder(
                        PAIR_ID,
                        hostHash,
                        androidHash,
                        hostPublic,
                        androidPublic).build();
                DualMachineEntitlementRecord entitlement =
                        new DualMachineEntitlementRecord(
                                ENTITLEMENT_ID,
                                PAIR_ID,
                                "89aabbccddeeff001122334455667788",
                                3L,
                                "active",
                                DualMachineEntitlementRecord.PROTOCOL_VERSION,
                                7L,
                                DualMachinePairingIdentityCodec.fingerprintHex(
                                        hostIdentity.getPublic().getEncoded()),
                                DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                                        hostIdentity.getPublic().getEncoded()),
                                DualMachinePairingIdentityCodec.fingerprintHex(
                                        androidIdentity.getPublic().getEncoded()),
                                ANDROID_ALIAS);
                byte[] canonical = transcript.canonicalEncoding();
                byte[] signature;
                try {
                    signature = DualMachinePairingIdentityCodec.sign(
                            hostIdentity.getPrivate(), canonical);
                } finally {
                    clear(canonical);
                }
                return new Scenario(
                        hostIdentity,
                        androidIdentity,
                        hostEphemeral,
                        androidEphemeral,
                        entitlement,
                        transcript,
                        signature);
            } catch (Exception failure) {
                hostEphemeral.close();
                androidEphemeral.close();
                throw failure;
            } finally {
                clear(hostHash);
                clear(androidHash);
                clear(hostPublic);
                clear(androidPublic);
            }
        }

        private AndroidBoundPeerHandshakeSession bind() throws Exception {
            return invokePrivateBind(
                    entitlement,
                    identity(androidIdentity.getPrivate()),
                    androidEphemeral,
                    transcript,
                    hostSignature);
        }

        private Object identity(PrivateKey signer) throws Exception {
            return newTypedIdentity(
                    ANDROID_ALIAS, androidIdentity.getPublic().getEncoded(), signer);
        }

        private DualMachineEntitlementRecord record(
                boolean revoked, String alias, String androidFingerprint)
                throws Exception {
            return new DualMachineEntitlementRecord(
                    ENTITLEMENT_ID,
                    PAIR_ID,
                    "89aabbccddeeff001122334455667788",
                    3L,
                    "active",
                    DualMachineEntitlementRecord.PROTOCOL_VERSION,
                    7L,
                    DualMachinePairingIdentityCodec.fingerprintHex(
                            hostIdentity.getPublic().getEncoded()),
                    DualMachinePairingIdentityCodec.encodePublicKeyBase64(
                            hostIdentity.getPublic().getEncoded()),
                    androidFingerprint,
                    alias,
                    "day",
                    "day",
                    false,
                    revoked);
        }

        private HandshakeTranscriptV1 transcript(
                String pair,
                byte[] hostHash,
                byte[] androidHash,
                byte[] androidPublic) throws Exception {
            return transcriptBuilder(pair, hostHash, androidHash, androidPublic).build();
        }

        private HandshakeTranscriptV1.Builder transcriptBuilder(
                String pair,
                byte[] hostHash,
                byte[] androidHash,
                byte[] androidPublic) throws Exception {
            byte[] hostPublic = hostEphemeral.publicKeySec1();
            try {
                return baseTranscriptBuilder(
                        pair, hostHash, androidHash, hostPublic, androidPublic);
            } finally {
                clear(hostPublic);
            }
        }

        private byte[] signHost(HandshakeTranscriptV1 value) throws Exception {
            byte[] canonical = value.canonicalEncoding();
            try {
                return DualMachinePairingIdentityCodec.sign(
                        hostIdentity.getPrivate(), canonical);
            } finally {
                clear(canonical);
            }
        }

        private byte[] hostHash() throws Exception {
            return sha256(hostIdentity.getPublic().getEncoded());
        }

        private byte[] androidHash() throws Exception {
            return sha256(androidIdentity.getPublic().getEncoded());
        }

        private byte[] androidPublic() throws Exception {
            return androidEphemeral.publicKeySec1();
        }

        private String androidFingerprint() throws Exception {
            return DualMachinePairingIdentityCodec.fingerprintHex(
                    androidIdentity.getPublic().getEncoded());
        }

        @Override
        public void close() {
            clear(hostSignature);
            hostEphemeral.close();
            androidEphemeral.close();
        }
    }
}
