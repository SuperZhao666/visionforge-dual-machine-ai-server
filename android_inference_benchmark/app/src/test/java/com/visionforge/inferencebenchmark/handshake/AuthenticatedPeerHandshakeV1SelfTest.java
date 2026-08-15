package com.visionforge.inferencebenchmark.handshake;

import static com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1.Role.ANDROID;
import static com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1.Role.HOST;
import static com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1Exception.Reason.CLOSED;
import static com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1Exception.Reason.CRYPTO_UNAVAILABLE;
import static com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1Exception.Reason.UNAUTHENTICATED_HANDSHAKE;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.KeyAgreement;

/** Dependency-free executable contract for the Android/JCA peer-handshake v1 foundation. */
public final class AuthenticatedPeerHandshakeV1SelfTest {
    private static final String HOST_PUBLIC_HEX =
            "046b17d1f2e12c4247f8bce6e563a440"
                    + "f277037d812deb33a0f4a13945d898c296"
                    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e"
                    + "162bce33576b315ececbb6406837bf51f5";
    private static final String ANDROID_PUBLIC_HEX =
            "047cf27b188d034f7e8a52380304b51a"
                    + "c3c08969e277f21b35a60b48fc47669978"
                    + "07775510db8ed040293d9ac69f7430d"
                    + "bba7dade63ce982299e04b79d227873d1";
    private static final String TRANSCRIPT_HASH_HEX =
            "e90e31ad0d9399f36274e42248064fa3"
                    + "ef9f3f0d73e9e73f0ea0ce8aabd24117";
    private static final String ECDH_SHARED_HEX =
            "7cf27b188d034f7e8a52380304b51ac3"
                    + "c08969e277f21b35a60b48fc47669978";
    private static final String PRK_HEX =
            "aa864bd95772a3a4a544ccd5fa23b588"
                    + "1dab0462e1439d23d04b5a19dac4e7e0";
    private static final String CONTROL_HOST_TO_ANDROID_HEX =
            "0f4714afae44c3000fe5fcdca61f2a42"
                    + "094e5d7b75ae35e7b0b8ddefd5e7a2ffcd8ec73d";
    private static final String CONTROL_ANDROID_TO_HOST_HEX =
            "7e5d8ae1483a45162434aa0b7d125e71"
                    + "e5785c1a961b4796e5495d1329ee23d277bb26ac";
    private static final String PRESENCE_HEX =
            "172a609bf56696232b79bed3a13373ce"
                    + "79a7aa33a24878c427923a421b5425ec69865a7e";
    private static final String VIDEO_HEX =
            "5abce1e7877c4894688bf65e5ad0df08"
                    + "b6a1ab597155df19ae049222de2fe2a8a9a2618c";
    private static final String IDR_HEX =
            "857be929d83a3e3fd56f8c21dec1db5b"
                    + "07e9d46b1550376b36042f4622519dee0b9cb385";
    private static final String MOUSE_HEX =
            "521dd222ba6d023752df2704eefb5d82"
                    + "b4218705922f70d81238d68c984cb6ec17b59d00";
    private static final String FINISHED_HOST_KEY_HEX =
            "51391a6d16c2a0d15e2a6d0d4164709"
                    + "1627d9d1035f6df979c18131ad552dddb";
    private static final String FINISHED_ANDROID_KEY_HEX =
            "943c2f631e1f2e862d059ba0b19e2283"
                    + "14a149ab6076ea36aac179afe5ce6eaa";
    private static final String EXPORTER_HEX =
            "226bd61eff3f8a9c097beefca9bcd9c4"
                    + "3c4b28019f16c8e99c03f70d0a0e33d2";
    private static final String FINISHED_HOST_HEX =
            "c55b5a1bb27b4d841cd71e246c57dd16"
                    + "6c90fbd10703be001e1ae8367e360f2e";
    private static final String FINISHED_ANDROID_HEX =
            "4eaa3269be3d699c74458b4ecf2336ac"
                    + "67b6275f504f03d24a5180c31622ded6";
    private static final String CHANNEL_BINDING_HEX =
            "5238342449e1585fe95db78cf437a47d"
                    + "386d0e2cf895a751053afa0cc431a98b";
    private static final String LEADING_ZERO_SHARED_HEX =
            "005543894af3d00ed7d740abdbd75c96"
                    + "b06877b787db5f70eea78b90a8d7c00a";

    private AuthenticatedPeerHandshakeV1SelfTest() {}

    public static void main(String[] arguments) throws Exception {
        require(arguments.length == 0, "self-test accepts no arguments");
        verifiesFrozenCrossLanguageVector();
        verifiesStrictCanonicalTranscriptParsing();
        verifiesTranscriptFieldContractsAndUnsignedBounds();
        verifiesRealP256PointValidation();
        verifiesHkdfLimitAndLabelIsolation();
        verifiesLeadingZeroEcdhNormalization();
        verifiesFreshCrossSessionAgreementAndLifecycle();
        verifiesFinishedFailureClosesSecrets();
        verifiesFreshFactoryUniquenessAndConcurrentOwnership();
        verifiesConcurrentPendingConfirmationAndClose();
        verifiesTerminalZeroizationAndClosedAccessors();
        verifiesProviderFailureClosesFresh();
        verifiesProductionApiHasNoChosenSecretEntryPoint();
        System.out.println("AuthenticatedPeerHandshakeV1SelfTest: PASS");
    }

    private static void verifiesFrozenCrossLanguageVector() throws Exception {
        byte[] hostScalar = scalar(1);
        byte[] androidScalar = scalar(2);
        byte[] expectedHostPublic = hex(HOST_PUBLIC_HEX);
        byte[] expectedAndroidPublic = hex(ANDROID_PUBLIC_HEX);
        try (FreshP256KeyAgreement hostAgreement = fixedAgreement(hostScalar);
                FreshP256KeyAgreement androidAgreement = fixedAgreement(androidScalar)) {
            byte[] hostPublic = hostAgreement.publicKeySec1();
            byte[] androidPublic = androidAgreement.publicKeySec1();
            requireBytes(hostPublic, expectedHostPublic, "scalar=1 SEC1");
            requireBytes(androidPublic, expectedAndroidPublic, "scalar=2 SEC1");
            HandshakeTranscriptV1 transcript = vectorTranscript(hostPublic, androidPublic);
            byte[] encoded = transcript.canonicalEncoding();
            require(encoded.length == 439, "frozen canonical transcript length");
            requireHex(transcript.transcriptHashSha256(), TRANSCRIPT_HASH_HEX, "transcript hash");
            HandshakeTranscriptV1 reparsed =
                    AuthenticatedPeerHandshakeV1.parseTranscript(encoded);
            requireBytes(reparsed.canonicalEncoding(), encoded, "canonical parse/encode identity");

            byte[] rawShared = rawEcdhForTest(hostScalar, androidPublic);
            byte[] transcriptHash = transcript.transcriptHashSha256();
            byte[] prk =
                    AuthenticatedPeerHandshakeV1Internals.hkdfExtractSha256(
                            transcriptHash, rawShared);
            requireHex(rawShared.clone(), ECDH_SHARED_HEX, "JCA P-256 ECDH shared secret");
            requireHex(prk.clone(), PRK_HEX, "HKDF extract PRK");
            requireDerivedKeyVector(prk);

            try (PendingPeerHandshakeConfirmation hostPending =
                            hostAgreement.deriveAfterPeerIdentityVerified(transcript, HOST);
                    PendingPeerHandshakeConfirmation androidPending =
                            androidAgreement.deriveAfterPeerIdentityVerified(transcript, ANDROID)) {
                requirePendingHasNoTrafficExports(hostPending);
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                byte[] androidFinished = androidPending.createLocalFinishedMac();
                requireHex(hostFinished.clone(), FINISHED_HOST_HEX, "host Finished");
                requireHex(androidFinished.clone(), FINISHED_ANDROID_HEX, "Android Finished");
                try (PeerHandshakeSecrets hostSecrets =
                                hostPending.confirmPeerFinishedMac(androidFinished);
                        PeerHandshakeSecrets androidSecrets =
                                androidPending.confirmPeerFinishedMac(hostFinished)) {
                    requireVectorOutputs(hostSecrets);
                    requireVectorOutputs(androidSecrets);
                    requireSameSessionOutputs(hostSecrets, androidSecrets);
                }
                clearAll(hostFinished, androidFinished);
            }
            clearAll(hostPublic, androidPublic, encoded, rawShared, transcriptHash, prk);
        }
        clearAll(hostScalar, androidScalar, expectedHostPublic, expectedAndroidPublic);
    }

    private static void verifiesStrictCanonicalTranscriptParsing() throws Exception {
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        HandshakeTranscriptV1 transcript = vectorTranscript(hostPublic, androidPublic);
        byte[] canonical = transcript.canonicalEncoding();
        byte[] baselineHash = transcript.transcriptHashSha256();
        List<FieldSpan> fields = fieldSpans(canonical);
        require(fields.size() == HandshakeTranscriptV1.FIELD_COUNT, "18 transcript fields");

        for (FieldSpan field : fields) {
            require(field.length > 0, "vector field is non-empty: " + field.tag);
            byte[] mutated = canonical.clone();
            mutated[field.valueOffset + field.length - 1] ^= 0x01;
            try {
                HandshakeTranscriptV1 parsed =
                        AuthenticatedPeerHandshakeV1.parseTranscript(mutated);
                byte[] mutatedHash = parsed.transcriptHashSha256();
                require(
                        !MessageDigest.isEqual(baselineHash, mutatedHash),
                        "accepted field mutation must change transcript hash: " + field.tag);
                clearAll(mutatedHash);
            } catch (AuthenticatedPeerHandshakeV1Exception rejected) {
                require(rejected.reason() == UNAUTHENTICATED_HANDSHAKE,
                        "field mutation generic rejection: " + field.tag);
            }
            clearAll(mutated);
        }

        FieldSpan second = fields.get(1);
        byte[] duplicate = canonical.clone();
        duplicate[second.tagOffset] = 0;
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(duplicate));

        byte[] outOfOrder = canonical.clone();
        outOfOrder[second.tagOffset] = 2;
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(outOfOrder));

        FieldSpan last = fields.get(fields.size() - 1);
        byte[] unknown = canonical.clone();
        unknown[last.tagOffset] = (byte) 18;
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(unknown));

        FieldSpan removedField = fields.get(7);
        byte[] missing = removeRange(
                canonical,
                removedField.tagOffset,
                HandshakeTranscriptV1.TLV_HEADER_BYTES + removedField.length);
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(missing));

        byte[] trailing = Arrays.copyOf(canonical, canonical.length + 1);
        trailing[trailing.length - 1] = 18;
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(trailing));

        for (int unsignedLength : new int[] {0x7fff_ffff, 0x8000_0000, 0xffff_ffff}) {
            byte[] maliciousLength = canonical.clone();
            ByteBuffer.wrap(
                            maliciousLength,
                            second.lengthOffset,
                            Integer.BYTES)
                    .putInt(unsignedLength);
            expectUnauthenticated(
                    () -> AuthenticatedPeerHandshakeV1.parseTranscript(maliciousLength));
            clearAll(maliciousLength);
        }

        byte[] zeroFixedLength = canonical.clone();
        ByteBuffer.wrap(zeroFixedLength, second.lengthOffset, Integer.BYTES).putInt(0);
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(zeroFixedLength));
        FieldSpan hostIdentity = fields.get(2);
        byte[] zeroIdentity = canonical.clone();
        Arrays.fill(
                zeroIdentity,
                hostIdentity.valueOffset,
                hostIdentity.valueOffset + hostIdentity.length,
                (byte) 0);
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(zeroIdentity));
        byte[] truncated = Arrays.copyOf(canonical, canonical.length - 1);
        expectUnauthenticated(() -> AuthenticatedPeerHandshakeV1.parseTranscript(truncated));

        clearAll(
                hostPublic,
                androidPublic,
                canonical,
                baselineHash,
                duplicate,
                outOfOrder,
                unknown,
                missing,
                trailing,
                zeroFixedLength,
                zeroIdentity,
                truncated);
    }

    private static void verifiesTranscriptFieldContractsAndUnsignedBounds() throws Exception {
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        byte[] hostIdentity = sequence(0x00, 32);
        byte[] androidIdentity = sequence(0x20, 32);
        byte[] hostNonce = sequence(0x40, 32);
        byte[] androidNonce = sequence(0x60, 32);

        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .androidIdentitySpkiSha256(hostIdentity)
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostIdentitySpkiSha256(new byte[32])
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .androidIdentitySpkiSha256(new byte[32])
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .androidEphemeralPublicKey(hostPublic)
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).androidNonce(hostNonce).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).hostNonce(new byte[32]).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).connectionId(0L).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).sessionGeneration(0L).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).transportKind(null).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).hostIpv4(new byte[3]).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).videoPort(0).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).controlPort(65536).build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .controlPort(45678)
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic).pairId("bad pair").build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .pairId(repeat('a', 65))
                        .build());

        for (String invalidVersion :
                new String[] {
                    "v17.8.47",
                    "17.08.47",
                    "17.8.47-beta",
                    "17.8.47+build",
                    "17.8",
                    "17.8.47.1",
                    "17.8.47 ",
                    ""
                }) {
            expectIllegalArgument(
                    () -> vectorBuilder(hostPublic, androidPublic)
                            .hostRuntimeVersion(invalidVersion)
                            .build());
        }

        byte[] sparseNonce = new byte[32];
        sparseNonce[31] = 1;
        HandshakeTranscriptV1 unsigned =
                vectorBuilder(hostPublic, androidPublic)
                        .hostNonce(sparseNonce)
                        .connectionId(Long.MIN_VALUE)
                        .sessionGeneration(-1L)
                        .videoPort(65535)
                        .controlPort(65534)
                        .pairId("")
                        .build();
        HandshakeTranscriptV1 parsed =
                AuthenticatedPeerHandshakeV1.parseTranscript(unsigned.canonicalEncoding());
        require(parsed.connectionId() == Long.MIN_VALUE, "unsigned-u64 high-bit connection");
        require(parsed.sessionGeneration() == -1L, "unsigned-u64 maximum generation");
        require(parsed.videoPort() == 65535, "unsigned-u16 maximum port");
        require(parsed.pairId().isEmpty(), "pre-activation empty pair id");
        requireBytes(parsed.hostNonce(), sparseNonce, "nonce rejects only the all-zero value");
        byte[] hostScalar = scalar(1);
        try (FreshP256KeyAgreement emptyPairAgreement = fixedAgreement(hostScalar)) {
            expectUnauthenticated(
                    () -> emptyPairAgreement.deriveAfterPeerIdentityVerified(parsed, HOST));
            expectClosed(
                    () -> emptyPairAgreement.deriveAfterPeerIdentityVerified(parsed, HOST));
        }

        clearAll(
                hostPublic,
                androidPublic,
                hostIdentity,
                androidIdentity,
                hostNonce,
                androidNonce,
                sparseNonce,
                hostScalar);
    }

    private static void verifiesRealP256PointValidation() throws Exception {
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        byte[] zeroPoint = new byte[65];
        zeroPoint[0] = 0x04;
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostEphemeralPublicKey(zeroPoint)
                        .build());

        byte[] wrongPrefix = hostPublic.clone();
        wrongPrefix[0] = 0x02;
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostEphemeralPublicKey(wrongPrefix)
                        .build());
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostEphemeralPublicKey(Arrays.copyOf(hostPublic, 64))
                        .build());

        byte[] offCurve = hostPublic.clone();
        offCurve[64] ^= 0x01;
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostEphemeralPublicKey(offCurve)
                        .build());

        byte[] primeCoordinate = hostPublic.clone();
        byte[] prime =
                hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        System.arraycopy(prime, 0, primeCoordinate, 1, prime.length);
        expectIllegalArgument(
                () -> vectorBuilder(hostPublic, androidPublic)
                        .hostEphemeralPublicKey(primeCoordinate)
                        .build());

        byte[] canonical = vectorTranscript(hostPublic, androidPublic).canonicalEncoding();
        FieldSpan hostPoint = fieldSpans(canonical).get(4);
        byte[] untrustedOffCurve = canonical.clone();
        untrustedOffCurve[hostPoint.valueOffset + hostPoint.length - 1] ^= 0x01;
        expectUnauthenticated(
                () -> AuthenticatedPeerHandshakeV1.parseTranscript(untrustedOffCurve));

        clearAll(
                hostPublic,
                androidPublic,
                zeroPoint,
                wrongPrefix,
                offCurve,
                primeCoordinate,
                prime,
                canonical,
                untrustedOffCurve);
    }

    private static void verifiesHkdfLimitAndLabelIsolation() throws Exception {
        byte[] prk = hex(PRK_HEX);
        byte[] info = "limit-test".getBytes(StandardCharsets.US_ASCII);
        byte[] empty =
                AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(prk, info, 0);
        require(empty.length == 0, "HKDF permits an empty output");
        byte[] maximum =
                AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                        prk,
                        info,
                        AuthenticatedPeerHandshakeV1Internals.HKDF_SHA256_MAX_OUTPUT_BYTES);
        require(
                maximum.length
                        == AuthenticatedPeerHandshakeV1Internals.HKDF_SHA256_MAX_OUTPUT_BYTES,
                "HKDF SHA-256 255-block limit");
        expectIllegalArgument(
                () -> AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                        prk,
                        info,
                        AuthenticatedPeerHandshakeV1Internals.HKDF_SHA256_MAX_OUTPUT_BYTES + 1));
        expectIllegalArgument(
                () -> AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(prk, info, -1));

        byte[] first =
                AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                        prk, "label-a".getBytes(StandardCharsets.US_ASCII), 36);
        byte[] second =
                AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                        prk, "label-b".getBytes(StandardCharsets.US_ASCII), 36);
        require(!MessageDigest.isEqual(first, second), "independent labels separate outputs");
        clearAll(prk, info, empty, maximum, first, second);
    }

    private static void verifiesLeadingZeroEcdhNormalization() throws Exception {
        byte[] hostScalar = scalar(1);
        byte[] androidScalar = scalar(379);
        byte[] expected = hex(LEADING_ZERO_SHARED_HEX);
        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                FreshP256KeyAgreement android = fixedAgreement(androidScalar)) {
            byte[] hostPublic = host.publicKeySec1();
            byte[] androidPublic = android.publicKeySec1();
            byte[] providerSecret = rawEcdhProviderOutputForTest(hostScalar, androidPublic);
            byte[] normalized =
                    AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(
                            providerSecret);
            requireBytes(normalized, expected, "leading-zero JCA ECDH normalized BE32");

            byte[] shortened = Arrays.copyOfRange(expected, 1, expected.length);
            byte[] padded =
                    AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(shortened);
            requireBytes(padded, expected, "short provider output is left-padded");
            byte[] oversizedLeadingZero = new byte[33];
            System.arraycopy(expected, 0, oversizedLeadingZero, 1, expected.length);
            byte[] oversized = new byte[64];
            expectGeneralSecurity(
                    () -> AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(
                            oversizedLeadingZero));
            expectGeneralSecurity(
                    () -> AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(
                            oversized));

            HandshakeTranscriptV1 transcript =
                    vectorBuilder(hostPublic, androidPublic)
                            .connectionId(0x2233_4455_6677_1188L)
                            .sessionGeneration(379L)
                            .build();
            final PendingPeerHandshakeConfirmation hostPending =
                    host.deriveAfterPeerIdentityVerified(transcript, HOST);
            final PendingPeerHandshakeConfirmation androidPending =
                    android.deriveAfterPeerIdentityVerified(transcript, ANDROID);
            try {
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                byte[] androidFinished = androidPending.createLocalFinishedMac();
                try (PeerHandshakeSecrets hostSecrets =
                                hostPending.confirmPeerFinishedMac(androidFinished);
                        PeerHandshakeSecrets androidSecrets =
                                androidPending.confirmPeerFinishedMac(hostFinished)) {
                    requireSameSessionOutputs(hostSecrets, androidSecrets);
                }
                clearAll(hostFinished, androidFinished);
            } finally {
                hostPending.close();
                androidPending.close();
            }
            clearAll(
                    hostPublic,
                    androidPublic,
                    providerSecret,
                    normalized,
                    shortened,
                    padded,
                    oversizedLeadingZero,
                    oversized);
        }
        clearAll(hostScalar, androidScalar, expected);
    }

    private static void verifiesFreshCrossSessionAgreementAndLifecycle() throws Exception {
        byte[] firstControl;
        byte[] firstBinding;
        try (FreshP256KeyAgreement host =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement android =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            byte[] hostPublic = host.publicKeySec1();
            byte[] androidPublic = android.publicKeySec1();
            HandshakeTranscriptV1 first =
                    vectorBuilder(hostPublic, androidPublic)
                            .connectionId(0x1111_2222_3333_4444L)
                            .sessionGeneration(11L)
                            .build();
            try (PendingPeerHandshakeConfirmation hostPending =
                            host.deriveAfterPeerIdentityVerified(first, HOST);
                    PendingPeerHandshakeConfirmation androidPending =
                            android.deriveAfterPeerIdentityVerified(first, ANDROID)) {
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                byte[] androidFinished = androidPending.createLocalFinishedMac();
                try (PeerHandshakeSecrets hostSecrets =
                                hostPending.confirmPeerFinishedMac(androidFinished);
                        PeerHandshakeSecrets androidSecrets =
                                androidPending.confirmPeerFinishedMac(hostFinished)) {
                    requireSameSessionOutputs(hostSecrets, androidSecrets);
                    firstControl = hostSecrets.controlHostToAndroidMaterial();
                    firstBinding = hostSecrets.channelBindingSha256();
                }
                clearAll(hostFinished, androidFinished);
            }
            expectClosed(() -> host.deriveAfterPeerIdentityVerified(first, HOST));
            expectClosed(() -> android.deriveAfterPeerIdentityVerified(first, ANDROID));
            clearAll(hostPublic, androidPublic);
        }

        try (FreshP256KeyAgreement host =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement android =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            byte[] hostPublic = host.publicKeySec1();
            byte[] androidPublic = android.publicKeySec1();
            byte[] changedNonce = sequence(0x70, 32);
            HandshakeTranscriptV1 second =
                    vectorBuilder(hostPublic, androidPublic)
                            .androidNonce(changedNonce)
                            .connectionId(0x5555_6666_7777_8888L)
                            .sessionGeneration(12L)
                            .build();
            try (PendingPeerHandshakeConfirmation hostPending =
                            host.deriveAfterPeerIdentityVerified(second, HOST);
                    PendingPeerHandshakeConfirmation androidPending =
                            android.deriveAfterPeerIdentityVerified(second, ANDROID)) {
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                byte[] androidFinished = androidPending.createLocalFinishedMac();
                try (PeerHandshakeSecrets hostSecrets =
                                hostPending.confirmPeerFinishedMac(androidFinished);
                        PeerHandshakeSecrets androidSecrets =
                                androidPending.confirmPeerFinishedMac(hostFinished)) {
                    requireSameSessionOutputs(hostSecrets, androidSecrets);
                    byte[] secondControl = hostSecrets.controlHostToAndroidMaterial();
                    byte[] secondBinding = hostSecrets.channelBindingSha256();
                    require(
                            !MessageDigest.isEqual(firstControl, secondControl),
                            "fresh session changes traffic material");
                    require(
                            !MessageDigest.isEqual(firstBinding, secondBinding),
                            "fresh session changes channel binding");
                    clearAll(secondControl, secondBinding);
                }
                clearAll(hostFinished, androidFinished);
            }
            clearAll(hostPublic, androidPublic, changedNonce);
        }

        FreshP256KeyAgreement closed =
                AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
        closed.close();
        expectClosed(closed::publicKeySec1);

        try (FreshP256KeyAgreement actual =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement declared =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement peer =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            byte[] declaredPublic = declared.publicKeySec1();
            byte[] peerPublic = peer.publicKeySec1();
            HandshakeTranscriptV1 mismatch = vectorTranscript(declaredPublic, peerPublic);
            expectUnauthenticated(
                    () -> actual.deriveAfterPeerIdentityVerified(mismatch, HOST));
            expectClosed(() -> actual.deriveAfterPeerIdentityVerified(mismatch, HOST));
            clearAll(declaredPublic, peerPublic);
        }
        clearAll(firstControl, firstBinding);
    }

    private static void verifiesFinishedFailureClosesSecrets() throws Exception {
        byte[] hostScalar = scalar(1);
        byte[] androidScalar = scalar(2);
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        HandshakeTranscriptV1 transcript = vectorTranscript(hostPublic, androidPublic);

        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                PendingPeerHandshakeConfirmation pending =
                        host.deriveAfterPeerIdentityVerified(transcript, HOST)) {
            expectUnauthenticated(() -> pending.confirmPeerFinishedMac(new byte[32]));
            expectClosed(pending::createLocalFinishedMac);
        }

        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                FreshP256KeyAgreement android = fixedAgreement(androidScalar);
                PendingPeerHandshakeConfirmation hostPending =
                        host.deriveAfterPeerIdentityVerified(transcript, HOST);
                PendingPeerHandshakeConfirmation androidPending =
                        android.deriveAfterPeerIdentityVerified(transcript, ANDROID)) {
            byte[] hostFinished = hostPending.createLocalFinishedMac();
            byte[] androidFinished = androidPending.createLocalFinishedMac();
            expectUnauthenticated(
                    () -> hostPending.confirmPeerFinishedMac(hostFinished));
            expectClosed(
                    () -> hostPending.confirmPeerFinishedMac(androidFinished));
            clearAll(hostFinished, androidFinished);
        }

        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                PendingPeerHandshakeConfirmation pending =
                        host.deriveAfterPeerIdentityVerified(transcript, HOST)) {
            byte[] localFinished = pending.createLocalFinishedMac();
            expectUnauthenticated(() -> pending.confirmPeerFinishedMac(new byte[31]));
            expectClosed(pending::createLocalFinishedMac);
            clearAll(localFinished);
        }

        byte[] oldAndroidFinished;
        try (FreshP256KeyAgreement android = fixedAgreement(androidScalar);
                PendingPeerHandshakeConfirmation pending =
                        android.deriveAfterPeerIdentityVerified(transcript, ANDROID)) {
            oldAndroidFinished = pending.createLocalFinishedMac();
        }
        HandshakeTranscriptV1 newSession =
                vectorBuilder(hostPublic, androidPublic)
                        .androidNonce(sequence(0x70, 32))
                        .connectionId(0x2233_4455_6677_8899L)
                        .sessionGeneration(2L)
                        .build();
        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                PendingPeerHandshakeConfirmation pending =
                        host.deriveAfterPeerIdentityVerified(newSession, HOST)) {
            byte[] localFinished = pending.createLocalFinishedMac();
            expectUnauthenticated(
                    () -> pending.confirmPeerFinishedMac(oldAndroidFinished));
            expectClosed(pending::createLocalFinishedMac);
            clearAll(localFinished);
        }
        clearAll(
                hostScalar,
                androidScalar,
                hostPublic,
                androidPublic,
                oldAndroidFinished);
    }

    private static void verifiesFreshFactoryUniquenessAndConcurrentOwnership()
            throws Exception {
        Set<String> publicKeys = new HashSet<String>();
        for (int index = 0; index < 24; index++) {
            try (FreshP256KeyAgreement agreement =
                    AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
                byte[] publicKey = agreement.publicKeySec1();
                AuthenticatedPeerHandshakeV1Internals.requireP256Point(publicKey);
                require(
                        publicKeys.add(lowercaseHex(publicKey)),
                        "public fresh factory must not reuse SEC1 public keys");
                clearAll(publicKey);
            }
        }

        try (FreshP256KeyAgreement shared =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement peer =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            byte[] sharedPublic = shared.publicKeySec1();
            byte[] peerPublic = peer.publicKeySec1();
            final HandshakeTranscriptV1 transcript =
                    vectorBuilder(sharedPublic, peerPublic)
                            .connectionId(0x3000_0000_0000_0001L)
                            .sessionGeneration(31L)
                            .build();
            final int workerCount = 12;
            final CountDownLatch ready = new CountDownLatch(workerCount);
            final CountDownLatch start = new CountDownLatch(1);
            final CountDownLatch done = new CountDownLatch(workerCount);
            final AtomicInteger successfulDerivations = new AtomicInteger();
            final AtomicInteger closedRejections = new AtomicInteger();
            final AtomicReference<PendingPeerHandshakeConfirmation> winner =
                    new AtomicReference<PendingPeerHandshakeConfirmation>();
            final AtomicReference<Throwable> unexpected = new AtomicReference<Throwable>();
            for (int index = 0; index < workerCount; index++) {
                Thread worker =
                        new Thread(
                                new Runnable() {
                                    @Override
                                    public void run() {
                                        ready.countDown();
                                        try {
                                            if (!start.await(10, TimeUnit.SECONDS)) {
                                                throw new AssertionError("Fresh race start timeout");
                                            }
                                            PendingPeerHandshakeConfirmation pending =
                                                    shared.deriveAfterPeerIdentityVerified(
                                                            transcript, HOST);
                                            successfulDerivations.incrementAndGet();
                                            if (!winner.compareAndSet(null, pending)) {
                                                pending.close();
                                                throw new AssertionError(
                                                        "more than one Fresh derive succeeded");
                                            }
                                        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
                                            if (failure.reason() == CLOSED) {
                                                closedRejections.incrementAndGet();
                                            } else {
                                                unexpected.compareAndSet(null, failure);
                                            }
                                        } catch (Throwable failure) {
                                            unexpected.compareAndSet(null, failure);
                                        } finally {
                                            done.countDown();
                                        }
                                    }
                                },
                                "vf-fresh-race-" + index);
                worker.start();
            }
            require(ready.await(10, TimeUnit.SECONDS), "Fresh race workers became ready");
            start.countDown();
            require(done.await(30, TimeUnit.SECONDS), "Fresh race workers completed");
            requireNoUnexpected(unexpected, "Fresh derive race");
            require(successfulDerivations.get() == 1, "exactly one Fresh derive succeeds");
            require(
                    closedRejections.get() == workerCount - 1,
                    "all losing Fresh derives receive CLOSED");
            PendingPeerHandshakeConfirmation winningPending = winner.get();
            require(winningPending != null, "Fresh race returns one Pending owner");
            winningPending.close();
            clearAll(sharedPublic, peerPublic);
        }
    }

    private static void verifiesConcurrentPendingConfirmationAndClose() throws Exception {
        try (FreshP256KeyAgreement host =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement();
                FreshP256KeyAgreement android =
                        AuthenticatedPeerHandshakeV1.generateFreshEphemeralKeyAgreement()) {
            byte[] hostPublic = host.publicKeySec1();
            byte[] androidPublic = android.publicKeySec1();
            HandshakeTranscriptV1 transcript =
                    vectorBuilder(hostPublic, androidPublic)
                            .connectionId(0x3000_0000_0000_0002L)
                            .sessionGeneration(32L)
                            .build();
            final PendingPeerHandshakeConfirmation hostPending =
                    host.deriveAfterPeerIdentityVerified(transcript, HOST);
            final PendingPeerHandshakeConfirmation androidPending =
                    android.deriveAfterPeerIdentityVerified(transcript, ANDROID);
            try {
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                final byte[] androidFinished = androidPending.createLocalFinishedMac();
                final int workerCount = 12;
                final CountDownLatch ready = new CountDownLatch(workerCount);
                final CountDownLatch start = new CountDownLatch(1);
                final CountDownLatch done = new CountDownLatch(workerCount);
                final AtomicInteger confirmedCount = new AtomicInteger();
                final AtomicReference<PeerHandshakeSecrets> confirmedWinner =
                        new AtomicReference<PeerHandshakeSecrets>();
                final AtomicReference<Throwable> unexpected =
                        new AtomicReference<Throwable>();
                for (int index = 0; index < workerCount; index++) {
                    final boolean closeWorker = index < 2;
                    Thread worker =
                            new Thread(
                                    new Runnable() {
                                        @Override
                                        public void run() {
                                            ready.countDown();
                                            try {
                                                if (!start.await(10, TimeUnit.SECONDS)) {
                                                    throw new AssertionError(
                                                            "Pending race start timeout");
                                                }
                                                if (closeWorker) {
                                                    hostPending.close();
                                                    return;
                                                }
                                                PeerHandshakeSecrets confirmed =
                                                        hostPending.confirmPeerFinishedMac(
                                                                androidFinished);
                                                confirmedCount.incrementAndGet();
                                                if (!confirmedWinner.compareAndSet(
                                                        null, confirmed)) {
                                                    confirmed.close();
                                                    throw new AssertionError(
                                                            "multiple confirmed owners returned");
                                                }
                                            } catch (AuthenticatedPeerHandshakeV1Exception failure) {
                                                if (failure.reason() != CLOSED) {
                                                    unexpected.compareAndSet(null, failure);
                                                }
                                            } catch (Throwable failure) {
                                                unexpected.compareAndSet(null, failure);
                                            } finally {
                                                done.countDown();
                                            }
                                        }
                                    },
                                    "vf-pending-race-" + index);
                    worker.start();
                }
                require(ready.await(10, TimeUnit.SECONDS), "Pending race workers became ready");
                start.countDown();
                require(done.await(30, TimeUnit.SECONDS), "Pending race workers completed");
                requireNoUnexpected(unexpected, "Pending confirm/close race");
                require(confirmedCount.get() <= 1, "at most one confirmed owner is returned");
                PeerHandshakeSecrets confirmed = confirmedWinner.get();
                if (confirmed != null) {
                    byte[] material = confirmed.controlHostToAndroidMaterial();
                    require(
                            !AuthenticatedPeerHandshakeV1Internals.isAllZero(material),
                            "the sole confirmed owner is usable");
                    clearAll(material);
                    confirmed.close();
                    expectAllConfirmedAccessorsClosed(confirmed);
                }
                clearAll(hostFinished, androidFinished);
            } finally {
                hostPending.close();
                androidPending.close();
            }
            clearAll(hostPublic, androidPublic);
        }
    }

    private static void verifiesTerminalZeroizationAndClosedAccessors() throws Exception {
        byte[] hostScalar = scalar(1);
        byte[] androidScalar = scalar(2);
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        HandshakeTranscriptV1 transcript = vectorTranscript(hostPublic, androidPublic);

        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                FreshP256KeyAgreement android = fixedAgreement(androidScalar)) {
            final PendingPeerHandshakeConfirmation hostPending =
                    host.deriveAfterPeerIdentityVerified(transcript, HOST);
            final PendingPeerHandshakeConfirmation androidPending =
                    android.deriveAfterPeerIdentityVerified(transcript, ANDROID);
            try {
                List<byte[]> hostScheduleArrays = captureScheduleArrays(hostPending);
                List<byte[]> androidScheduleArrays = captureScheduleArrays(androidPending);
                requireArraysLive(hostScheduleArrays, "normal host Pending schedule");
                requireArraysLive(androidScheduleArrays, "explicit-close Android schedule");
                byte[] hostFinished = hostPending.createLocalFinishedMac();
                byte[] androidFinished = androidPending.createLocalFinishedMac();
                PeerHandshakeSecrets confirmed =
                        hostPending.confirmPeerFinishedMac(androidFinished);
                requireArraysCleared(hostScheduleArrays, "normal Finished consumes Pending keys");
                expectClosed(() -> hostPending.confirmPeerFinishedMac(androidFinished));
                requireArraysCleared(
                        hostScheduleArrays, "duplicate consumption keeps keys cleared");

                List<byte[]> confirmedArrays = captureOwnedByteArrays(confirmed);
                requireArraysLive(confirmedArrays, "confirmed owner before close");
                confirmed.close();
                requireArraysCleared(confirmedArrays, "explicit confirmed close");
                expectAllConfirmedAccessorsClosed(confirmed);

                androidPending.close();
                requireArraysCleared(androidScheduleArrays, "explicit Pending close");
                expectClosed(androidPending::createLocalFinishedMac);
                clearAll(hostFinished, androidFinished);
            } finally {
                hostPending.close();
                androidPending.close();
            }
        }

        try (FreshP256KeyAgreement host = fixedAgreement(hostScalar);
                FreshP256KeyAgreement android = fixedAgreement(androidScalar);
                PendingPeerHandshakeConfirmation hostPending =
                        host.deriveAfterPeerIdentityVerified(transcript, HOST);
                PendingPeerHandshakeConfirmation androidPending =
                        android.deriveAfterPeerIdentityVerified(transcript, ANDROID)) {
            List<byte[]> rejectedScheduleArrays = captureScheduleArrays(hostPending);
            requireArraysLive(rejectedScheduleArrays, "wrong-Finished Pending schedule");
            byte[] wrongRoleFinished = hostPending.createLocalFinishedMac();
            byte[] androidFinished = androidPending.createLocalFinishedMac();
            expectUnauthenticated(
                    () -> hostPending.confirmPeerFinishedMac(wrongRoleFinished));
            requireArraysCleared(rejectedScheduleArrays, "wrong Finished clears Pending keys");
            expectClosed(
                    () -> hostPending.confirmPeerFinishedMac(androidFinished));
            clearAll(wrongRoleFinished, androidFinished);
        }
        clearAll(hostScalar, androidScalar, hostPublic, androidPublic);
    }

    private static void verifiesProviderFailureClosesFresh() throws Exception {
        byte[] hostPublic = hex(HOST_PUBLIC_HEX);
        byte[] androidPublic = hex(ANDROID_PUBLIC_HEX);
        RejectingPrivateKey rejectingPrivateKey = new RejectingPrivateKey();
        FreshP256KeyAgreement agreement =
                agreementWithPrivateKey(rejectingPrivateKey, hostPublic);
        List<byte[]> freshArrays = captureOwnedByteArrays(agreement);
        requireArraysLive(freshArrays, "provider-failure Fresh owner");
        HandshakeTranscriptV1 transcript = vectorTranscript(hostPublic, androidPublic);
        expectCryptoUnavailable(
                () -> agreement.deriveAfterPeerIdentityVerified(transcript, HOST));
        require(rejectingPrivateKey.isDestroyed(), "provider failure destroys private key owner");
        requireArraysCleared(freshArrays, "provider failure clears Fresh byte arrays");
        expectClosed(agreement::publicKeySec1);
        agreement.close();
        clearAll(hostPublic, androidPublic);
    }

    private static void verifiesProductionApiHasNoChosenSecretEntryPoint() throws Exception {
        AuthenticatedPeerHandshakeV1Exception cryptoFailure =
                AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        require(cryptoFailure.getCause() == null, "public crypto failure retains no provider cause");
        for (Method method : FreshP256KeyAgreement.class.getDeclaredMethods()) {
            String name = method.getName().toLowerCase();
            require(!name.contains("test"), "main Fresh API contains no test seam");
            require(!name.contains("scalar"), "main Fresh API contains no scalar seam");
        }
        for (java.lang.reflect.Constructor<?> constructor :
                FreshP256KeyAgreement.class.getDeclaredConstructors()) {
            require(
                    !Modifier.isPublic(constructor.getModifiers()),
                    "Fresh constructor is not a public chosen-key entry point");
        }
        for (Method method : PeerHandshakeSecrets.class.getMethods()) {
            String name = method.getName().toLowerCase();
            require(!name.contains("derive"),
                    "public secrets API exposes no caller-chosen KDF");
            require(!name.contains("exporter"),
                    "public secrets API does not expose the channel-binding exporter");
            require(!name.contains("finished"),
                    "confirmed secrets API does not expose Finished operations");
        }
        requirePendingHasNoTrafficExports(null);
        for (Class<?> mainClass :
                new Class<?>[] {
                    AuthenticatedPeerHandshakeV1.class,
                    AuthenticatedPeerHandshakeV1Exception.class,
                    AuthenticatedPeerHandshakeV1Internals.class,
                    FreshP256KeyAgreement.class,
                    HandshakeTranscriptV1.class,
                    PendingPeerHandshakeConfirmation.class,
                    PeerHandshakeKeySchedule.class,
                    PeerHandshakeSecrets.class
                }) {
            String classImage = classImageString(mainClass);
            for (String forbidden :
                    new String[] {
                        "ForTest",
                        "forTest",
                        "test scalar",
                        "sec1ForTestScalar",
                        "finishedKeyForTest",
                        "channelBindingExporterForTest"
                    }) {
                require(
                        !classImage.contains(forbidden),
                        "main class contains forbidden seam symbol: " + forbidden);
            }
        }
    }

    private static void requireVectorOutputs(PeerHandshakeSecrets secrets) throws Exception {
        requireHex(
                secrets.controlHostToAndroidMaterial(),
                CONTROL_HOST_TO_ANDROID_HEX,
                "control host-to-Android material");
        requireHex(
                secrets.controlAndroidToHostMaterial(),
                CONTROL_ANDROID_TO_HOST_HEX,
                "control Android-to-host material");
        requireHex(
                secrets.presenceHostToAndroidMaterial(), PRESENCE_HEX, "presence material");
        requireHex(secrets.videoHostToAndroidMaterial(), VIDEO_HEX, "video material");
        requireHex(secrets.idrAndroidToHostMaterial(), IDR_HEX, "IDR material");
        requireHex(secrets.mouseHostToAndroidMaterial(), MOUSE_HEX, "mouse material");
        requireHex(secrets.channelBindingSha256(), CHANNEL_BINDING_HEX, "channel binding");
        require(
                secrets.channelBindingLowercaseHex().equals(CHANNEL_BINDING_HEX),
                "channel binding lowercase hex");
    }

    private static void requireDerivedKeyVector(byte[] prk) throws Exception {
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/control/host-to-android",
                36,
                CONTROL_HOST_TO_ANDROID_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/control/android-to-host",
                36,
                CONTROL_ANDROID_TO_HOST_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/presence/host-to-android",
                36,
                PRESENCE_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/video/host-to-android",
                36,
                VIDEO_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/idr/android-to-host",
                36,
                IDR_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/mouse/host-to-android",
                36,
                MOUSE_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/finished/host",
                32,
                FINISHED_HOST_KEY_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/finished/android",
                32,
                FINISHED_ANDROID_KEY_HEX);
        requireHkdfVector(
                prk,
                "VFDUAL/PEER-HS/V1/channel-binding-exporter",
                32,
                EXPORTER_HEX);
    }

    private static void requireHkdfVector(
            byte[] prk, String label, int outputBytes, String expectedHex) throws Exception {
        byte[] output =
                AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                        prk, label.getBytes(StandardCharsets.US_ASCII), outputBytes);
        requireHex(output, expectedHex, label);
    }

    private static void requireSameSessionOutputs(
            PeerHandshakeSecrets host, PeerHandshakeSecrets android) throws Exception {
        byte[][] hostOutputs = {
            host.controlHostToAndroidMaterial(),
            host.controlAndroidToHostMaterial(),
            host.presenceHostToAndroidMaterial(),
            host.videoHostToAndroidMaterial(),
            host.idrAndroidToHostMaterial(),
            host.mouseHostToAndroidMaterial(),
            host.channelBindingSha256()
        };
        byte[][] androidOutputs = {
            android.controlHostToAndroidMaterial(),
            android.controlAndroidToHostMaterial(),
            android.presenceHostToAndroidMaterial(),
            android.videoHostToAndroidMaterial(),
            android.idrAndroidToHostMaterial(),
            android.mouseHostToAndroidMaterial(),
            android.channelBindingSha256()
        };
        try {
            for (int index = 0; index < hostOutputs.length; index++) {
                requireBytes(hostOutputs[index], androidOutputs[index], "same-session output " + index);
            }
        } finally {
            for (byte[] value : hostOutputs) clearAll(value);
            for (byte[] value : androidOutputs) clearAll(value);
        }
    }

    private static HandshakeTranscriptV1 vectorTranscript(
            byte[] hostPublic, byte[] androidPublic) {
        return vectorBuilder(hostPublic, androidPublic).build();
    }

    private static HandshakeTranscriptV1.Builder vectorBuilder(
            byte[] hostPublic, byte[] androidPublic) {
        return AuthenticatedPeerHandshakeV1.newTranscriptBuilder()
                .hostIdentitySpkiSha256(sequence(0x00, 32))
                .androidIdentitySpkiSha256(sequence(0x20, 32))
                .hostEphemeralPublicKey(hostPublic)
                .androidEphemeralPublicKey(androidPublic)
                .hostNonce(sequence(0x40, 32))
                .androidNonce(sequence(0x60, 32))
                .connectionId(0x1020_3040_5060_7080L)
                .sessionGeneration(0x0102_0304_0506_0708L)
                .transportKind(AuthenticatedPeerHandshakeV1.TransportKind.CAT6)
                .hostIpv4(hex("c0a83701"))
                .androidIpv4(hex("c0a83702"))
                .videoPort(45678)
                .controlPort(45679)
                .pairId("PAIR-2026_08.04")
                .hostRuntimeVersion("17.8.47")
                .androidRuntimeVersion("17.8.47");
    }

    private static FreshP256KeyAgreement fixedAgreement(byte[] privateScalar)
            throws Exception {
        BigInteger scalar = new BigInteger(1, privateScalar);
        ECParameterSpec parameters =
                AuthenticatedPeerHandshakeV1Internals.p256Parameters();
        PrivateKey privateKey =
                KeyFactory.getInstance(AuthenticatedPeerHandshakeV1Internals.EC_ALGORITHM)
                        .generatePrivate(new ECPrivateKeySpec(scalar, parameters));
        byte[] publicKey = fixtureSec1ForScalar(scalar, parameters);
        try {
            return agreementWithPrivateKey(privateKey, publicKey);
        } finally {
            clearAll(publicKey);
        }
    }

    private static FreshP256KeyAgreement agreementWithPrivateKey(
            PrivateKey privateKey, byte[] publicKey) throws Exception {
        Constructor<FreshP256KeyAgreement> constructor =
                FreshP256KeyAgreement.class.getDeclaredConstructor(
                        PrivateKey.class, byte[].class);
        constructor.setAccessible(true);
        boolean transferred = false;
        try {
            FreshP256KeyAgreement agreement = constructor.newInstance(privateKey, publicKey);
            transferred = true;
            return agreement;
        } finally {
            if (!transferred) {
                try {
                    privateKey.destroy();
                } catch (Exception ignored) {
                    // The fixture mirrors the production best-effort destruction boundary.
                }
            }
        }
    }

    private static byte[] fixtureSec1ForScalar(
            BigInteger scalar, ECParameterSpec parameters) throws Exception {
        if (scalar.signum() <= 0 || scalar.compareTo(parameters.getOrder()) >= 0) {
            throw new IllegalArgumentException("fixture scalar is outside P-256");
        }
        ECPoint result = null;
        ECPoint addend = parameters.getGenerator();
        BigInteger prime = ((ECFieldFp) parameters.getCurve().getField()).getP();
        BigInteger curveA = parameters.getCurve().getA();
        for (int bit = 0; bit < scalar.bitLength(); bit++) {
            if (scalar.testBit(bit)) {
                result = addFixturePoints(result, addend, prime, curveA);
            }
            addend = addFixturePoints(addend, addend, prime, curveA);
        }
        if (result == null) throw new IllegalArgumentException("fixture point is infinity");
        return AuthenticatedPeerHandshakeV1Internals.encodeP256PublicKey(
                KeyFactory.getInstance(AuthenticatedPeerHandshakeV1Internals.EC_ALGORITHM)
                        .generatePublic(new ECPublicKeySpec(result, parameters)));
    }

    private static ECPoint addFixturePoints(
            ECPoint left, ECPoint right, BigInteger prime, BigInteger curveA) {
        if (left == null) return right;
        if (right == null) return left;
        BigInteger x1 = left.getAffineX();
        BigInteger y1 = left.getAffineY();
        BigInteger x2 = right.getAffineX();
        BigInteger y2 = right.getAffineY();
        if (x1.equals(x2) && y1.add(y2).mod(prime).signum() == 0) return null;
        BigInteger slope;
        if (x1.equals(x2) && y1.equals(y2)) {
            if (y1.signum() == 0) return null;
            slope =
                    x1.multiply(x1)
                            .multiply(BigInteger.valueOf(3L))
                            .add(curveA)
                            .multiply(y1.shiftLeft(1).modInverse(prime))
                            .mod(prime);
        } else {
            slope =
                    y2.subtract(y1)
                            .multiply(x2.subtract(x1).mod(prime).modInverse(prime))
                            .mod(prime);
        }
        BigInteger x3 = slope.multiply(slope).subtract(x1).subtract(x2).mod(prime);
        BigInteger y3 = slope.multiply(x1.subtract(x3)).subtract(y1).mod(prime);
        return new ECPoint(x3, y3);
    }

    private static List<byte[]> captureScheduleArrays(
            PendingPeerHandshakeConfirmation pending) throws Exception {
        Field scheduleField =
                PendingPeerHandshakeConfirmation.class.getDeclaredField("keySchedule");
        scheduleField.setAccessible(true);
        Object schedule = scheduleField.get(pending);
        require(schedule != null, "Pending owns a key schedule before termination");
        return captureOwnedByteArrays(schedule);
    }

    private static List<byte[]> captureOwnedByteArrays(Object owner) throws Exception {
        List<byte[]> arrays = new ArrayList<byte[]>();
        Class<?> current = owner.getClass();
        while (current != null) {
            for (Field field : current.getDeclaredFields()) {
                if (field.getType() != byte[].class
                        || Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                field.setAccessible(true);
                byte[] value = (byte[]) field.get(owner);
                if (value != null) arrays.add(value);
            }
            current = current.getSuperclass();
        }
        require(!arrays.isEmpty(), "owner has private byte-array material");
        return arrays;
    }

    private static void requireArraysLive(List<byte[]> arrays, String message) {
        require(!arrays.isEmpty(), message + " has captured arrays");
        for (byte[] value : arrays) {
            require(value.length > 0, message + " array is non-empty");
            require(
                    !AuthenticatedPeerHandshakeV1Internals.isAllZero(value),
                    message + " array is live before termination");
        }
    }

    private static void requireArraysCleared(List<byte[]> arrays, String message) {
        require(!arrays.isEmpty(), message + " has captured arrays");
        for (byte[] value : arrays) {
            require(
                    AuthenticatedPeerHandshakeV1Internals.isAllZero(value),
                    message + " array is zeroized");
        }
    }

    private static void expectAllConfirmedAccessorsClosed(PeerHandshakeSecrets confirmed)
            throws Exception {
        expectClosed(confirmed::controlHostToAndroidMaterial);
        expectClosed(confirmed::controlAndroidToHostMaterial);
        expectClosed(confirmed::presenceHostToAndroidMaterial);
        expectClosed(confirmed::videoHostToAndroidMaterial);
        expectClosed(confirmed::idrAndroidToHostMaterial);
        expectClosed(confirmed::mouseHostToAndroidMaterial);
        expectClosed(confirmed::channelBindingSha256);
        expectClosed(confirmed::channelBindingLowercaseHex);
    }

    private static void requireNoUnexpected(
            AtomicReference<Throwable> unexpected, String operation) {
        Throwable failure = unexpected.get();
        if (failure == null) return;
        AssertionError assertion = new AssertionError(operation + " had an unexpected failure");
        assertion.initCause(failure);
        throw assertion;
    }

    private static String lowercaseHex(byte[] value) {
        StringBuilder encoded = new StringBuilder(value.length * 2);
        for (byte current : value) {
            encoded.append(Character.forDigit((current >>> 4) & 0x0f, 16));
            encoded.append(Character.forDigit(current & 0x0f, 16));
        }
        return encoded.toString();
    }

    private static void requirePendingHasNoTrafficExports(
            PendingPeerHandshakeConfirmation pending) {
        Class<?> pendingType = pending == null
                ? PendingPeerHandshakeConfirmation.class
                : pending.getClass();
        for (Method method : pendingType.getMethods()) {
            if (method.getDeclaringClass() != PendingPeerHandshakeConfirmation.class) continue;
            String name = method.getName();
            require(
                    name.equals("createLocalFinishedMac")
                            || name.equals("confirmPeerFinishedMac")
                            || name.equals("close"),
                    "pending type exposes only fixed confirmation operations");
        }
    }

    private static String classImageString(Class<?> type) throws Exception {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        InputStream input = type.getResourceAsStream(resource);
        if (input == null) throw new AssertionError("missing class resource: " + resource);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        try {
            int read;
            while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
            return new String(output.toByteArray(), StandardCharsets.ISO_8859_1);
        } finally {
            clearAll(buffer);
            input.close();
        }
    }

    private static byte[] rawEcdhForTest(byte[] privateScalar, byte[] peerPublic)
            throws Exception {
        byte[] provider = rawEcdhProviderOutputForTest(privateScalar, peerPublic);
        try {
            return AuthenticatedPeerHandshakeV1Internals.normalizeP256SharedSecret(provider);
        } finally {
            clearAll(provider);
        }
    }

    private static byte[] rawEcdhProviderOutputForTest(
            byte[] privateScalar, byte[] peerPublic) throws Exception {
        BigInteger scalar = new BigInteger(1, privateScalar);
        PrivateKey privateKey =
                KeyFactory.getInstance(AuthenticatedPeerHandshakeV1Internals.EC_ALGORITHM)
                        .generatePrivate(
                                new ECPrivateKeySpec(
                                        scalar,
                                        AuthenticatedPeerHandshakeV1Internals.p256Parameters()));
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(privateKey);
        agreement.doPhase(
                AuthenticatedPeerHandshakeV1Internals.publicKeyFromSec1(peerPublic), true);
        return agreement.generateSecret();
    }

    private static List<FieldSpan> fieldSpans(byte[] canonical) {
        List<FieldSpan> fields = new ArrayList<FieldSpan>();
        ByteBuffer input = ByteBuffer.wrap(canonical);
        while (input.hasRemaining()) {
            int tagOffset = input.position();
            int tag = Byte.toUnsignedInt(input.get());
            int lengthOffset = input.position();
            long unsignedLength = Integer.toUnsignedLong(input.getInt());
            require(unsignedLength <= input.remaining(), "self-test span length");
            int length = (int) unsignedLength;
            int valueOffset = input.position();
            fields.add(new FieldSpan(tag, tagOffset, lengthOffset, valueOffset, length));
            input.position(valueOffset + length);
        }
        return fields;
    }

    private static byte[] removeRange(byte[] value, int offset, int length) {
        byte[] result = new byte[value.length - length];
        System.arraycopy(value, 0, result, 0, offset);
        System.arraycopy(
                value,
                offset + length,
                result,
                offset,
                value.length - offset - length);
        return result;
    }

    private static byte[] scalar(int value) {
        byte[] scalar = new byte[32];
        ByteBuffer.wrap(scalar, scalar.length - Integer.BYTES, Integer.BYTES).putInt(value);
        return scalar;
    }

    private static byte[] sequence(int first, int length) {
        byte[] value = new byte[length];
        for (int index = 0; index < length; index++) value[index] = (byte) (first + index);
        return value;
    }

    private static String repeat(char character, int count) {
        char[] value = new char[count];
        Arrays.fill(value, character);
        return new String(value);
    }

    private static byte[] hex(String encoded) {
        if ((encoded.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] decoded = new byte[encoded.length() / 2];
        for (int index = 0; index < decoded.length; index++) {
            int high = Character.digit(encoded.charAt(index * 2), 16);
            int low = Character.digit(encoded.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
            decoded[index] = (byte) ((high << 4) | low);
        }
        return decoded;
    }

    private static void requireHex(byte[] actual, String expectedHex, String message) {
        byte[] expected = hex(expectedHex);
        try {
            requireBytes(actual, expected, message);
        } finally {
            clearAll(actual, expected);
        }
    }

    private static void requireBytes(byte[] actual, byte[] expected, String message) {
        require(MessageDigest.isEqual(actual, expected), message);
    }

    private static void expectUnauthenticated(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected generic unauthenticated rejection");
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            require(failure.reason() == UNAUTHENTICATED_HANDSHAKE,
                    "expected unauthenticated reason");
            require(
                    "authenticated peer handshake was rejected".equals(failure.getMessage()),
                    "unauthenticated errors disclose no parse or secret detail");
            require(failure.getCause() == null, "public unauthenticated failure retains no cause");
        }
    }

    private static void expectClosed(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected closed rejection");
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            require(failure.reason() == CLOSED, "expected closed reason");
            require(failure.getCause() == null, "public closed failure retains no cause");
        }
    }

    private static void expectCryptoUnavailable(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected crypto-unavailable rejection");
        } catch (AuthenticatedPeerHandshakeV1Exception failure) {
            require(failure.reason() == CRYPTO_UNAVAILABLE, "expected crypto-unavailable reason");
            require(
                    "authenticated peer handshake cryptography failed closed"
                            .equals(failure.getMessage()),
                    "provider failure is externally generic");
            require(failure.getCause() == null, "provider failure retains no public cause");
        }
    }

    private static void expectIllegalArgument(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected local-construction failure.
        }
    }

    private static void expectGeneralSecurity(CheckedAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError("expected GeneralSecurityException");
        } catch (GeneralSecurityException expected) {
            // Expected strict provider-output rejection.
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

    private static final class RejectingPrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;

        private volatile boolean destroyed;

        @Override
        public String getAlgorithm() {
            return "EC";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }

        @Override
        public void destroy() {
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }

    private static final class FieldSpan {
        final int tag;
        final int tagOffset;
        final int lengthOffset;
        final int valueOffset;
        final int length;

        FieldSpan(int tag, int tagOffset, int lengthOffset, int valueOffset, int length) {
            this.tag = tag;
            this.tagOffset = tagOffset;
            this.lengthOffset = lengthOffset;
            this.valueOffset = valueOffset;
            this.length = length;
        }
    }

    @FunctionalInterface
    private interface CheckedAction {
        void run() throws Exception;
    }
}
