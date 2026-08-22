package com.visionforge.inferencebenchmark.handshake;

import java.security.MessageDigest;
import java.util.Arrays;

/** Frozen Python/Java interoperability vectors for pair-generation dual PoP. */
public final class PairGenerationPopV1SelfTest {
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
    private static final String SERVER_NONCE_HEX =
            "dc66120c8c1a81e879aac654e34421b5"
                    + "5111d30c5e6836df235f18e90c0b0e69";
    private static final long CONNECTION_ID = 63_191_577_505_803_677L;

    private PairGenerationPopV1SelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        PairGenerationPopV1.ChallengeRequest request = request();
        check(request.canonicalBytes().length == 587);
        check(hex(request.payloadSha256()).equals(
                "f5fe7552fdd4009c4fcf6bb795cc8fe4"
                        + "9c8ced14f90e82fdef384029f171acea"));

        byte[] hostNonce = sequence(0x40);
        byte[] androidNonce = sequence(0x60);
        byte[] serverNonce = decodeHex(SERVER_NONCE_HEX);
        long connectionId = PairGenerationPopV1.deriveConnectionId(
                serverNonce,
                repeat("06", 16),
                hostNonce,
                androidNonce,
                repeat("04", 16),
                repeat("10", 32),
                repeat("20", 32));
        check(connectionId == CONNECTION_ID);

        PairGenerationProposalV1 proposal = proposal(
                connectionId, hostNonce, androidNonce);
        check(hex(proposal.proposalSha256()).equals(
                "f347088b897243eb8a2f1a69fb1e031c"
                        + "acd7f35cd2163efa9741dcf2964caf3f"));
        PairGenerationPopV1.FinalCredentialProof proof =
                PairGenerationPopV1.buildFinalCredentialProof(
                        request,
                        repeat("06", 16),
                        0x1234_5678L,
                        serverNonce,
                        proposal);
        check(proof.connectionId() == CONNECTION_ID);
        check(proof.canonicalBytes().length == 1033);
        check(hex(proof.payloadSha256()).equals(
                "2fe727665a08adf4893b869a8d5c9842"
                        + "064b53f8952a32693ca37fd2a83a72e1"));
        check(proof.transcriptProposalSha256().equals(
                hex(proposal.proposalSha256())));

        byte[] first = request.canonicalBytes();
        byte[] second = request.canonicalBytes();
        first[0] ^= 1;
        check(!Arrays.equals(first, second));
        expect(PairGenerationPopV1.ErrorCode.CONNECTION_ID_MISMATCH,
                () -> PairGenerationPopV1.buildFinalCredentialProof(
                        request,
                        repeat("06", 16),
                        0x1234_5678L,
                        serverNonce,
                        proposal(CONNECTION_ID + 1L, hostNonce, androidNonce)));
        expect(PairGenerationPopV1.ErrorCode.IDENTITY_ROLES_INVALID,
                () -> new PairGenerationPopV1.ChallengeFields(
                        repeat("01", 16),
                        repeat("02", 16),
                        repeat("03", 16),
                        repeat("04", 16),
                        repeat("05", 16),
                        1L,
                        1L,
                        repeat("10", 32),
                        repeat("10", 32)));
        check(MessageDigest.isEqual(
                request.payloadSha256(),
                MessageDigest.getInstance("SHA-256")
                        .digest(request.canonicalBytes())));
        System.out.println("ANDROID_PAIR_GENERATION_POP_V1_OK");
    }

    private static PairGenerationPopV1.ChallengeRequest request()
            throws Exception {
        return PairGenerationPopV1.buildChallengeRequest(
                new PairGenerationPopV1.ChallengeFields(
                        repeat("01", 16),
                        repeat("02", 16),
                        repeat("03", 16),
                        repeat("04", 16),
                        repeat("05", 16),
                        0x0102_0304_0506_0708L,
                        9L,
                        repeat("10", 32),
                        repeat("20", 32)));
    }

    private static PairGenerationProposalV1 proposal(
            long connectionId, byte[] hostNonce, byte[] androidNonce)
            throws Exception {
        return PairGenerationProposalV1.newBuilder()
                .hostIdentitySpkiSha256(decodeHex(repeat("10", 32)))
                .androidIdentitySpkiSha256(decodeHex(repeat("20", 32)))
                .hostEphemeralPublicKey(decodeHex(HOST_PUBLIC_HEX))
                .androidEphemeralPublicKey(decodeHex(ANDROID_PUBLIC_HEX))
                .hostNonce(hostNonce)
                .androidNonce(androidNonce)
                .connectionId(connectionId)
                .transportKind(
                        AuthenticatedPeerHandshakeV1.TransportKind.CAT6)
                .hostIpv4(decodeHex("c0a83701"))
                .androidIpv4(decodeHex("c0a83702"))
                .videoPort(45678)
                .controlPort(45679)
                .pairId(repeat("04", 16))
                .hostRuntimeVersion("17.8.47")
                .androidRuntimeVersion("17.8.47")
                .build();
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    private static void expect(
            PairGenerationPopV1.ErrorCode code, CheckedAction action)
            throws Exception {
        try {
            action.run();
            throw new AssertionError("invalid PoP input was accepted");
        } catch (PairGenerationPopV1.PopException expected) {
            check(expected.code() == code);
            check(expected.getCause() == null);
        }
    }

    private static byte[] sequence(int first) {
        byte[] value = new byte[32];
        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (first + index);
        }
        return value;
    }

    private static byte[] decodeHex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(
                    value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte current : value) {
            result.append(String.format("%02x", current & 0xff));
        }
        return result.toString();
    }

    private static String repeat(String value, int count) {
        StringBuilder result = new StringBuilder(value.length() * count);
        for (int index = 0; index < count; index++) result.append(value);
        return result.toString();
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("check failed");
    }
}
