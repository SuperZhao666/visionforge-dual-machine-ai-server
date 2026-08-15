package com.visionforge.inferencebenchmark.handshake;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/** Package-private owner of key-schedule outputs before peer Finished confirmation. */
final class PeerHandshakeKeySchedule implements AutoCloseable {
    private static final byte[] FINISHED_PROOF_DOMAIN =
            ascii("VFDUAL/PEER-HS/V1/finished-proof");
    private static final byte[] CHANNEL_BINDING_DOMAIN =
            ascii("visionforge-peer-channel-binding-v1");
    private static final byte[] CONTROL_HOST_TO_ANDROID_LABEL =
            ascii("VFDUAL/PEER-HS/V1/control/host-to-android");
    private static final byte[] CONTROL_ANDROID_TO_HOST_LABEL =
            ascii("VFDUAL/PEER-HS/V1/control/android-to-host");
    private static final byte[] PRESENCE_HOST_TO_ANDROID_LABEL =
            ascii("VFDUAL/PEER-HS/V1/presence/host-to-android");
    private static final byte[] VIDEO_HOST_TO_ANDROID_LABEL =
            ascii("VFDUAL/PEER-HS/V1/video/host-to-android");
    private static final byte[] IDR_ANDROID_TO_HOST_LABEL =
            ascii("VFDUAL/PEER-HS/V1/idr/android-to-host");
    private static final byte[] MOUSE_HOST_TO_ANDROID_LABEL =
            ascii("VFDUAL/PEER-HS/V1/mouse/host-to-android");
    private static final byte[] FINISHED_HOST_LABEL =
            ascii("VFDUAL/PEER-HS/V1/finished/host");
    private static final byte[] FINISHED_ANDROID_LABEL =
            ascii("VFDUAL/PEER-HS/V1/finished/android");
    private static final byte[] CHANNEL_BINDING_EXPORTER_LABEL =
            ascii("VFDUAL/PEER-HS/V1/channel-binding-exporter");

    private final byte[] transcriptHash;
    private final byte[] controlHostToAndroid;
    private final byte[] controlAndroidToHost;
    private final byte[] presenceHostToAndroid;
    private final byte[] videoHostToAndroid;
    private final byte[] idrAndroidToHost;
    private final byte[] mouseHostToAndroid;
    private final byte[] finishedHost;
    private final byte[] finishedAndroid;
    private final byte[] channelBindingSha256;
    private boolean closed;

    private PeerHandshakeKeySchedule(
            byte[] transcriptHash,
            byte[] controlHostToAndroid,
            byte[] controlAndroidToHost,
            byte[] presenceHostToAndroid,
            byte[] videoHostToAndroid,
            byte[] idrAndroidToHost,
            byte[] mouseHostToAndroid,
            byte[] finishedHost,
            byte[] finishedAndroid,
            byte[] channelBindingSha256) {
        this.transcriptHash = transcriptHash;
        this.controlHostToAndroid = controlHostToAndroid;
        this.controlAndroidToHost = controlAndroidToHost;
        this.presenceHostToAndroid = presenceHostToAndroid;
        this.videoHostToAndroid = videoHostToAndroid;
        this.idrAndroidToHost = idrAndroidToHost;
        this.mouseHostToAndroid = mouseHostToAndroid;
        this.finishedHost = finishedHost;
        this.finishedAndroid = finishedAndroid;
        this.channelBindingSha256 = channelBindingSha256;
    }

    static PeerHandshakeKeySchedule derive(byte[] sharedSecret, byte[] transcriptHash)
            throws AuthenticatedPeerHandshakeV1Exception {
        if (sharedSecret == null
                || sharedSecret.length != 32
                || AuthenticatedPeerHandshakeV1Internals.isAllZero(sharedSecret)) {
            throw new IllegalArgumentException("P-256 shared secret must be non-zero BE32");
        }
        if (transcriptHash == null
                || transcriptHash.length != AuthenticatedPeerHandshakeV1.SHA256_BYTES) {
            throw new IllegalArgumentException("transcript hash must be 32 bytes");
        }
        byte[] prk = null;
        byte[] transcriptHashCopy = transcriptHash.clone();
        byte[] controlHostToAndroid = null;
        byte[] controlAndroidToHost = null;
        byte[] presenceHostToAndroid = null;
        byte[] videoHostToAndroid = null;
        byte[] idrAndroidToHost = null;
        byte[] mouseHostToAndroid = null;
        byte[] finishedHost = null;
        byte[] finishedAndroid = null;
        byte[] channelBindingExporter = null;
        byte[] channelBindingSha256 = null;
        boolean transferred = false;
        try {
            prk =
                    AuthenticatedPeerHandshakeV1Internals.hkdfExtractSha256(
                            transcriptHashCopy, sharedSecret);
            controlHostToAndroid = deriveLabel(
                    prk,
                    CONTROL_HOST_TO_ANDROID_LABEL,
                    AuthenticatedPeerHandshakeV1.CONTROL_MATERIAL_BYTES);
            controlAndroidToHost = deriveLabel(
                    prk,
                    CONTROL_ANDROID_TO_HOST_LABEL,
                    AuthenticatedPeerHandshakeV1.CONTROL_MATERIAL_BYTES);
            presenceHostToAndroid = deriveLabel(
                    prk,
                    PRESENCE_HOST_TO_ANDROID_LABEL,
                    AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
            videoHostToAndroid = deriveLabel(
                    prk,
                    VIDEO_HOST_TO_ANDROID_LABEL,
                    AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
            idrAndroidToHost = deriveLabel(
                    prk,
                    IDR_ANDROID_TO_HOST_LABEL,
                    AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
            mouseHostToAndroid = deriveLabel(
                    prk,
                    MOUSE_HOST_TO_ANDROID_LABEL,
                    AuthenticatedPeerHandshakeV1.DATA_PLANE_MATERIAL_BYTES);
            finishedHost = deriveLabel(
                    prk, FINISHED_HOST_LABEL, AuthenticatedPeerHandshakeV1.FINISHED_MAC_BYTES);
            finishedAndroid = deriveLabel(
                    prk,
                    FINISHED_ANDROID_LABEL,
                    AuthenticatedPeerHandshakeV1.FINISHED_MAC_BYTES);
            channelBindingExporter =
                    deriveLabel(
                            prk,
                            CHANNEL_BINDING_EXPORTER_LABEL,
                            AuthenticatedPeerHandshakeV1.CHANNEL_BINDING_BYTES);
            byte[] bindingInput =
                    concatenate(
                            CHANNEL_BINDING_DOMAIN,
                            transcriptHashCopy,
                            channelBindingExporter);
            try {
                channelBindingSha256 =
                        AuthenticatedPeerHandshakeV1Internals.sha256(bindingInput);
            } finally {
                AuthenticatedPeerHandshakeV1Internals.clear(bindingInput);
            }
            PeerHandshakeKeySchedule result =
                    new PeerHandshakeKeySchedule(
                            transcriptHashCopy,
                            controlHostToAndroid,
                            controlAndroidToHost,
                            presenceHostToAndroid,
                            videoHostToAndroid,
                            idrAndroidToHost,
                            mouseHostToAndroid,
                            finishedHost,
                            finishedAndroid,
                            channelBindingSha256);
            transferred = true;
            return result;
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(prk);
            AuthenticatedPeerHandshakeV1Internals.clear(channelBindingExporter);
            if (!transferred) {
                AuthenticatedPeerHandshakeV1Internals.clear(transcriptHashCopy);
                AuthenticatedPeerHandshakeV1Internals.clear(controlHostToAndroid);
                AuthenticatedPeerHandshakeV1Internals.clear(controlAndroidToHost);
                AuthenticatedPeerHandshakeV1Internals.clear(presenceHostToAndroid);
                AuthenticatedPeerHandshakeV1Internals.clear(videoHostToAndroid);
                AuthenticatedPeerHandshakeV1Internals.clear(idrAndroidToHost);
                AuthenticatedPeerHandshakeV1Internals.clear(mouseHostToAndroid);
                AuthenticatedPeerHandshakeV1Internals.clear(finishedHost);
                AuthenticatedPeerHandshakeV1Internals.clear(finishedAndroid);
                AuthenticatedPeerHandshakeV1Internals.clear(channelBindingSha256);
            }
        }
    }

    synchronized byte[] createFinishedMac(AuthenticatedPeerHandshakeV1.Role role)
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        byte[] key = role == AuthenticatedPeerHandshakeV1.Role.HOST
                ? finishedHost
                : finishedAndroid;
        byte[] roleCode = {(byte) role.wireCode()};
        try {
            return AuthenticatedPeerHandshakeV1Internals.hmacSha256(
                    key, FINISHED_PROOF_DOMAIN, roleCode, transcriptHash);
        } catch (GeneralSecurityException | RuntimeException failure) {
            throw AuthenticatedPeerHandshakeV1Internals.cryptoFailure();
        } finally {
            AuthenticatedPeerHandshakeV1Internals.clear(roleCode);
        }
    }

    synchronized boolean verifiesFinishedMac(
            AuthenticatedPeerHandshakeV1.Role role, byte[] untrustedMac)
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        byte[] expected = createFinishedMac(role);
        byte[] normalizedCandidate = new byte[AuthenticatedPeerHandshakeV1.FINISHED_MAC_BYTES];
        boolean canonicalLength =
                untrustedMac != null
                        && untrustedMac.length
                                == AuthenticatedPeerHandshakeV1.FINISHED_MAC_BYTES;
        if (untrustedMac != null) {
            System.arraycopy(
                    untrustedMac,
                    0,
                    normalizedCandidate,
                    0,
                    Math.min(untrustedMac.length, normalizedCandidate.length));
        }
        boolean matches = MessageDigest.isEqual(expected, normalizedCandidate);
        AuthenticatedPeerHandshakeV1Internals.clear(expected);
        AuthenticatedPeerHandshakeV1Internals.clear(normalizedCandidate);
        return canonicalLength & matches;
    }

    synchronized PeerHandshakeSecrets confirmedSecrets()
            throws AuthenticatedPeerHandshakeV1Exception {
        requireOpen();
        return new PeerHandshakeSecrets(
                controlHostToAndroid,
                controlAndroidToHost,
                presenceHostToAndroid,
                videoHostToAndroid,
                idrAndroidToHost,
                mouseHostToAndroid,
                channelBindingSha256);
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        AuthenticatedPeerHandshakeV1Internals.clear(transcriptHash);
        AuthenticatedPeerHandshakeV1Internals.clear(controlHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(controlAndroidToHost);
        AuthenticatedPeerHandshakeV1Internals.clear(presenceHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(videoHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(idrAndroidToHost);
        AuthenticatedPeerHandshakeV1Internals.clear(mouseHostToAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(finishedHost);
        AuthenticatedPeerHandshakeV1Internals.clear(finishedAndroid);
        AuthenticatedPeerHandshakeV1Internals.clear(channelBindingSha256);
    }

    private void requireOpen() throws AuthenticatedPeerHandshakeV1Exception {
        if (closed) throw AuthenticatedPeerHandshakeV1Internals.closedFailure();
    }

    private static byte[] deriveLabel(byte[] prk, byte[] label, int outputBytes)
            throws GeneralSecurityException {
        return AuthenticatedPeerHandshakeV1Internals.hkdfExpandSha256(
                prk, label, outputBytes);
    }

    private static byte[] concatenate(byte[]... values) {
        int totalBytes = 0;
        for (byte[] value : values) totalBytes = Math.addExact(totalBytes, value.length);
        byte[] joined = new byte[totalBytes];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, joined, offset, value.length);
            offset += value.length;
        }
        return joined;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
