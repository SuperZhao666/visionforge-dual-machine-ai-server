package com.visionforge.inferencebenchmark;

import com.visionforge.inferencebenchmark.handshake.AuthenticatedPeerHandshakeV1;
import com.visionforge.inferencebenchmark.handshake.PeerHandshakeSecrets;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Confirmed Android peer-session metadata and role-separated key material.
 *
 * <p>The underlying key owner is never exposed. Every byte-array accessor
 * returns a defensive copy, and {@link #close()} clears all metadata copies and
 * closes the confirmed handshake secrets.</p>
 */
public final class ConfirmedAndroidPeerSession implements AutoCloseable {
    private static final String CLOSED_MESSAGE =
            "confirmed Android peer session is closed";

    private final String pairId;
    private final long connectionId;
    private final long sessionGeneration;
    private final AuthenticatedPeerHandshakeV1.TransportKind transportKind;
    private byte[] hostIpv4;
    private byte[] androidIpv4;
    private final int videoPort;
    private final int controlPort;
    private byte[] transcriptHashSha256;
    private PeerHandshakeSecrets secrets;
    private boolean closed;

    ConfirmedAndroidPeerSession(
            String pairId,
            long connectionId,
            long sessionGeneration,
            AuthenticatedPeerHandshakeV1.TransportKind transportKind,
            byte[] hostIpv4,
            byte[] androidIpv4,
            int videoPort,
            int controlPort,
            byte[] transcriptHashSha256,
            PeerHandshakeSecrets secrets) {
        if (pairId == null || pairId.isEmpty()
                || connectionId == 0L
                || sessionGeneration == 0L
                || transportKind == null
                || videoPort < 1 || videoPort > 0xffff
                || controlPort < 1 || controlPort > 0xffff
                || videoPort == controlPort
                || secrets == null) {
            throw new IllegalArgumentException(
                    "confirmed peer-session metadata is invalid");
        }
        this.pairId = pairId;
        this.connectionId = connectionId;
        this.sessionGeneration = sessionGeneration;
        this.transportKind = transportKind;
        this.hostIpv4 = requireLength(hostIpv4, 4, "Host IPv4");
        this.androidIpv4 = requireLength(androidIpv4, 4, "Android IPv4");
        this.videoPort = videoPort;
        this.controlPort = controlPort;
        this.transcriptHashSha256 = requireLength(
                transcriptHashSha256,
                AuthenticatedPeerHandshakeV1.SHA256_BYTES,
                "transcript hash");
        this.secrets = secrets;
    }

    public synchronized String pairId() throws GeneralSecurityException {
        requireOpen();
        return pairId;
    }

    /** Returns the canonical unsigned-u64 connection-id bit pattern. */
    public synchronized long connectionId() throws GeneralSecurityException {
        requireOpen();
        return connectionId;
    }

    /** Returns the canonical unsigned-u64 generation bit pattern. */
    public synchronized long sessionGeneration() throws GeneralSecurityException {
        requireOpen();
        return sessionGeneration;
    }

    public synchronized AuthenticatedPeerHandshakeV1.TransportKind transportKind()
            throws GeneralSecurityException {
        requireOpen();
        return transportKind;
    }

    public synchronized byte[] hostIpv4() throws GeneralSecurityException {
        requireOpen();
        return hostIpv4.clone();
    }

    public synchronized byte[] androidIpv4() throws GeneralSecurityException {
        requireOpen();
        return androidIpv4.clone();
    }

    public synchronized int videoPort() throws GeneralSecurityException {
        requireOpen();
        return videoPort;
    }

    public synchronized int controlPort() throws GeneralSecurityException {
        requireOpen();
        return controlPort;
    }

    public synchronized byte[] transcriptHashSha256()
            throws GeneralSecurityException {
        requireOpen();
        return transcriptHashSha256.clone();
    }

    public synchronized byte[] channelBindingSha256()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.channelBindingSha256();
    }

    public synchronized String channelBindingLowercaseHex()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.channelBindingLowercaseHex();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] controlHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.controlHostToAndroidMaterial();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] controlAndroidToHostMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.controlAndroidToHostMaterial();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] presenceHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.presenceHostToAndroidMaterial();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] videoHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.videoHostToAndroidMaterial();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] idrAndroidToHostMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.idrAndroidToHostMaterial();
    }

    /** Returns AES-256 key[32] followed by nonce prefix[4]. */
    public synchronized byte[] mouseHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return secrets.mouseHostToAndroidMaterial();
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        PeerHandshakeSecrets ownedSecrets = secrets;
        secrets = null;
        if (ownedSecrets != null) ownedSecrets.close();
        clear(hostIpv4);
        hostIpv4 = null;
        clear(androidIpv4);
        androidIpv4 = null;
        clear(transcriptHashSha256);
        transcriptHashSha256 = null;
    }

    private void requireOpen() throws GeneralSecurityException {
        if (closed || secrets == null) {
            throw new GeneralSecurityException(CLOSED_MESSAGE);
        }
    }

    private static byte[] requireLength(byte[] value, int length, String label) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(label + " has invalid length");
        }
        return value.clone();
    }

    private static void clear(byte[] value) {
        if (value != null) Arrays.fill(value, (byte) 0);
    }
}
