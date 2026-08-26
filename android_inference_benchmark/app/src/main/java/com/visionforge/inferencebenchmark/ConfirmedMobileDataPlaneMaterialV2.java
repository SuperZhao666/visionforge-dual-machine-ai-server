package com.visionforge.inferencebenchmark;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Minimum confirmed-session material owned temporarily by the mobile data-plane installer.
 *
 * <p>This boundary deliberately excludes pairing identity, control-channel and mouse keys.
 * Every secret accessor returns a defensive copy and {@link #close()} clears the owned copies.</p>
 */
final class ConfirmedMobileDataPlaneMaterialV2 implements AutoCloseable {
    private static final int IPV4_BYTES = 4;
    private static final int TRAFFIC_MATERIAL_BYTES = 36;
    private static final String CLOSED_MESSAGE =
            "confirmed mobile data-plane material is closed";

    private final long connectionId;
    private final MobileTransportEndpoint endpoint;
    private byte[] hostIpv4;
    private byte[] androidIpv4;
    private byte[] videoHostToAndroidMaterial;
    private byte[] presenceHostToAndroidMaterial;
    private byte[] idrAndroidToHostMaterial;
    private boolean closed;

    ConfirmedMobileDataPlaneMaterialV2(
            long connectionId,
            MobileTransportEndpoint endpoint,
            byte[] hostIpv4,
            byte[] androidIpv4,
            byte[] videoHostToAndroidMaterial,
            byte[] presenceHostToAndroidMaterial,
            byte[] idrAndroidToHostMaterial) {
        if (connectionId == 0L || endpoint == null
                || !endpoint.isReadyForDataPlane()) {
            throw new IllegalArgumentException(
                    "confirmed mobile data-plane route is invalid");
        }
        this.connectionId = connectionId;
        this.endpoint = endpoint;
        this.hostIpv4 = requireLength(hostIpv4, IPV4_BYTES, "Host IPv4");
        this.androidIpv4 = requireLength(
                androidIpv4, IPV4_BYTES, "Android IPv4");
        this.videoHostToAndroidMaterial = requireLength(
                videoHostToAndroidMaterial,
                TRAFFIC_MATERIAL_BYTES,
                "video traffic material");
        this.presenceHostToAndroidMaterial = requireLength(
                presenceHostToAndroidMaterial,
                TRAFFIC_MATERIAL_BYTES,
                "presence traffic material");
        this.idrAndroidToHostMaterial = requireLength(
                idrAndroidToHostMaterial,
                TRAFFIC_MATERIAL_BYTES,
                "IDR traffic material");
    }

    synchronized long connectionId() throws GeneralSecurityException {
        requireOpen();
        return connectionId;
    }

    synchronized MobileTransportEndpoint endpoint()
            throws GeneralSecurityException {
        requireOpen();
        return endpoint;
    }

    synchronized byte[] hostIpv4() throws GeneralSecurityException {
        requireOpen();
        return hostIpv4.clone();
    }

    synchronized byte[] androidIpv4() throws GeneralSecurityException {
        requireOpen();
        return androidIpv4.clone();
    }

    synchronized byte[] videoHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return videoHostToAndroidMaterial.clone();
    }

    synchronized byte[] presenceHostToAndroidMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return presenceHostToAndroidMaterial.clone();
    }

    synchronized byte[] idrAndroidToHostMaterial()
            throws GeneralSecurityException {
        requireOpen();
        return idrAndroidToHostMaterial.clone();
    }

    @Override
    public synchronized void close() {
        if (closed) return;
        closed = true;
        clear(hostIpv4);
        hostIpv4 = null;
        clear(androidIpv4);
        androidIpv4 = null;
        clear(videoHostToAndroidMaterial);
        videoHostToAndroidMaterial = null;
        clear(presenceHostToAndroidMaterial);
        presenceHostToAndroidMaterial = null;
        clear(idrAndroidToHostMaterial);
        idrAndroidToHostMaterial = null;
    }

    private void requireOpen() throws GeneralSecurityException {
        if (closed) throw new GeneralSecurityException(CLOSED_MESSAGE);
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
