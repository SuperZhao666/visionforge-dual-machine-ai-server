package com.visionforge.inferencebenchmark;

/** Production adapter for the JNI implementation of {@link NativeVideoInferencePipeline}. */
final class QnnNativeVideoInferencePipeline implements NativeVideoInferencePipeline {
    private final FlexibleYuvMediaCodecDecoder decoder = new FlexibleYuvMediaCodecDecoder();
    private final AuthenticatedMobileDataPlaneV2 authenticatedDataPlane =
            new AuthenticatedMobileDataPlaneV2();

    @Override
    public boolean installConfirmedPeerSession(
            ConfirmedMobileDataPlaneMaterialV2 material) {
        return authenticatedDataPlane.installConfirmedSession(material);
    }

    @Override
    public void clearConfirmedPeerSession() {
        authenticatedDataPlane.close();
    }

    @Override
    public boolean prepareQnn(
            String nativeLibraryDirectory, String skeletonDirectory, String modelToken) {
        return QnnHtpBridge.prepareNativeInferenceRealtime(
                MobileInferenceBackend.QNN_HTP.token,
                nativeLibraryDirectory,
                skeletonDirectory,
                "",
                modelToken);
    }

    @Override
    public boolean prepareInference(
            String backendToken,
            String nativeLibraryDirectory,
            String vendorRuntimeDirectory,
            String portableModelPath,
            String modelToken) {
        return QnnHtpBridge.prepareNativeInferenceRealtime(
                backendToken,
                nativeLibraryDirectory,
                vendorRuntimeDirectory,
                portableModelPath,
                modelToken);
    }

    @Override
    public boolean configureInferenceDecoder(int inputWidth, int inputHeight) {
        QnnHtpBridge.bindNativeH264AccessUnitBridge(decoder);
        if (!QnnHtpBridge.configureNativeH264InferenceDecoder(inputWidth, inputHeight)) {
            return false;
        }
        if (decoder.start(inputWidth, inputHeight)) {
            return true;
        }
        QnnHtpBridge.stopNativeH264Decoder();
        return false;
    }

    @Override
    public boolean startVideoReceiver(
            String localIpv4, String expectedSourceIpv4, int port, long networkHandle) {
        if (port != AuthenticatedMobileDataPlaneV2.NETWORK_VIDEO_PORT
                || !authenticatedDataPlane.startTransport(
                        localIpv4, expectedSourceIpv4, networkHandle)) {
            return false;
        }
        if (QnnHtpBridge.startNativeVideoReceiver(
                AuthenticatedMobileDataPlaneV2.LOOPBACK_IPV4,
                AuthenticatedMobileDataPlaneV2.LOOPBACK_IPV4,
                AuthenticatedMobileDataPlaneV2.NATIVE_VIDEO_PORT,
                networkHandle)) {
            return true;
        }
        authenticatedDataPlane.stopTransport();
        return false;
    }

    @Override
    public void stopVideoReceiver() {
        try {
            QnnHtpBridge.stopNativeVideoReceiver();
        } finally {
            authenticatedDataPlane.stopTransport();
        }
    }

    @Override
    public void stopInferenceDecoder() {
        decoder.stop();
        QnnHtpBridge.stopNativeH264Decoder();
    }

    @Override
    public void stop() {
        try {
            stopVideoReceiver();
        } finally {
            try {
                stopInferenceDecoder();
            } finally {
                QnnHtpBridge.releaseNativeInferenceRealtime();
            }
        }
    }

    @Override
    public String qnnReport() {
        return QnnHtpBridge.getNativeQnnRealtimeReport();
    }

    @Override
    public String videoReceiverReport() {
        return authenticatedDataPlane.report() + " native={"
                + QnnHtpBridge.getNativeVideoReceiverReport() + "}";
    }
}
