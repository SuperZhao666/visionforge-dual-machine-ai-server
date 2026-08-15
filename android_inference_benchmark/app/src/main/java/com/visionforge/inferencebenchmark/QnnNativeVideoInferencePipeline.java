package com.visionforge.inferencebenchmark;

/** Production adapter for the JNI implementation of {@link NativeVideoInferencePipeline}. */
final class QnnNativeVideoInferencePipeline implements NativeVideoInferencePipeline {
    private final FlexibleYuvMediaCodecDecoder decoder = new FlexibleYuvMediaCodecDecoder();

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
        return QnnHtpBridge.startNativeVideoReceiver(
                localIpv4, expectedSourceIpv4, port, networkHandle);
    }

    @Override
    public void stopVideoReceiver() {
        QnnHtpBridge.stopNativeVideoReceiver();
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
        return QnnHtpBridge.getNativeVideoReceiverReport();
    }
}
