package com.visionforge.inferencebenchmark;

final class QnnHtpBridge {
    static {
        System.loadLibrary("visionforge_qnn_htp");
    }

    private QnnHtpBridge() {
    }

    /** Verifies the shared C++ transport ABI used by the desktop and Android runtime. */
    static native String runDualTransportSelfTest();

    /** Debug-device benchmark entry point; production lifecycle uses prepareNativeQnnRealtime. */
    static native String runBenchmark(
            String nativeLibraryDirectory, String skeletonDirectory, String modelToken);

    static native boolean startNativeVideoReceiver(
            String localIpv4, String expectedSourceIpv4, int port, long networkHandle);

    static native void stopNativeVideoReceiver();

    static native boolean isNativeVideoReceiverRunning();

    static native String getNativeVideoReceiverReport();

    static native boolean startNativeCat6ReadyAgent(
            String localIpv4, String hostIpv4, String broadcastIpv4, long networkHandle);

    static native void stopNativeCat6ReadyAgent();

    static native boolean isNativeCat6ReadyAgentRunning();

    static native String getNativeCat6ReadyAgentReport();

    static native String getNativeCat6ReadyAgentRequesterIpv4();

    static native boolean configureNativeH264Decoder(android.view.Surface surface, int width, int height);

    static native void stopNativeH264Decoder();

    static native String getNativeH264DecoderReport();

    static native String getNativePipelineMetricsCsv();

    /** Explicit offline-only capture; disabled unless the operator starts it. */
    static native void beginNativeH264DetectionTrace(int maximumFrames);

    static native String getNativeH264DetectionTraceCsv();

    static native boolean configureNativeH264InferenceDecoder(int width, int height);

    static native void bindNativeH264AccessUnitBridge(Object decoder);

    static native boolean offerNativeDecodedYuv420(
            java.nio.ByteBuffer y, int yOffset, int yRemaining, int yRowStride, int yPixelStride,
            java.nio.ByteBuffer u, int uOffset, int uRemaining, int uRowStride, int uPixelStride,
            java.nio.ByteBuffer v, int vOffset, int vRemaining, int vRowStride, int vPixelStride,
            int imageWidth, int imageHeight,
            int cropLeft, int cropTop, int cropRight, int cropBottom, long presentationTimeUs);

    static native void discardNativeDecodedOutput(
            long presentationTimeUs, String reason, boolean fatal);

    static native void discardNativeCompressedAccessUnit(
            long presentationTimeUs, String reason, boolean fatal);

    static native void updateNativeH264JavaDecoderFormat(
            String codecName, int colorFormat, int colorStandard, int colorRange,
            int width, int height);

    static native void completeNativeH264StreamRestart(
            long generation, boolean succeeded, long elapsedUs, String diagnostic);


    static native String runRealtimeQnnInput(
            String nativeLibraryDirectory, String skeletonDirectory, String modelToken, byte[] input);

    static native boolean prepareNativeQnnRealtime(
            String nativeLibraryDirectory, String skeletonDirectory, String modelToken);

    static native boolean prepareNativeInferenceRealtime(
            String backendToken,
            String nativeLibraryDirectory,
            String vendorRuntimeDirectory,
            String portableModelPath,
            String modelToken);

    static native void releaseNativeInferenceRealtime();

    static native boolean configureNativeQnnPostprocess(float confidenceThreshold, float iouThreshold);

    /** Returns the native QNN/HTP readiness audit; UI must not infer this from decoder state. */
    static native String getNativeQnnRealtimeReport();

    static native boolean bindNativeMakcuMoveBridge(Class<?> controllerClass);

    static native boolean configureNativeMakcuControl(
            float gain,
            float deadzonePixels,
            int maximumAxisDelta,
            int switchConfirmationMillis,
            boolean outputEnabled,
            boolean personalTrajectoryEnabled,
            long personalProfileSeed,
            float personalSpeedScale,
            float personalStabilityScale,
            float personalVariationScale,
            float personalMedianDurationMillis,
            float personalPeakTimeFraction,
            float personalBellCorrelation,
            float personalJitterAmplitudePixels,
            float personalJitterMaximumPixels,
            int personalMaximumExtraCounts,
            float personalMinimumErrorPixels,
            float[] personalSpeedEnvelope,
            String modelToken,
            int bodyClassId,
            int headClassId,
            int selectedClassId,
            boolean selectedClassUsesHeadBox,
            boolean selectedClassUsesGeometricHead,
            float targetYRatio);

    /** Closes native delivery after a transport trip while preserving the active video generation. */
    static native void failClosedNativeMakcuOutput();

    /** Stable JNI callback wrapper; the native bridge binds ControlOutputMoveDispatcher. */
    static boolean offerNativeMove(int deltaX, int deltaY, long ticket) {
        return ControlOutputMoveDispatcher.offerNativeMove(deltaX, deltaY, ticket);
    }

    /** Firmware echo + prompt result for the exact native move ticket. */
    static native void reportNativeMakcuMoveResult(
            long ticket, boolean deviceAcknowledged, long acknowledgementMicros);

    /** Bluetooth HID has no report-completion callback; true is Android API acceptance. */
    static native boolean reportNativeBluetoothHidMoveAccepted(
            long ticket, long apiAcceptanceMicros);
}
