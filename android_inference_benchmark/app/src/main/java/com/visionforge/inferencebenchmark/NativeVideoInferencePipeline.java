package com.visionforge.inferencebenchmark;

/** Narrow native boundary used by the mobile video/inference lifecycle. */
interface NativeVideoInferencePipeline {
    default boolean installConfirmedPeerSession(
            ConfirmedMobileDataPlaneMaterialV2 material) {
        return false;
    }

    default void clearConfirmedPeerSession() {}

    boolean prepareQnn(
            String nativeLibraryDirectory, String skeletonDirectory, String modelToken);

    /**
     * Prepares one explicit backend. Legacy test adapters only implement the
     * QNN method; production overrides this method for NNAPI and CPU too.
     */
    default boolean prepareInference(
            String backendToken,
            String nativeLibraryDirectory,
            String vendorRuntimeDirectory,
            String portableModelPath,
            String modelToken) {
        if (MobileInferenceBackend.QNN_HTP.token.equals(backendToken)) {
            return prepareQnn(
                    nativeLibraryDirectory, vendorRuntimeDirectory, modelToken);
        }
        return false;
    }

    boolean configureInferenceDecoder(int inputWidth, int inputHeight);

    boolean startVideoReceiver(
            String localIpv4, String expectedSourceIpv4, int port, long networkHandle);

    void stopVideoReceiver();

    /** Releases only the H.264 decode path while retaining the prepared QNN graph. */
    void stopInferenceDecoder();

    void stop();

    String qnnReport();

    default String inferenceReport() {
        return qnnReport();
    }

    String videoReceiverReport();
}
