package com.visionforge.inferencebenchmark;

/** JNI adapter; no UI, USB, or evaluation policy belongs in this class. */
final class QnnNativeDetectionTracePort implements NativeDetectionTracePort {
    @Override
    public void begin(int maximumFrames) {
        QnnHtpBridge.beginNativeH264DetectionTrace(maximumFrames);
    }

    @Override
    public String exportCsv() {
        return QnnHtpBridge.getNativeH264DetectionTraceCsv();
    }
}
