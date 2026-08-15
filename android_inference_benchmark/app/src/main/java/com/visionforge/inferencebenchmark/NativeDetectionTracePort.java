package com.visionforge.inferencebenchmark;

/** Minimal boundary around the offline-only native QNN detection trace. */
interface NativeDetectionTracePort {
    void begin(int maximumFrames);

    String exportCsv();
}
