package com.visionforge.inferencebenchmark;

/** Minimal structured-event boundary shared by independent mobile domains. */
interface MobileRuntimeEventSink {
    void write(String event, String detail);
}
