package com.visionforge.mobile.core;

/** Stable command boundary exposed to an Android Activity or another presentation layer. */
public interface RuntimeCommandPort {
    void startSession();

    void stopSession();

    void requestRecovery();
}
