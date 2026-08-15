package com.visionforge.inferencebenchmark;

/**
 * Tracks whether an unavailable CAT6 button endpoint has already been handled.
 *
 * <p>Android can repeat equivalent network callbacks while MAKCU is the active
 * output route. The first unavailable observation remains visible, while later
 * observations cannot restart stop bookkeeping or manufacture duplicate events.</p>
 */
final class Cat6MouseButtonEndpointPolicy {
    private boolean unavailableHandled;

    synchronized boolean shouldHandleUnavailable(boolean inputAlreadyStopped) {
        if (inputAlreadyStopped && unavailableHandled) return false;
        unavailableHandled = true;
        return true;
    }

    synchronized void recordEndpointStarting() {
        unavailableHandled = false;
    }
}
