package com.visionforge.inferencebenchmark;

/** Native move callback sink owned by the selected phone-side output transport. */
interface ControlOutputMoveSink {
    boolean offerMoveFromNative(int deltaX, int deltaY, long ticket);

    boolean suspendMoveDeliveryForNativeRecovery(long generation);

    boolean resumeMoveDeliveryAfterNativeRecovery(long generation);

    boolean failClosedNativeMoveDelivery();
}
