package com.visionforge.inferencebenchmark;

/** Native move callback sink owned by the selected phone-side output transport. */
interface ControlOutputMoveSink {
    boolean offerMoveFromNative(
            int deltaX, int deltaY, long ticket, long remainingBudgetUs);

    default boolean offerMoveFromNative(int deltaX, int deltaY, long ticket) {
        return offerMoveFromNative(
                deltaX, deltaY, ticket, ControlMoveDeadline.DEFAULT_BUDGET_US);
    }

    boolean suspendMoveDeliveryForNativeRecovery(long generation);

    boolean resumeMoveDeliveryAfterNativeRecovery(long generation);

    boolean failClosedNativeMoveDelivery();
}
