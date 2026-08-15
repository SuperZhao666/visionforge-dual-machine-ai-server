package com.visionforge.inferencebenchmark;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Dependency-free recovery and explicit-authorization contract. */
final class MakcuDeliveryGateSelfTest {
    static void run() {
        verifiesMatchingRecoveryRestoresPriorDelivery();
        verifiesNewGenerationSupersedesStaleResume();
        verifiesExplicitDisableCancelsRecoveryEligibility();
        verifiesSuspensionWithoutPriorDeliveryCannotEnableOutput();
        verifiesSuspendDrainsPendingAndWaitsForSerialIdle();
        verifiesPhysicalReleaseRevokesWithoutMainCallback();
        verifiesPendingMoveAndTicketRemainOneSnapshot();
        verifiesHotPathCanReuseOnePendingMoveSnapshot();
    }

    private static void verifiesMatchingRecoveryRestoresPriorDelivery() {
        MakcuDeliveryGate gate = new MakcuDeliveryGate();
        require(!gate.isDeliveryAllowed());
        require(gate.setUserAllowed(true));
        require(gate.isDeliveryAllowed());

        gate.suspendForRecovery(10L);
        require(gate.isRecoverySuspended() && !gate.isDeliveryAllowed());
        require(!gate.resumeAfterRecovery(9L));
        require(gate.resumeAfterRecovery(10L));
        require(gate.isDeliveryAllowed());
    }

    private static void verifiesNewGenerationSupersedesStaleResume() {
        MakcuDeliveryGate gate = new MakcuDeliveryGate();
        require(gate.setUserAllowed(true));
        gate.suspendForRecovery(20L);
        gate.suspendForRecovery(21L);
        require(!gate.resumeAfterRecovery(20L));
        require(gate.resumeAfterRecovery(21L));
        require(gate.isDeliveryAllowed());
    }

    private static void verifiesExplicitDisableCancelsRecoveryEligibility() {
        MakcuDeliveryGate gate = new MakcuDeliveryGate();
        require(gate.setUserAllowed(true));
        gate.suspendForRecovery(30L);
        require(gate.setUserAllowed(false));
        require(gate.isRecoverySuspended());
        require(!gate.resumeAfterRecovery(30L));
        require(!gate.isRecoverySuspended());
        require(gate.setUserAllowed(true));
        require(!gate.resumeAfterRecovery(30L));
        require(gate.isDeliveryAllowed());

        gate.suspendForRecovery(31L);
        gate.failClosed();
        require(!gate.isRecoverySuspended());
        require(!gate.resumeAfterRecovery(31L));
        require(!gate.isDeliveryAllowed());
    }

    private static void verifiesSuspensionWithoutPriorDeliveryCannotEnableOutput() {
        MakcuDeliveryGate gate = new MakcuDeliveryGate();
        gate.suspendForRecovery(40L);
        require(!gate.setUserAllowed(true));
        require(gate.isRecoverySuspended());
        require(!gate.resumeAfterRecovery(40L));
        require(!gate.isDeliveryAllowed());
        require(!gate.isRecoverySuspended());
        require(gate.setUserAllowed(true));
        require(gate.isDeliveryAllowed());
        require(gate.setUserAllowed(false));
        require(!gate.isRecoverySuspended());
    }

    private static void verifiesSuspendDrainsPendingAndWaitsForSerialIdle() {
        MakcuPendingMoveSlot pendingMove = new MakcuPendingMoveSlot();
        pendingMove.offer(17L, 23L);
        Object serialIoLock = new Object();
        MakcuDeliveryGate gate = new MakcuDeliveryGate(pendingMove, serialIoLock);
        require(gate.setUserAllowed(true));
        CountDownLatch serialEntered = new CountDownLatch(1);
        CountDownLatch releaseSerial = new CountDownLatch(1);
        AtomicBoolean suspendReturned = new AtomicBoolean();

        Thread writer = new Thread(() -> {
            synchronized (serialIoLock) {
                serialEntered.countDown();
                await(releaseSerial);
            }
        });
        writer.start();
        await(serialEntered);

        Thread suspender = new Thread(() -> {
            gate.suspendForRecovery(50L);
            suspendReturned.set(true);
        });
        suspender.start();
        waitUntil(() -> gate.isRecoverySuspended() && !pendingMove.hasPending());
        pendingMove.offer(19L, 29L);
        require(!suspendReturned.get());
        releaseSerial.countDown();
        join(writer);
        join(suspender);
        require(suspendReturned.get());
        require(!pendingMove.hasPending());
        require(!gate.isDeliveryAllowed());
    }

    private static void verifiesPhysicalReleaseRevokesWithoutMainCallback() {
        MakcuPendingMoveSlot pendingMove = new MakcuPendingMoveSlot();
        pendingMove.offer(17L, 23L);
        Object serialIoLock = new Object();
        MakcuDeliveryGate gate = new MakcuDeliveryGate(pendingMove, serialIoLock);
        gate.updatePhysicalButtonMask(ControlTrigger.SIDE_BUTTON_2.buttonMask);
        gate.setRequiredPhysicalButtonMask(ControlTrigger.SIDE_BUTTON_2.buttonMask);
        require(gate.setUserAllowed(true));
        require(gate.isDeliveryAllowed());

        // This is the serial-reader fast path. Deliberately never run a main
        // thread callback: offer and final-write checks must already be shut.
        long rejectedTicket = gate.updatePhysicalButtonMask(0);
        boolean offerWouldBeAccepted = gate.isDeliveryAllowed()
                && gate.isPhysicalTriggerSatisfied();
        boolean finalWriteWouldBeAccepted;
        synchronized (serialIoLock) {
            finalWriteWouldBeAccepted = gate.isDeliveryAllowed()
                    && gate.isPhysicalTriggerSatisfied();
        }

        require(rejectedTicket == 23L);
        require(!pendingMove.hasPending());
        require(!offerWouldBeAccepted);
        require(!finalWriteWouldBeAccepted);
    }

    private static void verifiesPendingMoveAndTicketRemainOneSnapshot() {
        MakcuPendingMoveSlot slot = new MakcuPendingMoveSlot();
        MakcuPendingMoveSlot.PendingMove snapshot =
                new MakcuPendingMoveSlot.PendingMove();
        slot.offer(17L, 23L);
        require(slot.takeInto(snapshot));
        require(snapshot.packed == 17L && snapshot.ticket == 23L);

        // A stale failure for an identical displacement must not erase the
        // newer native ticket that replaced it.
        slot.offer(17L, 29L);
        require(!slot.clearIfMatches(17L, 23L));
        require(slot.takeInto(snapshot));
        require(snapshot.packed == 17L && snapshot.ticket == 29L);
    }

    private static void verifiesHotPathCanReuseOnePendingMoveSnapshot() {
        MakcuPendingMoveSlot slot = new MakcuPendingMoveSlot();
        MakcuPendingMoveSlot.PendingMove destination =
                new MakcuPendingMoveSlot.PendingMove();
        require(!slot.takeInto(destination));

        slot.offer(31L, 37L);
        require(slot.takeInto(destination));
        require(destination.packed == 31L && destination.ticket == 37L);
        require(!slot.hasPending());

        slot.offer(41L, 43L);
        require(slot.takeInto(destination));
        require(destination.packed == 41L && destination.ticket == 43L);
    }

    private static void waitUntil(Condition condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (!condition.evaluate() && System.nanoTime() < deadline) Thread.yield();
        require(condition.evaluate());
    }

    private static void await(CountDownLatch latch) {
        try {
            require(latch.await(2L, TimeUnit.SECONDS));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while testing MAKCU delivery gate", exception);
        }
    }

    private static void join(Thread thread) {
        try {
            thread.join(TimeUnit.SECONDS.toMillis(2L));
            require(!thread.isAlive());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while testing MAKCU delivery gate", exception);
        }
    }

    private interface Condition {
        boolean evaluate();
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("MAKCU delivery gate contract failed");
    }
}
