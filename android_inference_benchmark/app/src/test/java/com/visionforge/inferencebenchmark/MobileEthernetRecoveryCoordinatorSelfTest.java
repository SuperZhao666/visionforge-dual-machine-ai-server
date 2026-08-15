package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.List;

/** Deterministic contract for CAT6 loss debounce and network-handle replacement. */
final class MobileEthernetRecoveryCoordinatorSelfTest {
    static void run() {
        verifiesSameHandleRecoveryCancelsStop();
        verifiesNewHandleReplacementRequestsRebind();
        verifiesPermanentLossExpires();
        verifiesDuplicateCallbacksAreIdempotent();
        verifiesClosedDataPlaneAdoptsPreferredLinkWithoutRebind();
        verifiesSchedulingFailureExpiresImmediatelyAndCanRecover();
        verifiesDestroyCancelsPendingWork();
    }

    private static void verifiesSameHandleRecoveryCancelsStop() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner");
        fixture.coordinator.onLinkUnavailable(57L, "lost", "owner");
        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner",
                "debounce_started:57:lost:1800:owner")));

        fixture.coordinator.onLinkReady(
                57L, "link_properties_changed", "owner");
        fixture.scheduler.runAll();
        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner",
                "debounce_started:57:lost:1800:owner",
                "debounce_cancelled:57:57:link_properties_changed:owner")));
        require(fixture.coordinator.activeNetworkHandle() == 57L);
        require(!fixture.coordinator.isDebouncePending());
    }

    private static void verifiesNewHandleReplacementRequestsRebind() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner-a");
        fixture.coordinator.onLinkUnavailable(57L, "lost", "owner-a");
        fixture.coordinator.onLinkReady(58L, "available", "owner-b");
        fixture.scheduler.runAll();

        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner-a",
                "debounce_started:57:lost:1800:owner-a",
                "debounce_cancelled:57:58:available:owner-a",
                "rebind:57:58:available:owner-b")));
        require(fixture.coordinator.activeNetworkHandle() == 58L);

        Fixture directReplacement = new Fixture();
        directReplacement.coordinator.onLinkReady(
                70L, "available", "owner-a");
        directReplacement.coordinator.onLinkReady(
                71L, "available", "owner-b");
        require(directReplacement.listener.events.equals(List.of(
                "fail_closed:70:network_handle_changed_available:owner-b",
                "rebind:70:71:available:owner-b")));
    }

    private static void verifiesPermanentLossExpires() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner");
        fixture.coordinator.onLinkUnavailable(57L, "lost", "owner");
        fixture.scheduler.runAll();

        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner",
                "debounce_started:57:lost:1800:owner",
                "debounce_expired:57:lost:owner")));
        require(fixture.coordinator.activeNetworkHandle() == 0L);
        require(!fixture.coordinator.isDebouncePending());
    }

    private static void verifiesDuplicateCallbacksAreIdempotent() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner");
        fixture.coordinator.onLinkReady(
                57L, "available_duplicate", "owner");
        fixture.coordinator.onLinkUnavailable(57L, "lost", "owner");
        fixture.coordinator.onLinkUnavailable(
                57L, "lost_duplicate", "owner");
        fixture.coordinator.onLinkReady(57L, "available", "owner");
        fixture.coordinator.onLinkReady(
                57L, "available_duplicate", "owner");

        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner",
                "debounce_started:57:lost:1800:owner",
                "debounce_cancelled:57:57:available:owner")));
    }

    private static void
            verifiesClosedDataPlaneAdoptsPreferredLinkWithoutRebind() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(
                57L, "wireless_ready", "owner");
        fixture.coordinator.adoptLinkWhileDataPlaneClosed(
                58L, "formal_start_transport_selection");
        require(fixture.coordinator.activeNetworkHandle() == 58L);
        require(fixture.listener.events.isEmpty());

        fixture.coordinator.onLinkUnavailable(
                58L, "lost_before_start", "owner");
        fixture.coordinator.adoptLinkWhileDataPlaneClosed(
                59L, "formal_start_transport_selection");
        fixture.scheduler.runAll();
        require(fixture.listener.events.equals(List.of(
                "fail_closed:58:lost_before_start:owner",
                "debounce_started:58:lost_before_start:1800:owner",
                "debounce_cancelled:58:59:formal_start_transport_selection:owner")));
        require(fixture.coordinator.activeNetworkHandle() == 59L);
    }

    private static void verifiesDestroyCancelsPendingWork() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner");
        fixture.coordinator.onLinkUnavailable(57L, "lost", "owner");
        fixture.coordinator.destroy();
        fixture.scheduler.runAll();
        fixture.coordinator.onLinkReady(
                57L, "late_available", "owner");

        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner",
                "debounce_started:57:lost:1800:owner",
                "debounce_cancelled:57:0:coordinator_destroyed:owner")));
        require(fixture.coordinator.activeNetworkHandle() == 0L);
        require(!fixture.coordinator.isDebouncePending());
    }

    private static void
            verifiesSchedulingFailureExpiresImmediatelyAndCanRecover() {
        Fixture fixture = new Fixture();
        fixture.coordinator.onLinkReady(57L, "available", "owner-a");
        fixture.scheduler.failNext = true;
        fixture.coordinator.onLinkUnavailable(
                57L, "lost", "owner-a");

        require(fixture.listener.events.equals(List.of(
                "fail_closed:57:lost:owner-a",
                "debounce_started:57:lost:1800:owner-a",
                "debounce_expired:57:lost_debounce_setup_failed_"
                        + "IllegalStateException:owner-a")));
        require(fixture.coordinator.activeNetworkHandle() == 0L);
        require(!fixture.coordinator.isDebouncePending());

        fixture.coordinator.onLinkReady(58L, "available", "owner-b");
        fixture.coordinator.onLinkUnavailable(
                58L, "lost_again", "owner-b");
        fixture.scheduler.runAll();
        require(fixture.listener.events.subList(3, 6).equals(List.of(
                "fail_closed:58:lost_again:owner-b",
                "debounce_started:58:lost_again:1800:owner-b",
                "debounce_expired:58:lost_again:owner-b")));
        require(fixture.coordinator.activeNetworkHandle() == 0L);
        require(!fixture.coordinator.isDebouncePending());
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Mobile Ethernet recovery coordinator contract failed");
        }
    }

    private static final class Fixture {
        final FakeScheduler scheduler = new FakeScheduler();
        final FakeListener listener = new FakeListener();
        final MobileEthernetRecoveryCoordinator<String> coordinator =
                new MobileEthernetRecoveryCoordinator<>(scheduler, listener);
    }

    private static final class FakeScheduler
            implements MobileEthernetRecoveryCoordinator.Scheduler {
        private final List<ScheduledTask> tasks = new ArrayList<>();
        boolean failNext;

        @Override
        public MobileEthernetRecoveryCoordinator.Cancellation schedule(
                Runnable task, long delayMillis) {
            if (failNext) {
                failNext = false;
                throw new IllegalStateException(
                        "synthetic scheduler failure");
            }
            ScheduledTask scheduled = new ScheduledTask(task, delayMillis);
            tasks.add(scheduled);
            return () -> scheduled.cancelled = true;
        }

        void runAll() {
            for (ScheduledTask task : tasks) {
                if (!task.cancelled) task.runnable.run();
            }
        }
    }

    private static final class ScheduledTask {
        final Runnable runnable;
        final long delayMillis;
        boolean cancelled;

        ScheduledTask(Runnable runnable, long delayMillis) {
            this.runnable = runnable;
            this.delayMillis = delayMillis;
        }
    }

    private static final class FakeListener
            implements MobileEthernetRecoveryCoordinator.Listener<String> {
        final List<String> events = new ArrayList<>();

        @Override
        public void failClosed(
                long networkHandle, String source, String owner) {
            events.add("fail_closed:" + networkHandle + ":" + source
                    + ":" + owner);
        }

        @Override
        public void debounceStarted(
                long networkHandle,
                String source,
                long delayMillis,
                String owner) {
            events.add("debounce_started:" + networkHandle + ":" + source
                    + ":" + delayMillis + ":" + owner);
        }

        @Override
        public void debounceCancelled(
                long lostNetworkHandle,
                long readyNetworkHandle,
                String source,
                String owner) {
            events.add("debounce_cancelled:" + lostNetworkHandle + ":"
                    + readyNetworkHandle + ":" + source + ":" + owner);
        }

        @Override
        public void debounceExpired(
                long networkHandle, String source, String owner) {
            events.add("debounce_expired:" + networkHandle + ":" + source
                    + ":" + owner);
        }

        @Override
        public void rebindRequired(
                long previousNetworkHandle,
                long replacementNetworkHandle,
                String source,
                String owner) {
            events.add("rebind:" + previousNetworkHandle + ":"
                    + replacementNetworkHandle + ":" + source
                    + ":" + owner);
        }
    }
}
