package com.visionforge.inferencebenchmark;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/** Dependency-free ordering regressions for CAT6 button listener delivery. */
final class Cat6MouseButtonNotificationDispatcherSelfTest {
    private Cat6MouseButtonNotificationDispatcherSelfTest() {
    }

    static void run() throws Exception {
        rejectsOvertakenNotification();
        rejectsLateOlderRevision();
        serializesConcurrentPressThenRelease();
    }

    private static void rejectsOvertakenNotification() {
        MutableState state = new MutableState();
        List<Integer> delivered = new ArrayList<>();
        Cat6MouseButtonNotificationDispatcher dispatcher =
                new Cat6MouseButtonNotificationDispatcher(
                        state::matches, delivered::add);

        state.set(2L, true, 8);
        dispatcher.enqueue(1L, false, 0);
        dispatcher.enqueue(2L, true, 8);
        require(delivered.equals(List.of(8)));
    }

    private static void rejectsLateOlderRevision() {
        MutableState state = new MutableState();
        List<Integer> delivered = new ArrayList<>();
        Cat6MouseButtonNotificationDispatcher dispatcher =
                new Cat6MouseButtonNotificationDispatcher(
                        state::matches, delivered::add);

        state.set(2L, false, 0);
        dispatcher.enqueue(2L, false, 0);
        dispatcher.enqueue(1L, true, 16);
        require(delivered.equals(List.of(0)));
    }

    private static void serializesConcurrentPressThenRelease()
            throws Exception {
        MutableState state = new MutableState();
        state.set(1L, true, 16);
        List<Integer> delivered = Collections.synchronizedList(
                new ArrayList<>());
        CountDownLatch pressEntered = new CountDownLatch(1);
        CountDownLatch releasePress = new CountDownLatch(1);
        Cat6MouseButtonNotificationDispatcher dispatcher =
                new Cat6MouseButtonNotificationDispatcher(
                        state::matches,
                        buttonMask -> {
                            delivered.add(buttonMask);
                            if (buttonMask == 16) {
                                pressEntered.countDown();
                                await(releasePress);
                            }
                        });

        Thread press = new Thread(
                () -> dispatcher.enqueue(1L, true, 16),
                "cat6-button-press-dispatch");
        press.start();
        pressEntered.await();
        state.set(2L, false, 0);
        Thread release = new Thread(
                () -> dispatcher.enqueue(2L, false, 0),
                "cat6-button-release-dispatch");
        release.start();
        release.join();
        releasePress.countDown();
        press.join();

        require(delivered.equals(List.of(16, 0)));
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new AssertionError("notification dispatch interrupted", interrupted);
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("CAT6 mouse-button notification dispatch failed");
        }
    }

    private static final class MutableState {
        private long revision;
        private boolean streamReady;
        private int buttonMask;

        synchronized void set(
                long revision,
                boolean streamReady,
                int buttonMask) {
            this.revision = revision;
            this.streamReady = streamReady;
            this.buttonMask = buttonMask;
        }

        synchronized boolean matches(
                long expectedRevision,
                boolean expectedStreamReady,
                int expectedButtonMask) {
            return revision == expectedRevision
                    && streamReady == expectedStreamReady
                    && buttonMask == expectedButtonMask;
        }
    }
}
