package com.visionforge.inferencebenchmark;

/** Dependency-free regression test for display-only observed throughput. */
final class MobileThroughputTrackerSelfTest {
    static void run() {
        verifiesRatesFromMonotonicSamples();
        verifiesFastUiRefreshesDoNotCollapseObservedRateToZero();
        verifiesSameMillisecondRefreshPreservesObservedRate();
        verifiesCounterRegressionResetsRate();
        verifiesMissingCountersDoNotProduceRate();
    }

    private static void verifiesRatesFromMonotonicSamples() {
        MobileThroughputTracker tracker = new MobileThroughputTracker();
        require("--".equals(tracker.update(0, 0, 0, 0, 0, 0, 1_000).qnnFps));
        MobileThroughputTracker.Rates rates =
                tracker.update(32, 24, 30, 30, 22, 21, 1_500);
        require("64.0 FPS".equals(rates.reassembledFps));
        require("48.0 FPS".equals(rates.freshContentFps));
        require("16.0 FPS".equals(rates.repeatedContentFps));
        require("60.0 FPS".equals(rates.decoderAcceptedFps));
        require("60.0 FPS".equals(rates.decodedFrameFps));
        require("44.0 FPS".equals(rates.freshDecodedFrameFps));
        require("42.0 FPS".equals(rates.qnnFps));
    }

    private static void verifiesCounterRegressionResetsRate() {
        MobileThroughputTracker tracker = new MobileThroughputTracker();
        tracker.update(50, 40, 50, 50, 40, 40, 1_000);
        require("--".equals(
                tracker.update(1, 1, 1, 1, 1, 1, 1_500).decodedFrameFps));
        require("58.0 FPS".equals(
                tracker.update(30, 30, 30, 30, 30, 30, 2_000).qnnFps));
    }

    private static void verifiesFastUiRefreshesDoNotCollapseObservedRateToZero() {
        MobileThroughputTracker tracker = new MobileThroughputTracker();
        tracker.update(0, 0, 0, 0, 0, 0, 1_000);
        require("--".equals(
                tracker.update(4, 3, 4, 3, 3, 1, 1_050).freshContentFps));
        require("--".equals(
                tracker.update(8, 6, 8, 6, 6, 2, 1_100).qnnFps));

        MobileThroughputTracker.Rates visible =
                tracker.update(40, 35, 38, 34, 33, 10, 1_500);
        require("70.0 FPS".equals(visible.freshContentFps));
        require("66.0 FPS".equals(visible.freshDecodedFrameFps));
        require("20.0 FPS".equals(visible.qnnFps));

        MobileThroughputTracker.Rates held =
                tracker.update(41, 36, 39, 35, 34, 10, 1_550);
        require("70.0 FPS".equals(held.freshContentFps));
        require("66.0 FPS".equals(held.freshDecodedFrameFps));
        require("20.0 FPS".equals(held.qnnFps));
    }

    private static void verifiesSameMillisecondRefreshPreservesObservedRate() {
        MobileThroughputTracker tracker = new MobileThroughputTracker();
        tracker.update(0, 0, 0, 0, 0, 0, 1_000);
        MobileThroughputTracker.Rates visible =
                tracker.update(50, 40, 48, 45, 38, 20, 1_500);
        require("100.0 FPS".equals(visible.reassembledFps));

        // Service observers and the periodic UI tick can run in the same
        // elapsedRealtime millisecond. A duplicate observation must not erase
        // the last complete display window.
        MobileThroughputTracker.Rates duplicate =
                tracker.update(50, 40, 48, 45, 38, 20, 1_500);
        require("100.0 FPS".equals(duplicate.reassembledFps));
        require("90.0 FPS".equals(duplicate.decodedFrameFps));
    }

    private static void verifiesMissingCountersDoNotProduceRate() {
        MobileThroughputTracker tracker = new MobileThroughputTracker();
        require("--".equals(
                tracker.update(-1, -1, -1, -1, -1, -1, 1_000).reassembledFps));
        require("--".equals(
                tracker.update(20, 20, 20, 20, 20, 20, 1_500).reassembledFps));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile throughput tracker contract failed");
    }
}
