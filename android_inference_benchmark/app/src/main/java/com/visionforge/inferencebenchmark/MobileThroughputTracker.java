package com.visionforge.inferencebenchmark;

import java.util.Locale;

/** Computes wire and fresh-content rates from monotonic counter samples. */
final class MobileThroughputTracker {
    private long previousReassembledAccessUnits = -1L;
    private long previousFreshContentAccessUnits = -1L;
    private long previousDecoderAcceptedAccessUnits = -1L;
    private long previousDecodedFrames = -1L;
    private long previousFreshDecodedFrames = -1L;
    private long previousQnnExecutions = -1L;
    private long previousSampleMillis = -1L;

    Rates update(long reassembledAccessUnits, long freshContentAccessUnits,
                 long decoderAcceptedAccessUnits, long decodedFrames,
                 long freshDecodedFrames, long qnnExecutions, long sampleMillis) {
        Rates rates = Rates.unavailable();
        if (hasValidPreviousSample() && hasValidCounters(reassembledAccessUnits,
                freshContentAccessUnits, decoderAcceptedAccessUnits, decodedFrames,
                freshDecodedFrames, qnnExecutions)
                && sampleMillis > previousSampleMillis && countersDidNotRegress(
                reassembledAccessUnits, freshContentAccessUnits,
                decoderAcceptedAccessUnits, decodedFrames,
                freshDecodedFrames, qnnExecutions)) {
            double elapsedSeconds = (sampleMillis - previousSampleMillis) / 1000.0;
            rates = new Rates(
                    (reassembledAccessUnits - previousReassembledAccessUnits) / elapsedSeconds,
                    (freshContentAccessUnits - previousFreshContentAccessUnits) / elapsedSeconds,
                    (decoderAcceptedAccessUnits - previousDecoderAcceptedAccessUnits) / elapsedSeconds,
                    (decodedFrames - previousDecodedFrames) / elapsedSeconds,
                    (freshDecodedFrames - previousFreshDecodedFrames) / elapsedSeconds,
                    (qnnExecutions - previousQnnExecutions) / elapsedSeconds);
        }
        previousReassembledAccessUnits = reassembledAccessUnits;
        previousFreshContentAccessUnits = freshContentAccessUnits;
        previousDecoderAcceptedAccessUnits = decoderAcceptedAccessUnits;
        previousDecodedFrames = decodedFrames;
        previousFreshDecodedFrames = freshDecodedFrames;
        previousQnnExecutions = qnnExecutions;
        previousSampleMillis = sampleMillis;
        return rates;
    }

    private boolean hasValidPreviousSample() {
        return previousSampleMillis >= 0L && hasValidCounters(previousReassembledAccessUnits,
                previousFreshContentAccessUnits, previousDecoderAcceptedAccessUnits,
                previousDecodedFrames, previousFreshDecodedFrames, previousQnnExecutions);
    }

    private static boolean hasValidCounters(long reassembledAccessUnits,
                                             long freshContentAccessUnits,
                                             long decoderAcceptedAccessUnits, long decodedFrames,
                                             long freshDecodedFrames, long qnnExecutions) {
        return reassembledAccessUnits >= 0L && freshContentAccessUnits >= 0L
                && decoderAcceptedAccessUnits >= 0L && decodedFrames >= 0L
                && freshDecodedFrames >= 0L && qnnExecutions >= 0L;
    }

    private boolean countersDidNotRegress(long reassembledAccessUnits,
                                          long freshContentAccessUnits,
                                          long decoderAcceptedAccessUnits, long decodedFrames,
                                          long freshDecodedFrames, long qnnExecutions) {
        return reassembledAccessUnits >= previousReassembledAccessUnits
                && freshContentAccessUnits >= previousFreshContentAccessUnits
                && decoderAcceptedAccessUnits >= previousDecoderAcceptedAccessUnits
                && decodedFrames >= previousDecodedFrames
                && freshDecodedFrames >= previousFreshDecodedFrames
                && qnnExecutions >= previousQnnExecutions;
    }

    static final class Rates {
        final String reassembledFps;
        final String freshContentFps;
        final String repeatedContentFps;
        final String decoderAcceptedFps;
        final String decodedFrameFps;
        final String freshDecodedFrameFps;
        final String qnnFps;

        private Rates(double reassembledFps, double freshContentFps,
                      double decoderAcceptedFps, double decodedFrameFps,
                      double freshDecodedFrameFps, double qnnFps) {
            this.reassembledFps = format(reassembledFps);
            this.freshContentFps = format(freshContentFps);
            this.repeatedContentFps = format(
                    Math.max(0.0, reassembledFps - freshContentFps));
            this.decoderAcceptedFps = format(decoderAcceptedFps);
            this.decodedFrameFps = format(decodedFrameFps);
            this.freshDecodedFrameFps = format(freshDecodedFrameFps);
            this.qnnFps = format(qnnFps);
        }

        static Rates unavailable() {
            return new Rates(
                    Double.NaN, Double.NaN, Double.NaN,
                    Double.NaN, Double.NaN, Double.NaN);
        }

        static Rates from(double reassembledFps, double freshContentFps,
                          double decoderAcceptedFps, double decodedFrameFps,
                          double freshDecodedFrameFps, double qnnFps) {
            return new Rates(reassembledFps, freshContentFps, decoderAcceptedFps,
                    decodedFrameFps, freshDecodedFrameFps, qnnFps);
        }

        private static String format(double value) {
            return Double.isFinite(value) ? String.format(Locale.US, "%.1f FPS", value) : "--";
        }
    }
}
