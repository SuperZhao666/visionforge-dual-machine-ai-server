package com.visionforge.inferencebenchmark.dataplane;

import java.util.Arrays;

/** Fixed-size replay window over unsigned 64-bit counter bit patterns. */
final class UnsignedReplayWindow {
    private final int windowSize;
    private final long[] seenWords;
    private boolean initialized;
    private long highestCounter;

    UnsignedReplayWindow(int windowSize) {
        if (windowSize < 1
                || windowSize > AuthenticatedDataPlaneV2.MAX_REPLAY_WINDOW_SIZE) {
            throw new IllegalArgumentException(
                    "windowSize must be in [1, "
                            + AuthenticatedDataPlaneV2.MAX_REPLAY_WINDOW_SIZE
                            + "]");
        }
        this.windowSize = windowSize;
        this.seenWords = new long[(windowSize + Long.SIZE - 1) / Long.SIZE];
    }

    Decision inspect(long counter) {
        if (!initialized || Long.compareUnsigned(counter, highestCounter) > 0) {
            return Decision.ACCEPT;
        }
        long distance = highestCounter - counter;
        if (Long.compareUnsigned(distance, Integer.toUnsignedLong(windowSize)) >= 0) {
            return Decision.TOO_OLD;
        }
        int distanceBits = (int) distance;
        return isSet(distanceBits) ? Decision.DUPLICATE : Decision.ACCEPT;
    }

    boolean commitAuthenticated(long counter) {
        if (inspect(counter) != Decision.ACCEPT) return false;
        if (!initialized) {
            initialized = true;
            highestCounter = counter;
            set(0);
            return true;
        }
        if (Long.compareUnsigned(counter, highestCounter) > 0) {
            commitNewHighest(counter);
            return true;
        }
        long distance = highestCounter - counter;
        set((int) distance);
        return true;
    }

    private void commitNewHighest(long counter) {
        long advance = counter - highestCounter;
        if (Long.compareUnsigned(advance, Integer.toUnsignedLong(windowSize)) >= 0) {
            Arrays.fill(seenWords, 0L);
        } else {
            shiftSeenCounters((int) advance);
        }
        highestCounter = counter;
        set(0);
    }

    private boolean isSet(int distance) {
        int wordIndex = distance / Long.SIZE;
        int bitIndex = distance % Long.SIZE;
        return (seenWords[wordIndex] & (1L << bitIndex)) != 0L;
    }

    private void set(int distance) {
        int wordIndex = distance / Long.SIZE;
        int bitIndex = distance % Long.SIZE;
        seenWords[wordIndex] |= 1L << bitIndex;
    }

    private void shiftSeenCounters(int advance) {
        int wordShift = advance / Long.SIZE;
        int bitShift = advance % Long.SIZE;
        for (int destination = seenWords.length - 1; destination >= 0; destination--) {
            int source = destination - wordShift;
            long shiftedValue = 0L;
            if (source >= 0) {
                shiftedValue = seenWords[source] << bitShift;
                if (bitShift != 0 && source > 0) {
                    shiftedValue |= seenWords[source - 1] >>> (Long.SIZE - bitShift);
                }
            }
            seenWords[destination] = shiftedValue;
        }
        maskUnusedHighBits();
    }

    private void maskUnusedHighBits() {
        int usedBitsInLastWord = windowSize % Long.SIZE;
        if (usedBitsInLastWord == 0) return;
        seenWords[seenWords.length - 1] &= (1L << usedBitsInLastWord) - 1L;
    }

    enum Decision {
        ACCEPT,
        DUPLICATE,
        TOO_OLD
    }
}
