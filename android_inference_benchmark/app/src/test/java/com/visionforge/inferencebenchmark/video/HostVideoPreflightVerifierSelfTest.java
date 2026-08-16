package com.visionforge.inferencebenchmark.video;

public final class HostVideoPreflightVerifierSelfTest {
    public static void main(String[] ignored) {
        verifiesPartialFrameStartsCannotOpenBilling();
        verifiesCompleteIdrAndContinuousFrameOpenBilling();
        verifiesRepeatAndDuplicateCannotOpenBilling();
        verifiesEpochChangeAndGapRecovery();
    }

    private static void verifiesRepeatAndDuplicateCannotOpenBilling() {
        HostVideoPreflightVerifier verifier = new HostVideoPreflightVerifier(2);
        byte[] idr = idr(6L, 10L);
        require(verifier.offer(idr, idr.length, 14L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);

        // A whole-frame duplicate is network duplication, not proof of a new
        // visual frame and not a reason to destroy the healthy candidate.
        require(verifier.offer(idr, idr.length, 15L)
                == HostVideoPreflightVerifier.Decision.REJECTED);
        require(!verifier.snapshot().ready());

        byte[] repeated = packet(
                6L, 11L, true, 0, 1,
                new byte[] {0, 0, 0, 1, 0x41, (byte) 0x80});
        require(verifier.offer(repeated, repeated.length, 16L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);
        require(!verifier.snapshot().ready());
        require(verifier.snapshot().confirmedCompleteAccessUnits() == 1);

        byte[] fresh = predicted(6L, 12L);
        require(verifier.offer(fresh, fresh.length, 17L)
                == HostVideoPreflightVerifier.Decision.READY);
    }

    private static void verifiesPartialFrameStartsCannotOpenBilling() {
        HostVideoPreflightVerifier verifier = new HostVideoPreflightVerifier(2);
        byte[] firstOnly = packet(1L, 0L, false, 0, 2, new byte[] {0, 0, 0, 1});
        byte[] secondFrameFirstOnly = packet(1L, 1L, false, 0, 2, new byte[] {0, 0, 0, 1});
        require(verifier.offer(firstOnly, firstOnly.length, 1L)
                == HostVideoPreflightVerifier.Decision.BUFFERED);
        require(verifier.offer(secondFrameFirstOnly, secondFrameFirstOnly.length, 2L)
                == HostVideoPreflightVerifier.Decision.BUFFERED);
        require(!verifier.snapshot().ready());
        require(verifier.snapshot().confirmedCompleteAccessUnits() == 0);
    }

    private static void verifiesCompleteIdrAndContinuousFrameOpenBilling() {
        HostVideoPreflightVerifier verifier = new HostVideoPreflightVerifier(2);
        byte[] p0 = packet(5L, 10L, false, 0, 2, new byte[] {0, 0, 0, 1});
        byte[] p1 = packet(5L, 10L, false, 1, 2, new byte[] {0x65, (byte) 0x80});
        require(verifier.offer(p1, p1.length, 10L)
                == HostVideoPreflightVerifier.Decision.BUFFERED);
        require(verifier.offer(p0, p0.length, 11L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);

        byte[] predicted = packet(
                5L, 11L, false, 0, 1,
                new byte[] {0, 0, 0, 1, 0x41, (byte) 0x80});
        require(verifier.offer(predicted, predicted.length, 12L)
                == HostVideoPreflightVerifier.Decision.READY);
        require(verifier.snapshot().ready());
        require(verifier.snapshot().confirmedCompleteAccessUnits() == 2);
        require(verifier.snapshot().lastCompleteIdentity().equals(
                new VideoFrameIdentity(5L, 11L)));
    }

    private static void verifiesEpochChangeAndGapRecovery() {
        HostVideoPreflightVerifier verifier = new HostVideoPreflightVerifier(2);
        byte[] idr1 = idr(7L, 0L);
        byte[] p1 = predicted(7L, 1L);
        require(verifier.offer(idr1, idr1.length, 20L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);
        require(verifier.offer(p1, p1.length, 21L)
                == HostVideoPreflightVerifier.Decision.READY);

        byte[] gap = predicted(7L, 3L);
        require(verifier.offer(gap, gap.length, 22L)
                == HostVideoPreflightVerifier.Decision.RECOVERY_REQUIRED);
        byte[] recoveryIdr = idr(7L, 4L);
        require(verifier.offer(recoveryIdr, recoveryIdr.length, 23L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);
        byte[] recoveryP = predicted(7L, 5L);
        require(verifier.offer(recoveryP, recoveryP.length, 24L)
                == HostVideoPreflightVerifier.Decision.READY);

        byte[] nextEpochIdr = idr(8L, 0L);
        require(verifier.offer(nextEpochIdr, nextEpochIdr.length, 25L)
                == HostVideoPreflightVerifier.Decision.COMPLETE_BUT_NOT_READY);
        byte[] nextEpochP = predicted(8L, 1L);
        require(verifier.offer(nextEpochP, nextEpochP.length, 26L)
                == HostVideoPreflightVerifier.Decision.READY);

        VideoFragmentHeader previous = VideoWireProtocol.parse(
                recoveryP, recoveryP.length);
        VideoFragmentHeader current = VideoWireProtocol.parse(
                nextEpochIdr, nextEpochIdr.length);
        require(VideoWireProtocol.isForwardFrameStart(previous, current));
        require(!VideoWireProtocol.isForwardFrameStart(current, previous));
    }

    private static byte[] idr(long epoch, long sequence) {
        return packet(epoch, sequence, false, 0, 1,
                new byte[] {0, 0, 0, 1, 0x65, (byte) 0x80});
    }

    private static byte[] predicted(long epoch, long sequence) {
        return packet(epoch, sequence, false, 0, 1,
                new byte[] {0, 0, 0, 1, 0x41, (byte) 0x80});
    }

    private static byte[] packet(
            long epoch,
            long sequence,
            boolean repeated,
            int index,
            int count,
            byte[] payload) {
        return VideoWireProtocol.encodeForTest(
                new VideoFrameIdentity(epoch, sequence),
                repeated,
                index,
                count,
                payload);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Host video preflight verifier failed");
    }
}
