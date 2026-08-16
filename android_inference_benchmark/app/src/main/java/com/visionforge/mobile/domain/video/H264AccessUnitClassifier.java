package com.visionforge.mobile.domain.video;

import java.util.Objects;

/**
 * 只读 Annex-B NAL 分类器。它不修改码流，也不假设每帧只有一个 NAL。
 * 无起始码、非零前导垃圾、截断/空 NAL、forbidden_zero_bit 或保留 NAL 类型均
 * fail-closed 为 malformed。
 */
public final class H264AccessUnitClassifier {
    public record Classification(boolean malformed, boolean containsIdr, boolean containsSps,
                                 boolean containsPps, int nalUnitCount) {}

    private H264AccessUnitClassifier() {}

    public static Classification classify(byte[] accessUnit) {
        Objects.requireNonNull(accessUnit, "accessUnit");
        if (accessUnit.length == 0) {
            return malformed(0);
        }
        int firstStart = findStartCode(accessUnit, 0);
        if (firstStart < 0 || !allZero(accessUnit, 0, firstStart)) {
            return malformed(0);
        }

        boolean idr = false;
        boolean sps = false;
        boolean pps = false;
        int count = 0;
        int start = firstStart;
        while (start >= 0) {
            int prefix = startCodeLength(accessUnit, start);
            int headerIndex = start + prefix;
            if (headerIndex >= accessUnit.length) {
                return malformed(count);
            }
            int header = Byte.toUnsignedInt(accessUnit[headerIndex]);
            int nalType = header & 0x1f;
            if ((header & 0x80) != 0 || nalType == 0 || nalType > 23) {
                return malformed(count);
            }
            int next = findStartCode(accessUnit, headerIndex + 1);
            int nalEnd = next >= 0 ? next : accessUnit.length;
            if (nalEnd <= headerIndex + 1) {
                return malformed(count);
            }
            idr |= nalType == 5;
            sps |= nalType == 7;
            pps |= nalType == 8;
            count++;
            start = next;
        }
        return new Classification(false, idr, sps, pps, count);
    }

    private static Classification malformed(int count) {
        return new Classification(true, false, false, false, count);
    }

    private static boolean allZero(byte[] bytes, int from, int toExclusive) {
        for (int index = from; index < toExclusive; index++) {
            if (bytes[index] != 0) {
                return false;
            }
        }
        return true;
    }

    private static int findStartCode(byte[] bytes, int from) {
        for (int index = Math.max(0, from); index + 2 < bytes.length; index++) {
            if (bytes[index] == 0 && bytes[index + 1] == 0) {
                if (bytes[index + 2] == 1) {
                    return index;
                }
                if (index + 3 < bytes.length && bytes[index + 2] == 0 && bytes[index + 3] == 1) {
                    return index;
                }
            }
        }
        return -1;
    }

    private static int startCodeLength(byte[] bytes, int start) {
        return bytes[start + 2] == 1 ? 3 : 4;
    }
}
