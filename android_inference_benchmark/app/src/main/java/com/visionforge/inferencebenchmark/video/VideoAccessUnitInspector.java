package com.visionforge.inferencebenchmark.video;

/** Minimal allocation-free Annex-B IDR inspection used before epoch commit. */
public final class VideoAccessUnitInspector {
    private VideoAccessUnitInspector() {}

    public static boolean containsIdr(byte[] accessUnit) {
        if (accessUnit == null || accessUnit.length < 5) return false;
        for (int index = 0; index + 4 < accessUnit.length; index++) {
            int header = nalHeaderOffset(accessUnit, index);
            if (header < 0 || header >= accessUnit.length) continue;
            int nalType = accessUnit[header] & 0x1f;
            if (nalType == 5) return true;
        }
        return false;
    }

    private static int nalHeaderOffset(byte[] bytes, int index) {
        if (index + 3 < bytes.length && bytes[index] == 0
                && bytes[index + 1] == 0 && bytes[index + 2] == 1) {
            return index + 3;
        }
        if (index + 4 < bytes.length && bytes[index] == 0
                && bytes[index + 1] == 0 && bytes[index + 2] == 0
                && bytes[index + 3] == 1) {
            return index + 4;
        }
        return -1;
    }
}
