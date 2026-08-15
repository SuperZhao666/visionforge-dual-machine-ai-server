package com.visionforge.inferencebenchmark;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Verifies every packaged arm64 ELF supports Android's flexible 4/16 KB pages. */
public final class MobileReleaseElfPageAlignmentSelfTest {
    private static final String APK_PROPERTY = "visionforge.release.apk";
    private static final String ARM64_LIBRARY_PREFIX = "lib/arm64-v8a/";
    private static final long MAX_LIBRARY_BYTES = 256L * 1024L * 1024L;
    private static final long REQUIRED_LOAD_ALIGNMENT = 16L * 1024L;
    private static final int ELF_HEADER_BYTES = 64;
    private static final int ELF_CLASS_64 = 2;
    private static final int ELF_DATA_LITTLE_ENDIAN = 1;
    private static final int ELF_MACHINE_AARCH64 = 183;
    private static final int PROGRAM_HEADER_TYPE_LOAD = 1;
    private static final int PROGRAM_HEADER_MINIMUM_BYTES = 56;

    private MobileReleaseElfPageAlignmentSelfTest() {}

    public static void main(String[] args) throws Exception {
        String configured = System.getProperty(APK_PROPERTY, "").trim();
        require(!configured.isEmpty(), "Release APK path is unavailable");
        Path apk = Path.of(configured).toAbsolutePath().normalize();
        require(Files.isRegularFile(apk), "Release APK is missing: " + apk);

        int verifiedLibraries = verifyApk(apk);
        require(verifiedLibraries > 0, "Release APK has no arm64 libraries");
        System.out.println(
                "MOBILE_RELEASE_ARM64_16KB_ELF_OK libraries="
                        + verifiedLibraries);
    }

    private static int verifyApk(Path apk) throws IOException {
        int verifiedLibraries = 0;
        try (ZipFile archive = new ZipFile(apk.toFile())) {
            Enumeration<? extends ZipEntry> entries = archive.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()
                        || !entry.getName().startsWith(ARM64_LIBRARY_PREFIX)
                        || !entry.getName().endsWith(".so")) {
                    continue;
                }
                require(
                        entry.getSize() > 0 && entry.getSize() <= MAX_LIBRARY_BYTES,
                        "Invalid arm64 library size: " + entry.getName());
                byte[] elf;
                try (InputStream input = archive.getInputStream(entry)) {
                    elf = input.readAllBytes();
                }
                require(
                        elf.length == entry.getSize(),
                        "Truncated arm64 library: " + entry.getName());
                verifyArm64Elf(entry.getName(), elf);
                verifiedLibraries++;
            }
        }
        return verifiedLibraries;
    }

    private static void verifyArm64Elf(String name, byte[] elf) {
        require(elf.length >= ELF_HEADER_BYTES, "ELF header is truncated: " + name);
        require(
                unsigned(elf[0]) == 0x7f
                        && elf[1] == 'E'
                        && elf[2] == 'L'
                        && elf[3] == 'F',
                "Invalid ELF magic: " + name);
        require(unsigned(elf[4]) == ELF_CLASS_64, "ELF is not 64-bit: " + name);
        require(
                unsigned(elf[5]) == ELF_DATA_LITTLE_ENDIAN,
                "ELF is not little-endian: " + name);

        ByteBuffer header = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        require(
                Short.toUnsignedInt(header.getShort(18)) == ELF_MACHINE_AARCH64,
                "ELF machine is not AArch64: " + name);
        long programHeaderOffset = header.getLong(32);
        int programHeaderBytes = Short.toUnsignedInt(header.getShort(54));
        int programHeaderCount = Short.toUnsignedInt(header.getShort(56));
        require(
                programHeaderOffset >= ELF_HEADER_BYTES
                        && programHeaderBytes >= PROGRAM_HEADER_MINIMUM_BYTES
                        && programHeaderCount > 0,
                "Invalid ELF program-header table: " + name);
        long tableBytes;
        try {
            tableBytes = Math.multiplyExact(
                    (long) programHeaderBytes, (long) programHeaderCount);
        } catch (ArithmeticException overflow) {
            throw new AssertionError("ELF program-header table overflow: " + name, overflow);
        }
        require(
                programHeaderOffset <= elf.length
                        && tableBytes <= elf.length - programHeaderOffset,
                "ELF program-header table is out of bounds: " + name);

        int loadSegments = 0;
        for (int index = 0; index < programHeaderCount; index++) {
            int offset = Math.toIntExact(
                    programHeaderOffset + (long) index * programHeaderBytes);
            if (header.getInt(offset) != PROGRAM_HEADER_TYPE_LOAD) continue;
            loadSegments++;
            long alignment = header.getLong(offset + 48);
            require(
                    alignment >= REQUIRED_LOAD_ALIGNMENT
                            && isPowerOfTwo(alignment),
                    "Arm64 LOAD segment is not 16 KB compatible: "
                            + name + " p_align=0x"
                            + Long.toHexString(alignment));
        }
        require(loadSegments > 0, "ELF has no LOAD segment: " + name);
    }

    private static boolean isPowerOfTwo(long value) {
        return value > 0 && (value & (value - 1)) == 0;
    }

    private static int unsigned(byte value) {
        return value & 0xff;
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
