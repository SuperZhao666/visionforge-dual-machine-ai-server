package com.visionforge.inferencebenchmark;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/** Regression coverage for hash-pinned, atomic portable-model installation. */
final class PortableModelAssetInstallerSelfTest {
    private PortableModelAssetInstallerSelfTest() {}

    static void run() throws Exception {
        verifiesInstallRepairAndReuse();
        verifiesInterruptedCopyLeavesNoPublishedPart();
        verifiesConcurrentCallersShareOneVerifiedFile();
        verifiesDescriptorValidation();
    }

    private static void verifiesInstallRepairAndReuse() throws Exception {
        Path root = Files.createTempDirectory("visionforge-portable-model-");
        try {
            byte[] asset = asset(23, 4097);
            PortableModelAssetInstaller.Descriptor descriptor = descriptor(asset);
            PortableModelAssetInstaller.Result first =
                    PortableModelAssetInstaller.ensureInstalled(
                            root.toFile(), descriptor,
                            name -> new ByteArrayInputStream(asset));
            require(first.ready && first.modelFile.isFile());
            require(first.detail.contains("installed=true"));
            require(java.util.Arrays.equals(
                    asset, Files.readAllBytes(first.modelFile.toPath())));

            byte[] corrupted = asset.clone();
            corrupted[corrupted.length / 2] ^= 0x5a;
            Files.write(first.modelFile.toPath(), corrupted);
            PortableModelAssetInstaller.Result repaired =
                    PortableModelAssetInstaller.ensureInstalled(
                            root.toFile(), descriptor,
                            name -> new ByteArrayInputStream(asset));
            require(repaired.ready && repaired.detail.contains("installed=true"));
            require(java.util.Arrays.equals(
                    asset, Files.readAllBytes(repaired.modelFile.toPath())));

            PortableModelAssetInstaller.Result reused =
                    PortableModelAssetInstaller.ensureInstalled(
                            root.toFile(), descriptor,
                            name -> new ByteArrayInputStream(asset));
            require(reused.ready && reused.detail.contains("installed=false"));
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static void verifiesInterruptedCopyLeavesNoPublishedPart()
            throws Exception {
        Path root = Files.createTempDirectory("visionforge-portable-interrupt-");
        try {
            byte[] asset = asset(31, 8193);
            PortableModelAssetInstaller.Descriptor descriptor = descriptor(asset);
            PortableModelAssetInstaller.Result failed =
                    PortableModelAssetInstaller.ensureInstalled(
                            root.toFile(), descriptor,
                            name -> new FailingInputStream(
                                    asset, asset.length / 2));
            require(!failed.ready && failed.failure instanceof IOException);
            File directory = new File(
                    root.toFile(), PortableModelAssetInstaller.DIRECTORY_NAME);
            require(!new File(directory, descriptor.assetName).exists());
            require(!new File(directory, descriptor.assetName + ".part").exists());
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static void verifiesConcurrentCallersShareOneVerifiedFile()
            throws Exception {
        Path root = Files.createTempDirectory("visionforge-portable-concurrent-");
        try {
            byte[] asset = asset(47, 16_385);
            PortableModelAssetInstaller.Descriptor descriptor = descriptor(asset);
            CountDownLatch start = new CountDownLatch(1);
            AtomicReference<PortableModelAssetInstaller.Result> first =
                    new AtomicReference<>();
            AtomicReference<PortableModelAssetInstaller.Result> second =
                    new AtomicReference<>();
            Thread one = new Thread(
                    () -> install(root, descriptor, asset, start, first),
                    "portable-install-one");
            Thread two = new Thread(
                    () -> install(root, descriptor, asset, start, second),
                    "portable-install-two");
            one.start();
            two.start();
            start.countDown();
            one.join();
            two.join();
            require(first.get() != null && first.get().ready);
            require(second.get() != null && second.get().ready);
            require(first.get().modelFile.equals(second.get().modelFile));
            require(java.util.Arrays.equals(
                    asset,
                    Files.readAllBytes(first.get().modelFile.toPath())));
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static void verifiesDescriptorValidation() {
        for (String name : new String[]{"../model.onnx", "model.bin", ""}) {
            try {
                new PortableModelAssetInstaller.Descriptor(
                        name, 1L, "A".repeat(64));
                throw new AssertionError("Invalid portable model name accepted");
            } catch (IllegalArgumentException expected) {
                // Expected trust-boundary rejection.
            }
        }
    }

    private static void install(
            Path root,
            PortableModelAssetInstaller.Descriptor descriptor,
            byte[] asset,
            CountDownLatch start,
            AtomicReference<PortableModelAssetInstaller.Result> result) {
        try {
            start.await();
            result.set(PortableModelAssetInstaller.ensureInstalled(
                    root.toFile(), descriptor,
                    name -> new ByteArrayInputStream(asset)));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static PortableModelAssetInstaller.Descriptor descriptor(
            byte[] asset) throws Exception {
        StringBuilder sha = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(asset)) {
            sha.append(String.format("%02X", value & 0xff));
        }
        return new PortableModelAssetInstaller.Descriptor(
                "test-model.onnx", asset.length, sha.toString());
    }

    private static byte[] asset(int seed, int size) {
        byte[] value = new byte[size];
        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (seed + index * 17);
        }
        return value;
    }

    private static void deleteRecursively(File file) throws IOException {
        if (file == null || !file.exists()) return;
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) deleteRecursively(child);
            }
        }
        Files.deleteIfExists(file.toPath());
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError(
                    "Portable model asset installer contract failed");
        }
    }

    private static final class FailingInputStream extends InputStream {
        private final byte[] value;
        private final int failureOffset;
        private int offset;

        FailingInputStream(byte[] value, int failureOffset) {
            this.value = value;
            this.failureOffset = failureOffset;
        }

        @Override
        public int read() throws IOException {
            if (offset >= failureOffset) {
                throw new IOException("synthetic portable model copy failure");
            }
            return value[offset++] & 0xff;
        }

        @Override
        public int read(byte[] buffer, int start, int length)
                throws IOException {
            if (offset >= failureOffset) {
                throw new IOException("synthetic portable model copy failure");
            }
            int count = Math.min(
                    length,
                    Math.min(failureOffset - offset, value.length - offset));
            if (count <= 0) return -1;
            System.arraycopy(value, offset, buffer, start, count);
            offset += count;
            return count;
        }
    }
}
