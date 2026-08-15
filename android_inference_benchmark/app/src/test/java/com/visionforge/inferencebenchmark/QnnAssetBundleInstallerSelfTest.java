package com.visionforge.inferencebenchmark;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/** Regression coverage for atomic, verified and process-single-flight QNN assets. */
final class QnnAssetBundleInstallerSelfTest {
    static void run() throws Exception {
        Path root = Files.createTempDirectory("visionforge-qnn-assets-");
        try {
            Map<String, byte[]> assets = createAssets(17);
            QnnAssetBundleInstaller.AssetSource source = source(assets);
            QnnAssetBundleInstaller.Result first =
                    QnnAssetBundleInstaller.ensureInstalled(root.toFile(), source);
            require(first.ready && first.directory.isDirectory());
            require(first.detail.contains("installed_files="
                    + QnnAssetBundleInstaller.ASSET_NAMES.length));
            verifyFiles(first.directory, assets);

            File corrupted = new File(first.directory, QnnAssetBundleInstaller.ASSET_NAMES[2]);
            byte[] sameLengthCorruption = assets.get(corrupted.getName()).clone();
            sameLengthCorruption[sameLengthCorruption.length / 2] ^= 0x5a;
            Files.write(corrupted.toPath(), sameLengthCorruption);
            QnnAssetBundleInstaller.Result repaired =
                    QnnAssetBundleInstaller.ensureInstalled(root.toFile(), source);
            require(repaired.ready && repaired.detail.contains("installed_files=1"));
            verifyFiles(repaired.directory, assets);

            Map<String, byte[]> updatedAssets = createAssets(43);
            QnnAssetBundleInstaller.Result updated = QnnAssetBundleInstaller.ensureInstalled(
                    root.toFile(), source(updatedAssets));
            require(updated.ready && updated.detail.contains("installed_files="
                    + QnnAssetBundleInstaller.ASSET_NAMES.length));
            verifyFiles(updated.directory, updatedAssets);

            verifyFutureArchitectureManifestAndRollback(root);
            verifyStaleSkeletonDeletionFailureIsClosed();
            verifyArchitectureManifestValidation();
            verifyConcurrentCallers(root, updatedAssets);
            verifyInterruptedCopyDoesNotPublishMarker();
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static void verifyConcurrentCallers(Path root, Map<String, byte[]> assets)
            throws Exception {
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<QnnAssetBundleInstaller.Result> first = new AtomicReference<>();
        AtomicReference<QnnAssetBundleInstaller.Result> second = new AtomicReference<>();
        Thread one = new Thread(() -> runInstaller(root, assets, start, first), "qnn-install-one");
        Thread two = new Thread(() -> runInstaller(root, assets, start, second), "qnn-install-two");
        one.start();
        two.start();
        start.countDown();
        one.join();
        two.join();
        require(first.get() != null && first.get().ready);
        require(second.get() != null && second.get().ready);
        verifyFiles(first.get().directory, assets);
    }

    private static void verifyFutureArchitectureManifestAndRollback(Path root)
            throws Exception {
        String futureManifest = "v75,v81,v83";
        Map<String, byte[]> futureAssets = createAssets(59, futureManifest);
        QnnAssetBundleInstaller.Result future = QnnAssetBundleInstaller.ensureInstalled(
                root.toFile(), source(futureAssets), futureManifest);
        require(future.ready && future.architectures.equals(
                java.util.Arrays.asList("v75", "v81", "v83")));
        verifyFiles(future.directory, futureAssets);

        File unrelated = new File(future.directory, "customer-note.keep");
        Files.write(unrelated.toPath(), new byte[]{7});
        String rollbackManifest = "v68,v69,v73,v75,v79";
        Map<String, byte[]> rollbackAssets = createAssets(61, rollbackManifest);
        QnnAssetBundleInstaller.Result rollback = QnnAssetBundleInstaller.ensureInstalled(
                root.toFile(), source(rollbackAssets), rollbackManifest);
        require(rollback.ready && rollback.detail.contains("removed_stale_files=2"));
        require(!new File(rollback.directory, "libQnnHtpV81Skel.so").exists());
        require(!new File(rollback.directory, "libQnnHtpV83Skel.so").exists());
        require(unrelated.isFile());
        verifyFiles(rollback.directory, rollbackAssets);
    }

    private static void verifyStaleSkeletonDeletionFailureIsClosed() throws Exception {
        Path root = Files.createTempDirectory("visionforge-qnn-stale-close-");
        try {
            Map<String, byte[]> assets = createAssets(67);
            QnnAssetBundleInstaller.Result initial = QnnAssetBundleInstaller.ensureInstalled(
                    root.toFile(), source(assets));
            require(initial.ready);
            File undeletable = new File(initial.directory, "libQnnHtpV81Skel.so");
            require(undeletable.mkdir());
            Files.write(new File(undeletable, "keep").toPath(), new byte[]{1});
            QnnAssetBundleInstaller.Result failed = QnnAssetBundleInstaller.ensureInstalled(
                    root.toFile(), source(assets));
            require(!failed.ready && failed.failure instanceof IOException);
            require(!new File(initial.directory,
                    QnnAssetBundleInstaller.COMPLETION_MARKER).exists());
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static void verifyArchitectureManifestValidation() {
        require(QnnAssetBundleInstaller.parseArchitectures("v81;V83").equals(
                java.util.Arrays.asList("v81", "v83")));
        for (String invalid : new String[]{
                "", "v8", "v1234", "v81,v81", "../v81",
                "v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22,v23,v24,v25,v26"}) {
            try {
                QnnAssetBundleInstaller.parseArchitectures(invalid);
                throw new AssertionError("Invalid architecture manifest accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                // Expected validation failure.
            }
        }
    }

    private static void runInstaller(
            Path root, Map<String, byte[]> assets, CountDownLatch start,
            AtomicReference<QnnAssetBundleInstaller.Result> result) {
        try {
            start.await();
            result.set(QnnAssetBundleInstaller.ensureInstalled(root.toFile(), source(assets)));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void verifyInterruptedCopyDoesNotPublishMarker() throws Exception {
        Path root = Files.createTempDirectory("visionforge-qnn-interrupt-");
        try {
            Map<String, byte[]> assets = createAssets(71);
            String failingName = QnnAssetBundleInstaller.ASSET_NAMES[0];
            Map<String, Integer> openCounts = new HashMap<>();
            QnnAssetBundleInstaller.AssetSource source = name -> {
                int count = openCounts.merge(name, 1, Integer::sum);
                byte[] value = assets.get(name);
                if (failingName.equals(name) && count >= 2) {
                    return new FailingInputStream(value, value.length / 2);
                }
                return new ByteArrayInputStream(value);
            };
            QnnAssetBundleInstaller.Result failed =
                    QnnAssetBundleInstaller.ensureInstalled(root.toFile(), source);
            require(!failed.ready && failed.failure instanceof IOException);
            File directory = new File(root.toFile(), QnnAssetBundleInstaller.DIRECTORY_NAME);
            require(!new File(directory, QnnAssetBundleInstaller.COMPLETION_MARKER).exists());
            require(!new File(directory, failingName + ".part").exists());
        } finally {
            deleteRecursively(root.toFile());
        }
    }

    private static Map<String, byte[]> createAssets(int seed) {
        return createAssets(seed, QnnAssetBundleInstaller.DEFAULT_ARCHITECTURES);
    }

    private static Map<String, byte[]> createAssets(int seed, String architectures) {
        Map<String, byte[]> assets = new HashMap<>();
        java.util.List<String> names = QnnAssetBundleInstaller.assetNames(
                QnnAssetBundleInstaller.parseArchitectures(architectures));
        for (int assetIndex = 0; assetIndex < names.size(); assetIndex++) {
            byte[] value = new byte[257 + assetIndex * 19];
            for (int index = 0; index < value.length; index++) {
                value[index] = (byte) (seed + assetIndex * 13 + index * 7);
            }
            assets.put(names.get(assetIndex), value);
        }
        return assets;
    }

    private static QnnAssetBundleInstaller.AssetSource source(Map<String, byte[]> assets) {
        return name -> {
            byte[] value = assets.get(name);
            if (value == null) throw new IOException("Missing test asset: " + name);
            return new ByteArrayInputStream(value);
        };
    }

    private static void verifyFiles(File directory, Map<String, byte[]> assets) throws IOException {
        for (String name : assets.keySet()) {
            require(java.util.Arrays.equals(
                    assets.get(name), Files.readAllBytes(new File(directory, name).toPath())));
        }
        require(new File(directory, QnnAssetBundleInstaller.COMPLETION_MARKER).isFile());
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
        if (!condition) throw new AssertionError("QNN asset bundle installer contract failed");
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
            if (offset >= failureOffset) throw new IOException("synthetic interrupted copy");
            return value[offset++] & 0xff;
        }

        @Override
        public int read(byte[] buffer, int start, int length) throws IOException {
            if (offset >= failureOffset) throw new IOException("synthetic interrupted copy");
            int count = Math.min(length, Math.min(failureOffset - offset, value.length - offset));
            if (count <= 0) return -1;
            System.arraycopy(value, offset, buffer, start, count);
            offset += count;
            return count;
        }
    }
}
