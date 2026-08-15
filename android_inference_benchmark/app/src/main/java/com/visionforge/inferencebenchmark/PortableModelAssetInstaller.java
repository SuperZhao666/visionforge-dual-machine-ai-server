package com.visionforge.inferencebenchmark;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.regex.Pattern;

/** Atomically installs one hash-pinned ONNX model for the portable backend. */
final class PortableModelAssetInstaller {
    static final String DIRECTORY_NAME = "portable_models_v1";
    private static final Pattern ASSET_NAME = Pattern.compile(
            "[a-z0-9][a-z0-9._-]{0,126}\\.onnx");
    private static final Pattern SHA256 = Pattern.compile("[0-9A-F]{64}");
    private static final int COPY_BUFFER_BYTES = 64 * 1024;
    private static final Object INSTALL_LOCK = new Object();

    private PortableModelAssetInstaller() {}

    @FunctionalInterface
    interface AssetSource {
        InputStream open(String name) throws IOException;
    }

    static Result ensureInstalled(
            File filesDirectory,
            MobileModelCatalog.Profile model,
            AssetSource source) {
        if (model == null) {
            return Result.failure(
                    null,
                    "portable_model_profile_missing",
                    new IllegalArgumentException("model is required"));
        }
        return ensureInstalled(
                filesDirectory,
                new Descriptor(
                        model.portableModelAsset,
                        model.portableModelBytes,
                        model.portableModelSha256),
                source);
    }

    static Result ensureInstalled(
            File filesDirectory,
            Descriptor descriptor,
            AssetSource source) {
        if (filesDirectory == null || descriptor == null || source == null) {
            return Result.failure(
                    null,
                    "invalid_portable_model_installer_argument",
                    new IllegalArgumentException(
                            "filesDirectory, descriptor and source are required"));
        }
        synchronized (INSTALL_LOCK) {
            return installLocked(filesDirectory, descriptor, source);
        }
    }

    private static Result installLocked(
            File filesDirectory,
            Descriptor descriptor,
            AssetSource source) {
        long startedNanos = System.nanoTime();
        File directory = new File(filesDirectory, DIRECTORY_NAME);
        File destination = new File(directory, descriptor.assetName);
        File temporary = new File(directory, descriptor.assetName + ".part");
        try {
            if (!directory.isDirectory() && !directory.mkdirs()) {
                throw new IOException(
                        "Unable to create portable model directory: " + directory);
            }
            boolean installed = false;
            if (!fileMatches(destination, descriptor)) {
                Files.deleteIfExists(temporary.toPath());
                copyVerified(temporary, descriptor, source);
                moveAtomically(temporary, destination);
                installed = true;
            }
            if (!fileMatches(destination, descriptor)) {
                throw new IOException(
                        "Portable model post-install verification failed: "
                                + descriptor.assetName);
            }
            long elapsedMillis = (System.nanoTime() - startedNanos) / 1_000_000L;
            return Result.success(
                    destination,
                    "asset=" + descriptor.assetName
                            + " installed=" + installed
                            + " bytes=" + descriptor.expectedBytes
                            + " sha256=" + descriptor.sha256
                            + " elapsed_ms=" + elapsedMillis);
        } catch (IOException | RuntimeException failure) {
            deleteQuietly(temporary);
            return Result.failure(
                    destination,
                    "portable_model_install_failed asset=" + descriptor.assetName,
                    failure);
        }
    }

    private static void copyVerified(
            File temporary,
            Descriptor descriptor,
            AssetSource source) throws IOException {
        MessageDigest digest = sha256();
        long copied = 0L;
        try (InputStream input = source.open(descriptor.assetName);
             FileOutputStream output = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[COPY_BUFFER_BYTES];
            int read;
            while ((read = input.read(buffer)) != -1) {
                requireNotInterrupted();
                output.write(buffer, 0, read);
                digest.update(buffer, 0, read);
                copied += read;
                if (copied > descriptor.expectedBytes) {
                    throw new IOException("Portable model asset exceeds expected size");
                }
            }
            output.getFD().sync();
        } catch (IOException | RuntimeException failure) {
            deleteQuietly(temporary);
            throw failure;
        }
        String actualSha256 = toHex(digest.digest());
        if (copied != descriptor.expectedBytes
                || !descriptor.sha256.equals(actualSha256)) {
            deleteQuietly(temporary);
            throw new IOException(
                    "Portable model asset integrity mismatch: "
                            + descriptor.assetName);
        }
    }

    private static boolean fileMatches(
            File file,
            Descriptor descriptor) throws IOException {
        if (!file.isFile() || file.length() != descriptor.expectedBytes) {
            return false;
        }
        MessageDigest digest = sha256();
        byte[] buffer = new byte[COPY_BUFFER_BYTES];
        try (InputStream input = new FileInputStream(file)) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                requireNotInterrupted();
                digest.update(buffer, 0, read);
            }
        }
        return descriptor.sha256.equals(toHex(digest.digest()));
    }

    private static void moveAtomically(File source, File destination)
            throws IOException {
        try {
            Files.move(
                    source.toPath(),
                    destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(
                    source.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void requireNotInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException(
                    "Portable model installation interrupted");
        }
    }

    private static String toHex(byte[] value) {
        char[] encoded = new char[value.length * 2];
        char[] alphabet = "0123456789ABCDEF".toCharArray();
        for (int index = 0; index < value.length; index++) {
            int current = value[index] & 0xff;
            encoded[index * 2] = alphabet[current >>> 4];
            encoded[index * 2 + 1] = alphabet[current & 0x0f];
        }
        return new String(encoded);
    }

    private static void deleteQuietly(File file) {
        if (file == null) return;
        try {
            Files.deleteIfExists(file.toPath());
        } catch (IOException ignored) {
            // The primary failure is returned with its original stack.
        }
    }

    static final class Descriptor {
        final String assetName;
        final long expectedBytes;
        final String sha256;

        Descriptor(String assetName, long expectedBytes, String sha256) {
            String canonicalSha256 = sha256 == null
                    ? "" : sha256.trim().toUpperCase(Locale.ROOT);
            if (assetName == null || !ASSET_NAME.matcher(assetName).matches()
                    || expectedBytes <= 0L
                    || !SHA256.matcher(canonicalSha256).matches()) {
                throw new IllegalArgumentException(
                        "invalid portable model descriptor");
            }
            this.assetName = assetName;
            this.expectedBytes = expectedBytes;
            this.sha256 = canonicalSha256;
        }
    }

    static final class Result {
        final boolean ready;
        final File modelFile;
        final String detail;
        final Throwable failure;

        private Result(
                boolean ready,
                File modelFile,
                String detail,
                Throwable failure) {
            this.ready = ready;
            this.modelFile = modelFile;
            this.detail = detail;
            this.failure = failure;
        }

        static Result success(File modelFile, String detail) {
            return new Result(true, modelFile, detail, null);
        }

        static Result failure(
                File modelFile,
                String detail,
                Throwable failure) {
            return new Result(false, modelFile, detail, failure);
        }
    }
}
