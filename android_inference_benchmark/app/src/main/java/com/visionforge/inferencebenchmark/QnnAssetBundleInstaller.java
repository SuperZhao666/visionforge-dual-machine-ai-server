package com.visionforge.inferencebenchmark;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Installs and verifies the complete QNN HTP skeleton bundle.
 *
 * <p>The installer is Android-framework independent so interruption,
 * corruption and concurrent callers can be exercised on the build host. A
 * completion marker is written only after every installed file is fsynced,
 * atomically renamed and SHA-256 verified against the packaged asset.</p>
 */
final class QnnAssetBundleInstaller {
    static final String DIRECTORY_NAME = "qnn";
    static final String BUNDLE_VERSION = "qairt-dynamic-htp-v3-sha256";
    static final String COMPLETION_MARKER = ".complete-v3";
    static final String DEFAULT_ARCHITECTURES = "v68,v69,v73,v75,v79";
    private static final Pattern ARCHITECTURE_TOKEN = Pattern.compile("v[0-9]{2,3}");
    private static final Pattern INSTALLED_SKELETON = Pattern.compile(
            "libQnnHtpV[0-9]{2,3}Skel\\.so");
    static final String[] ASSET_NAMES = assetNames(
            parseArchitectures(DEFAULT_ARCHITECTURES)).toArray(new String[0]);

    private static final Object INSTALL_LOCK = new Object();
    private static final int COPY_BUFFER_BYTES = 32 * 1024;
    private static final int MAX_ARCHITECTURES = 16;
    private static final int MAX_ARCHITECTURE_MANIFEST_CHARACTERS = 256;

    private QnnAssetBundleInstaller() {}

    @FunctionalInterface
    interface AssetSource {
        InputStream open(String name) throws IOException;
    }

    static Result ensureInstalled(File filesDirectory, AssetSource source) {
        return ensureInstalled(filesDirectory, source, DEFAULT_ARCHITECTURES);
    }

    static Result ensureInstalled(
            File filesDirectory,
            AssetSource source,
            String packagedArchitectures) {
        if (filesDirectory == null || source == null) {
            return Result.failure(null, "invalid_installer_argument",
                    Collections.emptyList(),
                    new IllegalArgumentException("filesDirectory and source are required"));
        }
        final List<String> architectures;
        try {
            architectures = parseArchitectures(packagedArchitectures);
        } catch (IllegalArgumentException invalid) {
            return Result.failure(null, "qnn_architecture_manifest_invalid",
                    Collections.emptyList(), invalid);
        }
        synchronized (INSTALL_LOCK) {
            return installLocked(filesDirectory, source, architectures);
        }
    }

    private static Result installLocked(
            File filesDirectory,
            AssetSource source,
            List<String> architectures) {
        long startedNanos = System.nanoTime();
        File directory = new File(filesDirectory, DIRECTORY_NAME);
        File marker = new File(directory, COMPLETION_MARKER);
        List<String> names = assetNames(architectures);
        try {
            if (!directory.isDirectory() && !directory.mkdirs()) {
                throw new IOException("Unable to create QNN directory: " + directory);
            }
            List<AssetDescriptor> descriptors = describeAssets(source, names);
            String markerContent = markerContent(descriptors);
            boolean markerCurrent = markerMatches(marker, markerContent);
            int removedStaleFiles = removeStaleSkeletons(
                    directory, names, marker);
            if (removedStaleFiles > 0) markerCurrent = false;
            int installedFiles = 0;
            for (AssetDescriptor descriptor : descriptors) {
                File destination = new File(directory, descriptor.name);
                if (!fileMatches(destination, descriptor)) {
                    Files.deleteIfExists(marker.toPath());
                    installAsset(directory, descriptor, source);
                    installedFiles++;
                }
            }
            if (!markerCurrent || installedFiles > 0) {
                writeAtomically(marker, markerContent.getBytes(StandardCharsets.UTF_8));
            }
            for (AssetDescriptor descriptor : descriptors) {
                if (!fileMatches(new File(directory, descriptor.name), descriptor)) {
                    throw new IOException("Post-install verification failed: " + descriptor.name);
                }
            }
            long elapsedMillis = (System.nanoTime() - startedNanos) / 1_000_000L;
            return Result.success(directory,
                    architectures,
                    "bundle_version=" + BUNDLE_VERSION
                            + " architectures=" + String.join(",", architectures)
                            + " installed_files=" + installedFiles
                            + " removed_stale_files=" + removedStaleFiles
                            + " verified_files=" + descriptors.size()
                            + " elapsed_ms=" + elapsedMillis);
        } catch (IOException | RuntimeException failure) {
            deleteQuietly(marker);
            cleanupTemporaryFiles(directory, names);
            return Result.failure(directory, "qnn_asset_bundle_install_failed",
                    architectures, failure);
        }
    }

    private static List<AssetDescriptor> describeAssets(
            AssetSource source,
            List<String> names) throws IOException {
        List<AssetDescriptor> descriptors = new ArrayList<>(names.size());
        byte[] buffer = new byte[COPY_BUFFER_BYTES];
        for (String name : names) {
            MessageDigest digest = sha256();
            long size = 0L;
            try (InputStream input = source.open(name)) {
                int read;
                while ((read = input.read(buffer)) != -1) {
                    requireNotInterrupted();
                    digest.update(buffer, 0, read);
                    size += read;
                }
            }
            if (size <= 0L) throw new IOException("Packaged QNN asset is empty: " + name);
            descriptors.add(new AssetDescriptor(name, size, toHex(digest.digest())));
        }
        return descriptors;
    }

    private static void installAsset(
            File directory, AssetDescriptor descriptor, AssetSource source) throws IOException {
        File destination = new File(directory, descriptor.name);
        File temporary = new File(directory, descriptor.name + ".part");
        Files.deleteIfExists(temporary.toPath());
        MessageDigest digest = sha256();
        long copied = 0L;
        try (InputStream input = source.open(descriptor.name);
             FileOutputStream output = new FileOutputStream(temporary)) {
            byte[] buffer = new byte[COPY_BUFFER_BYTES];
            int read;
            while ((read = input.read(buffer)) != -1) {
                requireNotInterrupted();
                output.write(buffer, 0, read);
                digest.update(buffer, 0, read);
                copied += read;
            }
            output.getFD().sync();
        } catch (IOException | RuntimeException failure) {
            deleteQuietly(temporary);
            throw failure;
        }
        if (copied != descriptor.size || !descriptor.sha256.equals(toHex(digest.digest()))) {
            deleteQuietly(temporary);
            throw new IOException("Packaged QNN asset changed while copying: " + descriptor.name);
        }
        moveAtomically(temporary, destination);
    }

    private static boolean fileMatches(File file, AssetDescriptor descriptor) throws IOException {
        if (!file.isFile() || file.length() != descriptor.size) return false;
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

    private static boolean markerMatches(File marker, String expected) throws IOException {
        if (!marker.isFile()) return false;
        return expected.equals(new String(
                Files.readAllBytes(marker.toPath()), StandardCharsets.UTF_8));
    }

    private static String markerContent(List<AssetDescriptor> descriptors) {
        StringBuilder value = new StringBuilder("version=").append(BUNDLE_VERSION).append('\n');
        for (AssetDescriptor descriptor : descriptors) {
            value.append("asset=").append(descriptor.name)
                    .append(" size=").append(descriptor.size)
                    .append(" sha256=").append(descriptor.sha256).append('\n');
        }
        return value.toString();
    }

    private static void writeAtomically(File destination, byte[] content) throws IOException {
        File temporary = new File(destination.getParentFile(), destination.getName() + ".part");
        Files.deleteIfExists(temporary.toPath());
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            output.write(content);
            output.getFD().sync();
        } catch (IOException failure) {
            deleteQuietly(temporary);
            throw failure;
        }
        moveAtomically(temporary, destination);
    }

    private static void moveAtomically(File source, File destination) throws IOException {
        try {
            Files.move(source.toPath(), destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(source.toPath(), destination.toPath(),
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
            throw new InterruptedIOException("QNN asset installation interrupted");
        }
    }

    private static String toHex(byte[] value) {
        char[] encoded = new char[value.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int index = 0; index < value.length; index++) {
            int current = value[index] & 0xff;
            encoded[index * 2] = alphabet[current >>> 4];
            encoded[index * 2 + 1] = alphabet[current & 0x0f];
        }
        return new String(encoded);
    }

    private static void cleanupTemporaryFiles(File directory, List<String> names) {
        if (directory == null || !directory.isDirectory()) return;
        for (String name : names) deleteQuietly(new File(directory, name + ".part"));
        deleteQuietly(new File(directory, COMPLETION_MARKER + ".part"));
    }

    static List<String> parseArchitectures(String configured) {
        if (configured == null
                || configured.length() > MAX_ARCHITECTURE_MANIFEST_CHARACTERS) {
            throw new IllegalArgumentException("QNN HTP architecture manifest is required");
        }
        LinkedHashSet<String> parsed = new LinkedHashSet<>();
        for (String value : configured.split("[,;]")) {
            String architecture = value.trim().toLowerCase(Locale.ROOT);
            if (architecture.isEmpty()) continue;
            if (!ARCHITECTURE_TOKEN.matcher(architecture).matches()
                    || !parsed.add(architecture)) {
                throw new IllegalArgumentException(
                        "Invalid or duplicate QNN HTP architecture: " + architecture);
            }
            if (parsed.size() > MAX_ARCHITECTURES) {
                throw new IllegalArgumentException(
                        "QNN HTP architecture manifest is too large");
            }
        }
        if (parsed.isEmpty()) {
            throw new IllegalArgumentException("QNN HTP architecture manifest is empty");
        }
        return Collections.unmodifiableList(new ArrayList<>(parsed));
    }

    static List<String> assetNames(List<String> architectures) {
        ArrayList<String> names = new ArrayList<>(architectures.size() + 1);
        names.add("libQnnHtp.so");
        for (String architecture : architectures) {
            names.add("libQnnHtp"
                    + architecture.toUpperCase(Locale.ROOT)
                    + "Skel.so");
        }
        return Collections.unmodifiableList(names);
    }

    private static int removeStaleSkeletons(
            File directory,
            List<String> expectedNames,
            File marker) throws IOException {
        File[] children = directory.listFiles();
        if (children == null) {
            throw new IOException("Unable to enumerate QNN runtime directory: " + directory);
        }
        int removed = 0;
        for (File child : children) {
            if (!INSTALLED_SKELETON.matcher(child.getName()).matches()
                    || expectedNames.contains(child.getName())) {
                continue;
            }
            Files.deleteIfExists(marker.toPath());
            Files.delete(child.toPath());
            removed++;
        }
        return removed;
    }

    private static void deleteQuietly(File file) {
        if (file == null) return;
        try {
            Files.deleteIfExists(file.toPath());
        } catch (IOException ignored) {
            // The primary failure is returned to the caller with its full stack.
        }
    }

    private static final class AssetDescriptor {
        final String name;
        final long size;
        final String sha256;

        AssetDescriptor(String name, long size, String sha256) {
            this.name = name;
            this.size = size;
            this.sha256 = sha256;
        }
    }

    static final class Result {
        final boolean ready;
        final File directory;
        final String detail;
        final List<String> architectures;
        final Throwable failure;

        private Result(
                boolean ready,
                File directory,
                String detail,
                List<String> architectures,
                Throwable failure) {
            this.ready = ready;
            this.directory = directory;
            this.detail = detail;
            this.architectures = Collections.unmodifiableList(
                    new ArrayList<>(architectures));
            this.failure = failure;
        }

        static Result success(
                File directory,
                List<String> architectures,
                String detail) {
            return new Result(true, directory, detail, architectures, null);
        }

        static Result failure(
                File directory,
                String detail,
                List<String> architectures,
                Throwable failure) {
            return new Result(false, directory, detail, architectures, failure);
        }
    }
}
