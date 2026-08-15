package com.visionforge.inferencebenchmark;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Overwrites one ADB-readable health snapshot outside the frame hot path. */
final class MobileExternalHealthSnapshotWriter {
    static final String SNAPSHOT_FILE_NAME = "mobile-runtime-latest.txt";
    private static final String DIAGNOSTICS_DIRECTORY_NAME = "diagnostics";
    private final File diagnosticsDirectory;

    MobileExternalHealthSnapshotWriter(File externalFilesDirectory) {
        diagnosticsDirectory = externalFilesDirectory == null
                ? null : new File(externalFilesDirectory, DIAGNOSTICS_DIRECTORY_NAME);
    }

    boolean overwrite(String payload) {
        if (diagnosticsDirectory == null || payload == null) return false;
        if (!diagnosticsDirectory.exists() && !diagnosticsDirectory.mkdirs()) return false;
        File destination = new File(diagnosticsDirectory, SNAPSHOT_FILE_NAME);
        File temporary = new File(diagnosticsDirectory, SNAPSHOT_FILE_NAME + ".tmp");
        try (FileOutputStream stream = new FileOutputStream(temporary, false)) {
            stream.write(payload.getBytes(StandardCharsets.UTF_8));
            stream.flush();
        } catch (IOException | SecurityException failure) {
            deleteTemporary(temporary);
            return false;
        }
        try {
            moveSnapshot(temporary, destination);
            return true;
        } catch (IOException | SecurityException failure) {
            deleteTemporary(temporary);
            return false;
        }
    }

    private static void moveSnapshot(File temporary, File destination)
            throws IOException {
        try {
            Files.move(
                    temporary.toPath(), destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException unsupported) {
            Files.move(
                    temporary.toPath(), destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteTemporary(File temporary) {
        try {
            Files.deleteIfExists(temporary.toPath());
        } catch (IOException | SecurityException ignored) {
            // A later overwrite truncates the same bounded temporary file.
        }
    }
}
