package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Dependency-free contract for the bounded external health snapshot. */
final class MobileExternalHealthSnapshotWriterSelfTest {
    private MobileExternalHealthSnapshotWriterSelfTest() {}

    static void run() throws Exception {
        require(!new MobileExternalHealthSnapshotWriter(null).overwrite("unavailable\n"));
        Path externalRoot = Files.createTempDirectory("vf-mobile-health-");
        Path diagnostics = externalRoot.resolve("diagnostics");
        Path snapshot = diagnostics.resolve(
                MobileExternalHealthSnapshotWriter.SNAPSHOT_FILE_NAME);
        Path temporary = diagnostics.resolve(
                MobileExternalHealthSnapshotWriter.SNAPSHOT_FILE_NAME + ".tmp");
        try {
            MobileExternalHealthSnapshotWriter writer =
                    new MobileExternalHealthSnapshotWriter(externalRoot.toFile());
            require(writer.overwrite("sample=first\n"));
            require("sample=first\n".equals(new String(
                    Files.readAllBytes(snapshot), StandardCharsets.UTF_8)));
            require(writer.overwrite("sample=second\n"));
            require("sample=second\n".equals(new String(
                    Files.readAllBytes(snapshot), StandardCharsets.UTF_8)));
            require(!Files.exists(temporary));
        } finally {
            Files.deleteIfExists(temporary);
            Files.deleteIfExists(snapshot);
            Files.deleteIfExists(diagnostics);
            Files.deleteIfExists(externalRoot);
        }
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("mobile external health snapshot contract failed");
        }
    }
}
