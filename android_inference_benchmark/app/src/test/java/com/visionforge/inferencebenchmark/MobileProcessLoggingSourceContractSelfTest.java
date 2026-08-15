package com.visionforge.inferencebenchmark;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Source contract for append-only logging and process-level crash capture. */
public final class MobileProcessLoggingSourceContractSelfTest {
    private static final String PROJECT_DIRECTORY_PROPERTY =
            "visionforge.android.project.dir";

    private MobileProcessLoggingSourceContractSelfTest() {
    }

    public static void main(String[] arguments) throws Exception {
        run();
        System.out.println("MOBILE_PROCESS_LOGGING_SOURCE_CONTRACT_OK");
    }

    static void run() throws Exception {
        Path project = Paths.get(System.getProperty(
                PROJECT_DIRECTORY_PROPERTY, ".")).toAbsolutePath().normalize();
        String logger = read(project,
                "src/main/java/com/visionforge/inferencebenchmark/MobileEventLogger.java");
        String application = read(project,
                "src/main/java/com/visionforge/inferencebenchmark/"
                        + "VisionForgeApplication.java");
        String manifest = read(project, "src/main/AndroidManifest.xml");

        verifySingleAppendOnlyFile(logger);
        verifyCentralSanitization(logger);
        verifyProcessCrashLifecycle(application, manifest);
    }

    private static void verifySingleAppendOnlyFile(String logger) {
        require(logger.contains(
                "EVENT_FILE_NAME = \"visionforge-mobile-runtime.jsonl\""));
        require(logger.contains("new FileOutputStream(eventFile, true)"));
        require(logger.contains("stream.getFD().sync()"));
        require(!logger.contains("renameTo("));
        require(!logger.contains(".delete("));
        require(!logger.contains("listFiles("));
        require(!logger.contains("MAX_FILE"));
        require(!logger.toLowerCase().contains("rotate"));
        require(logger.contains("long exportTo(OutputStream output)"));
        require(logger.contains("snapshotLength = eventFile.exists()"));
        require(logger.contains("copied < snapshotLength"));
    }

    private static void verifyCentralSanitization(String logger) {
        String compactLogger = logger.replaceAll("\\s+", "");
        require(compactLogger.contains("MobileLogSanitizer.sanitize(event)"));
        require(compactLogger.contains("MobileLogSanitizer.sanitize(detail)"));
        require(compactLogger.contains(
                "MobileLogSanitizer.sanitize(Thread.currentThread().getName())"));
        int sanitization = logger.indexOf("String safeEvent =");
        int logcatWrite = logger.indexOf("Log.i(TAG, line.trim())");
        int fileWrite = logger.indexOf("new FileOutputStream(eventFile, true)");
        require(sanitization >= 0 && logcatWrite > sanitization
                && fileWrite > logcatWrite);
    }

    private static void verifyProcessCrashLifecycle(
            String application, String manifest) {
        require(manifest.contains("android:name=\".VisionForgeApplication\""));
        require(application.contains(
                "public final class VisionForgeApplication extends Application"));
        require(application.contains("mobile_process_started"));
        require(application.contains("mobile_previous_abnormal_exit"));
        require(application.contains("mobile_process_uncaught_exception"));
        require(application.contains("Thread.setDefaultUncaughtExceptionHandler(handler)"));
        require(application.contains("pending_uncaught_exception"));
        require(application.contains(".putBoolean(PENDING_ABNORMAL_EXIT_KEY, true)"));
        require(application.contains(".remove(PENDING_ABNORMAL_EXIT_KEY)"));
        require(application.contains(".commit()"));
        require(application.contains("new AtomicBoolean()"));
        require(application.contains("compareAndSet(false, true)"));
        require(application.contains(
                "public synchronized void uncaughtException("));
        require(application.contains("previousHandler.uncaughtException(thread, failure)"));
        require(application.contains("terminateProcess();"));
        require(application.contains("catch (Throwable ignoredLoggingFailure)"));
        require(!application.contains(
                "Log.e(TAG, \"mobile uncaught exception log write failed\", "));
    }

    private static String read(Path project, String relativePath) throws Exception {
        return new String(
                Files.readAllBytes(project.resolve(relativePath)),
                StandardCharsets.UTF_8);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("mobile process logging source contract failed");
        }
    }
}
