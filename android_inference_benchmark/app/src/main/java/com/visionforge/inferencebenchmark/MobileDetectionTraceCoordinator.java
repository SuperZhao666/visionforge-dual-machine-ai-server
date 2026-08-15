package com.visionforge.inferencebenchmark;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Coordinates explicit, bounded, offline dataset evidence collection.
 *
 * <p>The production control path cannot start this collection and collection
 * never changes MAKCU output state.  A trace is useful only when paired with
 * the deterministic desktop H.264 replayer and its source label manifest.</p>
 */
final class MobileDetectionTraceCoordinator {
    static final String TRACE_FILE_NAME = "qnn-detection-trace.csv";
    static final int MAXIMUM_TRACE_FRAMES = 500;

    private final NativeDetectionTracePort tracePort;
    private final MobileRuntimeEventSink events;
    private final File diagnosticsDirectory;

    MobileDetectionTraceCoordinator(NativeDetectionTracePort tracePort,
                                   MobileRuntimeEventSink events,
                                   File diagnosticsDirectory) {
        this.tracePort = tracePort;
        this.events = events;
        this.diagnosticsDirectory = diagnosticsDirectory;
    }

    Result begin(int maximumFrames) {
        if (maximumFrames <= 0 || maximumFrames > MAXIMUM_TRACE_FRAMES) {
            events.write("mobile_detection_trace_rejected", "maximum_frames=" + maximumFrames);
            return Result.failure("trace frame count must be 1-" + MAXIMUM_TRACE_FRAMES);
        }
        tracePort.begin(maximumFrames);
        events.write("mobile_detection_trace_started", "maximum_frames=" + maximumFrames + " control_output_unchanged");
        return Result.success("trace armed for " + maximumFrames + " frames");
    }

    Result export() {
        final String csv = tracePort.exportCsv();
        if (!isTraceCsv(csv)) {
            events.write("mobile_detection_trace_export_rejected", "empty_or_invalid_native_trace");
            return Result.failure("native trace is empty");
        }
        if (!diagnosticsDirectory.exists() && !diagnosticsDirectory.mkdirs()) {
            events.write("mobile_detection_trace_export_failed", "diagnostics_directory_unavailable");
            return Result.failure("diagnostics directory unavailable");
        }
        final File destination = new File(diagnosticsDirectory, TRACE_FILE_NAME);
        final File temporary = new File(diagnosticsDirectory, TRACE_FILE_NAME + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(csv.getBytes(StandardCharsets.UTF_8));
        } catch (IOException exception) {
            events.write("mobile_detection_trace_export_failed", "write_failed=" + exception.getClass().getSimpleName());
            return Result.failure("trace write failed");
        }
        if (destination.exists() && !destination.delete()) {
            temporary.delete();
            events.write("mobile_detection_trace_export_failed", "replace_existing_failed");
            return Result.failure("existing trace cannot be replaced");
        }
        if (!temporary.renameTo(destination)) {
            temporary.delete();
            events.write("mobile_detection_trace_export_failed", "atomic_rename_failed");
            return Result.failure("trace rename failed");
        }
        final int dataRows = Math.max(0, csv.split("\\n").length - 1);
        events.write("mobile_detection_trace_exported", "rows=" + dataRows + " path=" + destination.getName());
        return Result.success(destination.getAbsolutePath());
    }

    private static boolean isTraceCsv(String csv) {
        return csv != null && csv.startsWith("frame_id,class_id,confidence,x1,y1,x2,y2\n")
                && csv.length() > "frame_id,class_id,confidence,x1,y1,x2,y2\n".length();
    }

    static final class Result {
        final boolean success;
        final String message;

        private Result(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        static Result success(String message) {
            return new Result(true, message);
        }

        static Result failure(String message) {
            return new Result(false, message);
        }
    }
}
