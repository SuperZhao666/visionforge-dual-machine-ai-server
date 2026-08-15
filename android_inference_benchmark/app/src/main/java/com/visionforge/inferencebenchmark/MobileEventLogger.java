package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/** Append-only, privacy-preserving local runtime event log for mobile diagnostics. */
final class MobileEventLogger implements MobileRuntimeEventSink {
    private static final String TAG = "VisionForgeMobile";
    private static final String DIAGNOSTICS_DIRECTORY_NAME = "diagnostics";
    private static final String EVENT_FILE_NAME = "visionforge-mobile-runtime.jsonl";
    private static final Object FILE_WRITE_LOCK = new Object();
    private static final String PROCESS_TRACE_ID = UUID.randomUUID().toString();
    private static final long PROCESS_START_ELAPSED_MILLIS = SystemClock.elapsedRealtime();
    private static final AtomicLong PROCESS_SEQUENCE = new AtomicLong();
    private final File eventFile;

    MobileEventLogger(Context context) {
        Context requiredContext = Objects.requireNonNull(context, "context");
        File directory = new File(
                Objects.requireNonNull(
                        requiredContext.getFilesDir(), "context.filesDir"),
                DIAGNOSTICS_DIRECTORY_NAME);
        if (!directory.exists() && !directory.mkdirs()) {
            Log.e(TAG, "mobile diagnostics directory unavailable path=" + directory);
        }
        eventFile = new File(directory, EVENT_FILE_NAME);
    }

    @Override
    public void write(String event, String detail) {
        String safeEvent = MobileLogSanitizer.sanitize(event);
        String safeDetail = MobileLogSanitizer.sanitize(detail);
        String safeThreadName = MobileLogSanitizer.sanitize(
                Thread.currentThread().getName());
        synchronized (FILE_WRITE_LOCK) {
            long timestampUnixMillis = System.currentTimeMillis();
            String line = "{\"timestamp_utc\":\"" + Instant.ofEpochMilli(
                    timestampUnixMillis) + "\",\"timestamp_unix_ms\":" + timestampUnixMillis
                    + ",\"elapsed_ms\":"
                    + (SystemClock.elapsedRealtime() - PROCESS_START_ELAPSED_MILLIS)
                    + ",\"trace_id\":\"" + PROCESS_TRACE_ID + "\",\"sequence\":"
                    + PROCESS_SEQUENCE.incrementAndGet()
                    + ",\"process_id\":" + Process.myPid()
                    + ",\"thread_name\":\"" + escape(safeThreadName) + "\""
                    + ",\"event\":\"" + escape(safeEvent) + "\",\"detail\":\""
                    + escape(safeDetail) + "\"}\n";
            Log.i(TAG, line.trim());
            byte[] encodedLine = line.getBytes(StandardCharsets.UTF_8);
            try (FileOutputStream stream = new FileOutputStream(eventFile, true)) {
                stream.write(encodedLine);
                stream.getFD().sync();
            } catch (IOException exception) {
                Log.e(TAG, "mobile event log write failed path=" + eventFile, exception);
            }
        }
    }

    long exportTo(OutputStream output) throws IOException {
        Objects.requireNonNull(output, "output");
        final long snapshotLength;
        synchronized (FILE_WRITE_LOCK) {
            snapshotLength = eventFile.exists() ? eventFile.length() : 0L;
        }
        long copied = 0L;
        byte[] buffer = new byte[16 * 1024];
        try (FileInputStream input = new FileInputStream(eventFile)) {
            while (copied < snapshotLength) {
                int requested = (int) Math.min(
                        buffer.length, snapshotLength - copied);
                int read = input.read(buffer, 0, requested);
                if (read < 0) break;
                output.write(buffer, 0, read);
                copied += read;
            }
        }
        output.flush();
        return copied;
    }

    private static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                    break;
            }
        }
        return escaped.toString();
    }
}
