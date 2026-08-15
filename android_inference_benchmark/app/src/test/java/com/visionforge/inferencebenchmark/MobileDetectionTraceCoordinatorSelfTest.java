package com.visionforge.inferencebenchmark;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** Dependency-free regression coverage for bounded offline trace ownership. */
final class MobileDetectionTraceCoordinatorSelfTest {
    static void run() {
        try {
            File directory = Files.createTempDirectory("visionforge-detection-trace").toFile();
            FakeTracePort port = new FakeTracePort();
            List<String> events = new ArrayList<>();
            MobileDetectionTraceCoordinator coordinator = new MobileDetectionTraceCoordinator(
                    port, (event, detail) -> events.add(event + ":" + detail), directory);
            require(!coordinator.begin(0).success);
            require(!coordinator.begin(501).success);
            require(coordinator.begin(3).success && port.maximumFrames == 3);
            require(coordinator.export().success);
            File trace = new File(directory, MobileDetectionTraceCoordinator.TRACE_FILE_NAME);
            require(trace.isFile());
            String text = new String(Files.readAllBytes(trace.toPath()), StandardCharsets.UTF_8);
            require(text.contains("1,0,0.9"));
            require(events.stream().anyMatch(value -> value.startsWith("mobile_detection_trace_exported:")));
            File[] files = directory.listFiles();
            if (files != null) for (File file : files) file.delete();
            directory.delete();
        } catch (Exception exception) {
            throw new AssertionError("Mobile detection trace coordinator contract failed", exception);
        }
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Mobile detection trace coordinator contract failed");
    }

    private static final class FakeTracePort implements NativeDetectionTracePort {
        int maximumFrames;

        @Override
        public void begin(int maximumFrames) {
            this.maximumFrames = maximumFrames;
        }

        @Override
        public String exportCsv() {
            return "frame_id,class_id,confidence,x1,y1,x2,y2\n1,0,0.9,1,2,3,4\n";
        }
    }
}
