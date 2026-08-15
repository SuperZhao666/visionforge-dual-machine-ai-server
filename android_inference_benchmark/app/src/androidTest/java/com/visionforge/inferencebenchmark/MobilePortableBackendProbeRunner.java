package com.visionforge.inferencebenchmark;

import android.content.Context;
import android.os.Bundle;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/** Real-graph portable-backend probe used only by the official x86_64 emulator lane. */
final class MobilePortableBackendProbeRunner {
    private static final String ARG_BACKEND_TOKEN = "backendToken";
    private static final String ARG_ITERATIONS = "iterations";
    private static final String ARG_MODEL_TOKEN = "modelToken";
    private static final String ARG_ALLOW_PHYSICAL = "allowPhysical";
    private static final int DEFAULT_ITERATIONS = 1;
    private static final int MAX_ITERATIONS = 64;
    private static final String RESULT_PREFIX = "MOBILE_PORTABLE_BACKEND_PROBE";

    private MobilePortableBackendProbeRunner() {}

    static String run(Context context, Bundle arguments) throws IOException {
        if (context == null) {
            throw new IllegalStateException("target context is unavailable");
        }
        MobileSocCompatibilityPolicy.Result compatibility =
                MobileSocCompatibilityPolicy.evaluate(
                        AndroidDeviceProfileCollector.collectSocModel(),
                        AndroidDeviceProfileCollector.collectSocManufacturer(),
                        AndroidDeviceProfileCollector.collectSocHardwareEvidence());
        MobileInferenceBackendPolicy.Plan plan =
                MobileInferenceBackendPolicy.evaluate(compatibility);
        boolean physicalDiagnosticOverride = Boolean.parseBoolean(
                optionalArgument(arguments, ARG_ALLOW_PHYSICAL));
        if (!physicalDiagnosticOverride) {
            require(
                    compatibility.family
                            == MobileSocCompatibilityPolicy.Family.ANDROID_EMULATOR,
                    "probe requires the official Android emulator identity: "
                            + compatibility.detail());
            require(
                    plan.candidates.length == 1
                            && plan.candidates[0]
                            == MobileInferenceBackend.ONNXRUNTIME_CPU,
                    "emulator must route only to ONNX Runtime CPU: "
                            + plan.detail());
        } else {
            require(
                    compatibility.family
                            != MobileSocCompatibilityPolicy.Family.ANDROID_EMULATOR,
                    "physical diagnostic override requires a physical SoC identity");
        }
        MobileInferenceBackend probeBackend = probeBackend(arguments);
        int iterations = probeIterations(arguments);
        List<MobileModelCatalog.Profile> profiles = selectedProfiles(
                optionalArgument(arguments, ARG_MODEL_TOKEN));
        String nativeLibraryDirectory =
                context.getApplicationInfo().nativeLibraryDir;
        StringBuilder stream = startReport(
                compatibility,
                plan,
                probeBackend,
                nativeLibraryDirectory,
                profiles.size(),
                iterations,
                physicalDiagnosticOverride);
        int executionIndex = 0;
        for (int iteration = 1; iteration <= iterations; iteration++) {
            stream.append("iteration_start=").append(iteration).append('\n');
            for (MobileModelCatalog.Profile profile : profiles) {
                executionIndex++;
                runModelProbe(
                        context,
                        probeBackend,
                        nativeLibraryDirectory,
                        profile,
                        iteration,
                        executionIndex,
                        stream);
            }
            stream.append("iteration_complete=").append(iteration).append('\n');
        }
        return stream.append(RESULT_PREFIX).append("_OK models=")
                .append(profiles.size()).append(" iterations=")
                .append(iterations).append(" executions=")
                .append(executionIndex).append(" backend=")
                .append(probeBackend.token).append('\n').toString();
    }

    private static StringBuilder startReport(
            MobileSocCompatibilityPolicy.Result compatibility,
            MobileInferenceBackendPolicy.Plan plan,
            MobileInferenceBackend backend,
            String nativeLibraryDirectory,
            int modelCount,
            int iterations,
            boolean physicalDiagnosticOverride) {
        return new StringBuilder(RESULT_PREFIX)
                .append("_START\n")
                .append(compatibility.detail()).append('\n')
                .append(plan.detail()).append('\n')
                .append("probe_backend=").append(backend.token)
                .append(" diagnostic_override=")
                .append(backend == MobileInferenceBackend.ONNXRUNTIME_NNAPI)
                .append(" physical_diagnostic_override=")
                .append(physicalDiagnosticOverride)
                .append(" models=").append(modelCount)
                .append(" iterations=").append(iterations).append('\n')
                .append("native_library_directory=")
                .append(nativeLibraryDirectory).append('\n');
    }

    private static void runModelProbe(
            Context context,
            MobileInferenceBackend backend,
            String nativeLibraryDirectory,
            MobileModelCatalog.Profile profile,
            int iteration,
            int executionIndex,
            StringBuilder stream) throws IOException {
        PortableModelAssetInstaller.Result installed =
                PortableModelAssetInstaller.ensureInstalled(
                        context.getFilesDir(),
                        profile,
                        name -> openPortableModelAsset(context, name));
        require(
                installed.ready && installed.modelFile != null,
                "portable model install failed model=" + profile.token
                        + " detail={" + installed.detail + "}");
        String report;
        try {
            boolean prepared = QnnHtpBridge.prepareNativeInferenceRealtime(
                    backend.token,
                    nativeLibraryDirectory,
                    "",
                    installed.modelFile.getAbsolutePath(),
                    profile.token);
            report = QnnHtpBridge.getNativeQnnRealtimeReport();
            require(
                    prepared,
                    "portable real-graph preparation failed model="
                            + profile.token + " iteration=" + iteration
                            + " report={" + report + "}");
            requireReadinessEvidence(backend, profile, iteration, report);
        } finally {
            QnnHtpBridge.releaseNativeInferenceRealtime();
        }
        stream.append("execution=").append(executionIndex)
                .append(" iteration=").append(iteration)
                .append(" model=").append(profile.token)
                .append(" bytes=").append(installed.modelFile.length())
                .append(" sha256=").append(profile.portableModelSha256)
                .append(" result=real_graph_execution_success\n")
                .append(report).append('\n');
    }

    private static void requireReadinessEvidence(
            MobileInferenceBackend backend,
            MobileModelCatalog.Profile profile,
            int iteration,
            String report) {
        require(
                report.contains("ready=1")
                        && report.contains("backend_token=" + backend.token)
                        && report.contains("model=" + profile.token)
                        && report.contains("probe_execution=success")
                        && report.contains("outputs=FP32_split"),
                "portable readiness evidence incomplete model="
                        + profile.token + " iteration=" + iteration
                        + " report={" + report + "}");
    }

    private static List<MobileModelCatalog.Profile> selectedProfiles(
            String requestedToken) {
        List<MobileModelCatalog.Profile> selected = new ArrayList<>();
        for (MobileModelCatalog.Profile profile : MobileModelCatalog.ALL) {
            if (requestedToken == null || requestedToken.isBlank()
                    || profile.token.equals(requestedToken)) {
                selected.add(profile);
            }
        }
        require(!selected.isEmpty(), "unknown modelToken: " + requestedToken);
        return selected;
    }

    private static int probeIterations(Bundle arguments) {
        String requested = optionalArgument(arguments, ARG_ITERATIONS);
        if (requested == null || requested.isBlank()) {
            return DEFAULT_ITERATIONS;
        }
        final int parsed;
        try {
            parsed = Integer.parseInt(requested.trim());
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(
                    "iterations must be a decimal integer", invalid);
        }
        require(
                parsed >= 1 && parsed <= MAX_ITERATIONS,
                "iterations must be between 1 and " + MAX_ITERATIONS);
        return parsed;
    }

    private static MobileInferenceBackend probeBackend(Bundle arguments) {
        String requested = optionalArgument(arguments, ARG_BACKEND_TOKEN);
        if (requested == null || requested.isBlank()) {
            return MobileInferenceBackend.ONNXRUNTIME_CPU;
        }
        MobileInferenceBackend backend =
                MobileInferenceBackend.forToken(requested.trim());
        require(
                backend == MobileInferenceBackend.ONNXRUNTIME_NNAPI
                        || backend == MobileInferenceBackend.ONNXRUNTIME_CPU,
                "portable probe backend is unsupported: " + requested);
        return backend;
    }

    private static String optionalArgument(Bundle arguments, String name) {
        return arguments == null ? null : arguments.getString(name);
    }

    private static InputStream openPortableModelAsset(
            Context context,
            String name) throws IOException {
        return context.getAssets().open(
                "portable_models" + File.separator + name);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
