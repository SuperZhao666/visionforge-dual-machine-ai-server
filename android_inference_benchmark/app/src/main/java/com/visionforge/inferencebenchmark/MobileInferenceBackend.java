package com.visionforge.inferencebenchmark;

import java.util.Locale;

/** Explicit native inference implementations available to the mobile runtime. */
enum MobileInferenceBackend {
    QNN_HTP("qnn_htp", true, false),
    ONNXRUNTIME_NNAPI("onnxruntime_nnapi", false, true),
    ONNXRUNTIME_CPU("onnxruntime_cpu", false, true);

    final String token;
    final boolean requiresQnnRuntime;
    final boolean requiresPortableModel;

    MobileInferenceBackend(
            String token,
            boolean requiresQnnRuntime,
            boolean requiresPortableModel) {
        this.token = token;
        this.requiresQnnRuntime = requiresQnnRuntime;
        this.requiresPortableModel = requiresPortableModel;
    }

    static MobileInferenceBackend forToken(String token) {
        if (token != null) {
            for (MobileInferenceBackend backend : values()) {
                if (backend.token.equals(token.toLowerCase(Locale.ROOT))) {
                    return backend;
                }
            }
        }
        throw new IllegalArgumentException("unsupported mobile inference backend");
    }
}
