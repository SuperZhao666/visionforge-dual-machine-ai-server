package com.visionforge.inferencebenchmark;

/** Maps stable runtime failure codes to bounded user-facing message kinds. */
final class MobileRuntimeFailureMessagePolicy {
    enum Kind {
        GENERIC,
        QNN_HTP_ARCHITECTURE_NOT_PACKAGED
    }

    private MobileRuntimeFailureMessagePolicy() {}

    static Kind classify(String failureCode) {
        return "qnn_htp_architecture_not_packaged".equals(failureCode)
                ? Kind.QNN_HTP_ARCHITECTURE_NOT_PACKAGED
                : Kind.GENERIC;
    }
}
