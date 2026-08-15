package com.visionforge.inferencebenchmark;

/** Ensures internal QNN closure details do not leak into the product message. */
final class MobileRuntimeFailureMessagePolicySelfTest {
    private MobileRuntimeFailureMessagePolicySelfTest() {}

    static void run() {
        require(MobileRuntimeFailureMessagePolicy.classify(
                "qnn_htp_architecture_not_packaged")
                == MobileRuntimeFailureMessagePolicy.Kind
                .QNN_HTP_ARCHITECTURE_NOT_PACKAGED);
        require(MobileRuntimeFailureMessagePolicy.classify(
                "detail contains qnn_htp_architecture_not_packaged but code differs")
                == MobileRuntimeFailureMessagePolicy.Kind.GENERIC);
        require(MobileRuntimeFailureMessagePolicy.classify(
                "portable_model_unavailable")
                == MobileRuntimeFailureMessagePolicy.Kind.GENERIC);
        require(MobileRuntimeFailureMessagePolicy.classify(null)
                == MobileRuntimeFailureMessagePolicy.Kind.GENERIC);
    }

    private static void require(boolean condition) {
        if (!condition) {
            throw new AssertionError("Mobile runtime failure message policy failed");
        }
    }
}
