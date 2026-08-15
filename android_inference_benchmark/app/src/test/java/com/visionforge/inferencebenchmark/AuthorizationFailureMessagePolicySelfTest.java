package com.visionforge.inferencebenchmark;

final class AuthorizationFailureMessagePolicySelfTest {
    private AuthorizationFailureMessagePolicySelfTest() {
    }

    static void run() {
        check(AuthorizationFailureMessagePolicy.forSafeErrorCode(
                "license_bound_to_another_device")
                == AuthorizationFailureMessagePolicy.Message.DEVICE_REBIND_REQUIRED);
        check(AuthorizationFailureMessagePolicy.forSafeErrorCode(
                "license_device_binding_inconsistent")
                == AuthorizationFailureMessagePolicy.Message.DEVICE_BINDING_INCONSISTENT);
        check(AuthorizationFailureMessagePolicy.forSafeErrorCode("")
                == AuthorizationFailureMessagePolicy.Message.GENERIC);
        check(AuthorizationFailureMessagePolicy.forSafeErrorCode(null)
                == AuthorizationFailureMessagePolicy.Message.GENERIC);
    }

    private static void check(boolean condition) {
        if (!condition) {
            throw new AssertionError("authorization failure message policy failed");
        }
    }
}
