package com.visionforge.inferencebenchmark;

/** Maps authenticated sidecar error codes to safe, actionable UI guidance. */
final class AuthorizationFailureMessagePolicy {
    enum Message {
        GENERIC,
        DEVICE_REBIND_REQUIRED,
        DEVICE_BINDING_INCONSISTENT
    }

    private AuthorizationFailureMessagePolicy() {
    }

    static Message forSafeErrorCode(String safeErrorCode) {
        if ("license_bound_to_another_device".equals(safeErrorCode)) {
            return Message.DEVICE_REBIND_REQUIRED;
        }
        if ("license_device_binding_inconsistent".equals(safeErrorCode)) {
            return Message.DEVICE_BINDING_INCONSISTENT;
        }
        return Message.GENERIC;
    }
}
