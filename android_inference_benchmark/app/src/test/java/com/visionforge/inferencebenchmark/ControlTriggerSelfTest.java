package com.visionforge.inferencebenchmark;

final class ControlTriggerSelfTest {
    static void run() {
        require(ControlTrigger.fromStorageToken(null) == ControlTrigger.SIDE_BUTTON_2);
        require(ControlTrigger.fromStorageToken("") == ControlTrigger.SIDE_BUTTON_2);
        require(ControlTrigger.fromStorageToken("corrupt") == ControlTrigger.SIDE_BUTTON_2);
        require(ControlTrigger.fromStorageToken("always") == ControlTrigger.ALWAYS);
        require(ControlTrigger.fromStorageToken("MOUSE4") == ControlTrigger.SIDE_BUTTON_1);
        require(ControlTrigger.fromStorageToken("mouse5") == ControlTrigger.SIDE_BUTTON_2);
        require(ControlTrigger.ALWAYS.isSatisfiedBy(0));
        ControlTrigger restoredAlways =
                ControlTrigger.fromPersistedStorageToken(
                        ControlTrigger.ALWAYS.storageToken);
        require(restoredAlways == ControlTrigger.ALWAYS);
        require(!restoredAlways.requiresButtonStream());
        require(restoredAlways.isSatisfiedBy(0));
        require(!ControlTrigger.persistedTokenNeedsMigration("always"));
        require(ControlTrigger.persistedTokenNeedsMigration(null));
        require(ControlTrigger.persistedTokenNeedsMigration("corrupt"));
        require(!ControlTrigger.persistedTokenNeedsMigration("mouse5"));
        require(ControlTrigger.fromPersistedStorageToken(null)
                == ControlTrigger.SIDE_BUTTON_2);
        require(ControlTrigger.fromPersistedStorageToken("corrupt")
                == ControlTrigger.SIDE_BUTTON_2);
        require(!ControlTrigger.RIGHT_MOUSE.isSatisfiedBy(0x01));
        require(ControlTrigger.RIGHT_MOUSE.isSatisfiedBy(0x02));
        require(ControlTrigger.SIDE_BUTTON_1.isSatisfiedBy(0x0a));
        require(ControlTrigger.SIDE_BUTTON_2.isSatisfiedBy(0x10));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Control trigger contract failed");
    }

    private ControlTriggerSelfTest() {
    }
}
