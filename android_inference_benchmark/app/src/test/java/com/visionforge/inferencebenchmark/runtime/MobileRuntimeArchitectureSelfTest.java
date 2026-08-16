package com.visionforge.inferencebenchmark.runtime;

/** Pure-JVM regression for the UI/Service architecture boundary. */
public final class MobileRuntimeArchitectureSelfTest {
    public static void main(String[] ignored) {
        commandProtocolFailsClosed();
        readModelStorePublishesImmutableValues();
    }

    private static void commandProtocolFailsClosed() {
        require(MobileRuntimeCommandProtocol.parse(null, true)
                == MobileRuntimeCommandProtocol.Command.ENSURE);
        require(MobileRuntimeCommandProtocol.parse(null, false)
                == MobileRuntimeCommandProtocol.Command.UNKNOWN);
        require(MobileRuntimeCommandProtocol.parse(
                MobileRuntimeCommandProtocol.ACTION_REFRESH_POWER_POLICY,
                true) == MobileRuntimeCommandProtocol.Command.REFRESH_POWER_POLICY);
        require(MobileRuntimeCommandProtocol.parse("typo", true)
                == MobileRuntimeCommandProtocol.Command.UNKNOWN);
    }

    private static void readModelStorePublishesImmutableValues() {
        MobileRuntimeReadModel status = new MobileRuntimeReadModel(
                MobileRuntimePhase.RUNNING, "healthy", "none", 7L);
        MobileRuntimeReadModelStore.publish(status);
        MobileRuntimeReadModelStore.publishEthernetDiagnostics("accepted=true");
        require(MobileRuntimeReadModelStore.snapshot() == status);
        require(MobileRuntimeReadModelStore.snapshot().phase
                == MobileRuntimePhase.RUNNING);
        require("accepted=true".equals(
                MobileRuntimeReadModelStore.ethernetDiagnostics()));
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("mobile runtime architecture failed");
    }
}
