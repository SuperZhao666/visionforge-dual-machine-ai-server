package com.visionforge.inferencebenchmark.video;

public final class DecoderRestartCoordinatorSelfTest {
    public static void main(String[] ignored) {
        DecoderRestartCoordinator coordinator = new DecoderRestartCoordinator();
        DecoderRestartCoordinator.Request first = coordinator.request(10L);
        require(first.startNow && first.generation == 1L);
        DecoderRestartCoordinator.Request merged = coordinator.request(11L);
        require(!merged.startNow && merged.generation == first.generation);
        require(coordinator.complete(first.generation, true) == 11L);
        require(coordinator.complete(first.generation, true) == -1L);
        DecoderRestartCoordinator.Request second = coordinator.request(12L);
        require(second.startNow && second.generation == 2L);
    }

    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("decoder restart merge failed");
    }
}
