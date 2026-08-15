package com.visionforge.inferencebenchmark;

import java.util.function.LongSupplier;

/** Keeps the readiness agent attached to exactly one selected transport endpoint. */
final class Cat6ReadyLifecycleCoordinator {
    private final Cat6ReadyAgentPort agent;
    private final LongSupplier monotonicClock;
    private final Cat6ReadyAgentRecoveryPolicy recovery =
            new Cat6ReadyAgentRecoveryPolicy();
    private long activeNetworkHandle;
    private String activeLocalIpv4 = "";
    private String activeHostIpv4 = "";
    private boolean running;
    private boolean nativeStateUntrusted;

    Cat6ReadyLifecycleCoordinator(Cat6ReadyAgentPort agent) {
        this(agent, System::nanoTime);
    }

    Cat6ReadyLifecycleCoordinator(
            Cat6ReadyAgentPort agent,
            LongSupplier monotonicClock) {
        if (agent == null) throw new IllegalArgumentException("agent");
        if (monotonicClock == null) {
            throw new IllegalArgumentException("monotonicClock");
        }
        this.agent = agent;
        this.monotonicClock = monotonicClock;
    }

    synchronized boolean update(MobileTransportEndpoint endpoint) {
        if (endpoint == null || endpoint.networkHandle <= 0L) {
            stop();
            return false;
        }
        long nowNanos = monotonicClock.getAsLong();
        boolean sameEndpoint = hasSameEndpoint(endpoint);
        if (!sameEndpoint) replaceEndpoint(endpoint, nowNanos);
        if (reconcileRunningState(nowNanos)) return true;
        if (!recovery.canAttempt(nowNanos)) return false;
        cleanupUntrustedNativeState(nowNanos);
        if (sameEndpoint && adoptExistingNativeState(nowNanos)) return true;
        return startAgent(endpoint, nowNanos);
    }

    private boolean hasSameEndpoint(MobileTransportEndpoint endpoint) {
        return activeNetworkHandle == endpoint.networkHandle
                && activeLocalIpv4.equals(endpoint.localIpv4)
                && activeHostIpv4.equals(endpoint.hostIpv4);
    }

    private void replaceEndpoint(
            MobileTransportEndpoint endpoint,
            long nowNanos) {
        try {
            stop();
        } catch (RuntimeException | LinkageError stopFailure) {
            setActiveEndpoint(endpoint);
            nativeStateUntrusted = true;
            recovery.recordFailure(nowNanos);
            throw stopFailure;
        }
        setActiveEndpoint(endpoint);
    }

    private boolean reconcileRunningState(long nowNanos) {
        if (!running) return false;
        if (observeNativeRunning(nowNanos)) {
            recovery.recordHealthyObservation();
            return true;
        }
        stopNativeAgentOrRecordFailure(nowNanos);
        recovery.recordFailure(nowNanos);
        return false;
    }

    private boolean observeNativeRunning(long nowNanos) {
        try {
            return agent.isRunning();
        } catch (RuntimeException | LinkageError observationFailure) {
            recordExceptionalAgentFailure(nowNanos, observationFailure);
            throw observationFailure;
        }
    }

    private void cleanupUntrustedNativeState(long nowNanos) {
        if (!nativeStateUntrusted) return;
        stopNativeAgentOrRecordFailure(nowNanos);
    }

    private boolean adoptExistingNativeState(long nowNanos) {
        if (!observeNativeRunning(nowNanos)) return false;
        running = true;
        recovery.recordHealthyObservation();
        return true;
    }

    private boolean startAgent(
            MobileTransportEndpoint endpoint,
            long nowNanos) {
        try {
            running = agent.start(endpoint);
        } catch (RuntimeException | LinkageError startFailure) {
            recordExceptionalAgentFailure(nowNanos, startFailure);
            throw startFailure;
        }
        if (running) return true;
        stopNativeAgentOrRecordFailure(nowNanos);
        recovery.recordFailure(nowNanos);
        return false;
    }

    private void stopNativeAgentOrRecordFailure(long nowNanos) {
        try {
            agent.stop();
            running = false;
            nativeStateUntrusted = false;
        } catch (RuntimeException | LinkageError stopFailure) {
            recordStopFailure(nowNanos);
            throw stopFailure;
        }
    }

    private void setActiveEndpoint(MobileTransportEndpoint endpoint) {
        activeNetworkHandle = endpoint.networkHandle;
        activeLocalIpv4 = endpoint.localIpv4;
        activeHostIpv4 = endpoint.hostIpv4;
    }

    private void recordExceptionalAgentFailure(
            long nowNanos,
            Throwable primaryFailure) {
        running = false;
        nativeStateUntrusted = false;
        try {
            agent.stop();
        } catch (RuntimeException | LinkageError stopFailure) {
            nativeStateUntrusted = true;
            if (stopFailure != primaryFailure) {
                primaryFailure.addSuppressed(stopFailure);
            }
        }
        recovery.recordFailure(nowNanos);
    }

    private void recordStopFailure(long nowNanos) {
        running = false;
        nativeStateUntrusted = true;
        recovery.recordFailure(nowNanos);
    }

    synchronized void stop() {
        try {
            if (running) {
                agent.stop();
                return;
            }
            final boolean nativeRunning;
            try {
                nativeRunning = agent.isRunning();
            } catch (RuntimeException | LinkageError observationFailure) {
                stopAfterObservationFailure(observationFailure);
                throw observationFailure;
            }
            if (nativeRunning) agent.stop();
        } finally {
            clearCachedState();
        }
    }

    private void stopAfterObservationFailure(Throwable observationFailure) {
        try {
            agent.stop();
        } catch (RuntimeException | LinkageError stopFailure) {
            if (stopFailure != observationFailure) {
                observationFailure.addSuppressed(stopFailure);
            }
        }
    }

    private void clearCachedState() {
        running = false;
        nativeStateUntrusted = false;
        activeNetworkHandle = 0L;
        activeLocalIpv4 = "";
        activeHostIpv4 = "";
        recovery.reset();
    }

    synchronized boolean isRunning() {
        if (!running) return false;
        long nowNanos = monotonicClock.getAsLong();
        final boolean observedRunning;
        observedRunning = observeNativeRunning(nowNanos);
        if (observedRunning) {
            recovery.recordHealthyObservation();
            return true;
        }
        stopNativeAgentOrRecordFailure(nowNanos);
        recovery.recordFailure(nowNanos);
        return false;
    }

    synchronized String report() {
        return agent.report()
                + " java_recovery_failures="
                + recovery.consecutiveFailures();
    }
}
