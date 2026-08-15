package com.visionforge.inferencebenchmark;

public final class Cat6ReadyLifecycleCoordinatorSelfTest {
    public static void main(String[] arguments) {
        Cat6ReadyAgentRecoveryPolicySelfTest.run();
        FakeAgent agent = new FakeAgent();
        ManualClock clock = new ManualClock();
        Cat6ReadyLifecycleCoordinator lifecycle =
                new Cat6ReadyLifecycleCoordinator(agent, clock::now);

        require(!lifecycle.update(null) && agent.calls.isEmpty(), "reject missing Ethernet");
        require(lifecycle.update(endpoint(57L)) && lifecycle.isRunning(), "start on fixed Ethernet");
        require("start:57:10.57.23.2:10.57.23.1".equals(agent.calls), "single start");
        require(("fake-ready-report java_recovery_failures=0")
                .equals(lifecycle.report()), "native report passthrough");
        require(lifecycle.update(endpoint(57L))
                && "start:57:10.57.23.2:10.57.23.1".equals(agent.calls), "idempotent update");
        require(lifecycle.update(endpoint(58L)), "restart on replacement Ethernet handle");
        require(("start:57:10.57.23.2:10.57.23.1,stop,"
                + "start:58:10.57.23.2:10.57.23.1").equals(agent.calls), "replacement ordering");
        require(!lifecycle.update(null) && !lifecycle.isRunning(), "stop on Ethernet loss");
        require(("start:57:10.57.23.2:10.57.23.1,stop,"
                + "start:58:10.57.23.2:10.57.23.1,stop").equals(agent.calls), "loss stop");
        require(lifecycle.update(endpoint(59L)), "restart after Ethernet recovery");
        lifecycle.stop();
        lifecycle.stop();
        require(("start:57:10.57.23.2:10.57.23.1,stop,"
                + "start:58:10.57.23.2:10.57.23.1,stop,"
                + "start:59:10.57.23.2:10.57.23.1,stop").equals(agent.calls),
                "explicit stop is idempotent");

        FakeAgent failingAgent = new FakeAgent();
        failingAgent.startResult = false;
        ManualClock failingClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator failing =
                new Cat6ReadyLifecycleCoordinator(
                        failingAgent, failingClock::now);
        require(!failing.update(endpoint(60L)) && !failing.isRunning(),
                "native start failure remains stopped");
        require(!failing.update(endpoint(60L))
                        && ("start:60:10.57.23.2:10.57.23.1,stop")
                        .equals(failingAgent.calls),
                "failed start is cleaned and same-endpoint retry observes backoff");
        failingClock.advance(999_999_999L);
        require(!failing.update(endpoint(60L))
                        && ("start:60:10.57.23.2:10.57.23.1,stop")
                        .equals(failingAgent.calls),
                "retry stays closed immediately before deadline");
        failingClock.advance(1L);
        failingAgent.startResult = true;
        require(failing.update(endpoint(60L)),
                "failed Ready agent retries at due boundary");

        FakeAgent partialStartAgent = new FakeAgent();
        partialStartAgent.startResult = false;
        partialStartAgent.partialStartOnFailure = true;
        Cat6ReadyLifecycleCoordinator partialStart =
                new Cat6ReadyLifecycleCoordinator(partialStartAgent);
        require(!partialStart.update(endpoint(63L)),
                "partial-start fixture returns failure");
        require(("start:63:10.57.23.2:10.57.23.1,stop")
                        .equals(partialStartAgent.calls),
                "failed start immediately closes its partial native worker");
        require(!partialStartAgent.running,
                "partial native worker is closed before update returns");

        FakeAgent throwingStartAgent = new FakeAgent();
        ManualClock throwingStartClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator throwingStart =
                new Cat6ReadyLifecycleCoordinator(
                        throwingStartAgent, throwingStartClock::now);
        IllegalStateException startFailure =
                new IllegalStateException("native start exception");
        throwingStartAgent.startFailure = startFailure;
        try {
            throwingStart.update(endpoint(67L));
            throw new AssertionError("native start exception must be preserved");
        } catch (IllegalStateException expected) {
            require(expected == startFailure,
                    "start exception identity is preserved");
        }
        require(throwingStartAgent.calls.endsWith(",stop"),
                "exceptional start attempts native cleanup");
        require(throwingStart.report().endsWith(
                        "java_recovery_failures=1"),
                "exceptional start increments observable recovery state");
        throwingStartAgent.startFailure = null;
        require(!throwingStart.update(endpoint(67L)),
                "exceptional start enters recovery backoff");
        throwingStartClock.advance(1_000_000_000L);
        require(throwingStart.update(endpoint(67L)),
                "exceptional start retries only at the due boundary");

        FakeAgent healthObservationAgent = new FakeAgent();
        ManualClock healthObservationClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator healthObservationLifecycle =
                new Cat6ReadyLifecycleCoordinator(
                        healthObservationAgent, healthObservationClock::now);
        require(healthObservationLifecycle.update(endpoint(68L)),
                "health-observation fixture starts");
        IllegalStateException healthObservationFailure =
                new IllegalStateException("native health exception");
        healthObservationAgent.isRunningFailure = healthObservationFailure;
        try {
            healthObservationLifecycle.isRunning();
            throw new AssertionError("native health exception must be preserved");
        } catch (IllegalStateException expected) {
            require(expected == healthObservationFailure,
                    "health exception identity is preserved");
        }
        healthObservationAgent.isRunningFailure = null;
        require(!healthObservationLifecycle.update(endpoint(68L)),
                "health observation exception enters recovery backoff");
        healthObservationClock.advance(1_000_000_000L);
        require(healthObservationLifecycle.update(endpoint(68L)),
                "health observation exception retries at the due boundary");

        FakeAgent workerStopFailureAgent = new FakeAgent();
        ManualClock workerStopFailureClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator workerStopFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(
                        workerStopFailureAgent, workerStopFailureClock::now);
        require(workerStopFailureLifecycle.update(endpoint(69L)),
                "worker-stop-failure fixture starts");
        workerStopFailureAgent.simulateWorkerFailure();
        UnsatisfiedLinkError workerStopFailure =
                new UnsatisfiedLinkError("failed worker cleanup");
        workerStopFailureAgent.stopFailure = workerStopFailure;
        try {
            workerStopFailureLifecycle.isRunning();
            throw new AssertionError("worker cleanup failure must be preserved");
        } catch (UnsatisfiedLinkError expected) {
            require(expected == workerStopFailure,
                    "worker cleanup failure identity is preserved");
        }
        workerStopFailureAgent.stopFailure = null;
        require(!workerStopFailureLifecycle.update(endpoint(69L)),
                "worker cleanup failure enters recovery backoff");
        workerStopFailureClock.advance(1_000_000_000L);
        require(workerStopFailureLifecycle.update(endpoint(69L)),
                "untrusted native state is cleaned before the due retry");

        FakeAgent combinedStartFailureAgent = new FakeAgent();
        ManualClock combinedStartFailureClock = new ManualClock();
        IllegalStateException combinedStartFailure =
                new IllegalStateException("combined start failure");
        UnsatisfiedLinkError combinedStartCleanupFailure =
                new UnsatisfiedLinkError("combined start cleanup failure");
        combinedStartFailureAgent.startFailure = combinedStartFailure;
        combinedStartFailureAgent.stopFailure = combinedStartCleanupFailure;
        Cat6ReadyLifecycleCoordinator combinedStartFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(
                        combinedStartFailureAgent,
                        combinedStartFailureClock::now);
        try {
            combinedStartFailureLifecycle.update(endpoint(70L));
            throw new AssertionError("combined start failure must be preserved");
        } catch (IllegalStateException expected) {
            require(expected == combinedStartFailure,
                    "start remains the primary exceptional failure");
            require(expected.getSuppressed().length == 1
                            && expected.getSuppressed()[0]
                            == combinedStartCleanupFailure,
                    "failed exceptional-start cleanup is retained");
        }
        combinedStartFailureAgent.startFailure = null;
        combinedStartFailureAgent.stopFailure = null;
        require(!combinedStartFailureLifecycle.update(endpoint(70L)),
                "combined start failure observes backoff");
        combinedStartFailureClock.advance(1_000_000_000L);
        require(combinedStartFailureLifecycle.update(endpoint(70L)),
                "combined start failure cleans untrusted state before retry");

        FakeAgent replacementStopFailureAgent = new FakeAgent();
        ManualClock replacementStopFailureClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator replacementStopFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(
                        replacementStopFailureAgent,
                        replacementStopFailureClock::now);
        require(replacementStopFailureLifecycle.update(endpoint(71L)),
                "replacement-stop-failure fixture starts");
        UnsatisfiedLinkError replacementStopFailure =
                new UnsatisfiedLinkError("replacement stop failure");
        replacementStopFailureAgent.stopFailure = replacementStopFailure;
        try {
            replacementStopFailureLifecycle.update(endpoint(72L));
            throw new AssertionError("replacement stop failure must be preserved");
        } catch (UnsatisfiedLinkError expected) {
            require(expected == replacementStopFailure,
                    "replacement stop preserves exact failure");
        }
        replacementStopFailureAgent.stopFailure = null;
        String callsAfterReplacementFailure = replacementStopFailureAgent.calls;
        require(!replacementStopFailureLifecycle.update(endpoint(72L))
                        && callsAfterReplacementFailure.equals(
                        replacementStopFailureAgent.calls),
                "replacement cleanup failure is throttled during backoff");
        replacementStopFailureClock.advance(1_000_000_000L);
        require(replacementStopFailureLifecycle.update(endpoint(72L)),
                "replacement cleanup retries at the due boundary");

        FakeAgent recoveringAgent = new FakeAgent();
        ManualClock recoveringClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator recovering =
                new Cat6ReadyLifecycleCoordinator(
                        recoveringAgent, recoveringClock::now);
        require(recovering.update(endpoint(62L)),
                "worker recovery fixture starts");
        require(recovering.update(endpoint(62L)),
                "worker must be observed healthy before failure reset");
        recoveringAgent.simulateWorkerFailure();
        require(!recovering.isRunning(),
                "native worker failure overrides cached Java state");
        require(!recovering.update(endpoint(62L)),
                "same endpoint records native worker death before retry");
        recoveringClock.advance(1_000_000_000L);
        require(recovering.update(endpoint(62L)),
                "same endpoint restarts native worker at due boundary");
        require(recovering.isRunning()
                        && recovering.report().endsWith(
                        "java_recovery_failures=0"),
                "stable health observation resets recovery history");
        require(("start:62:10.57.23.2:10.57.23.1,stop,"
                + "start:62:10.57.23.2:10.57.23.1")
                .equals(recoveringAgent.calls),
                "same-endpoint recovery uses ordered stop/start");

        FakeAgent observationFailureAgent = new FakeAgent();
        observationFailureAgent.startResult = false;
        Cat6ReadyLifecycleCoordinator observationFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(observationFailureAgent);
        require(!observationFailureLifecycle.update(endpoint(64L)),
                "observation-failure fixture retains a failed-start endpoint");
        IllegalStateException observationFailure =
                new IllegalStateException("native running observation failed");
        observationFailureAgent.isRunningFailure = observationFailure;
        try {
            observationFailureLifecycle.stop();
            throw new AssertionError("isRunning failure must be preserved");
        } catch (IllegalStateException expected) {
            require(expected == observationFailure,
                    "stop preserves the exact isRunning failure");
        }
        require(observationFailureAgent.calls.endsWith(",stop"),
                "stop is attempted when native running observation fails");
        observationFailureAgent.isRunningFailure = null;
        observationFailureAgent.startResult = true;
        require(observationFailureLifecycle.update(endpoint(64L)),
                "observation failure clears cached endpoint and retry state");

        FakeAgent stopFailureAgent = new FakeAgent();
        Cat6ReadyLifecycleCoordinator stopFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(stopFailureAgent);
        require(stopFailureLifecycle.update(endpoint(65L)),
                "stop-failure fixture starts");
        UnsatisfiedLinkError stopFailure =
                new UnsatisfiedLinkError("native stop failed");
        stopFailureAgent.stopFailure = stopFailure;
        try {
            stopFailureLifecycle.stop();
            throw new AssertionError("native stop failure must be preserved");
        } catch (UnsatisfiedLinkError expected) {
            require(expected == stopFailure,
                    "stop preserves the exact native stop failure");
        }
        stopFailureAgent.stopFailure = null;
        require(stopFailureLifecycle.update(endpoint(66L)),
                "stop failure still clears cached state for a clean restart");
        require(stopFailureAgent.calls.endsWith(",stop,stop,"
                        + "start:66:10.57.23.2:10.57.23.1"),
                "restart first closes a native worker left by failed stop");

        FakeAgent combinedFailureAgent = new FakeAgent();
        IllegalStateException combinedObservationFailure =
                new IllegalStateException("combined observation failure");
        UnsatisfiedLinkError combinedStopFailure =
                new UnsatisfiedLinkError("combined stop failure");
        combinedFailureAgent.isRunningFailure = combinedObservationFailure;
        combinedFailureAgent.stopFailure = combinedStopFailure;
        Cat6ReadyLifecycleCoordinator combinedFailureLifecycle =
                new Cat6ReadyLifecycleCoordinator(combinedFailureAgent);
        try {
            combinedFailureLifecycle.stop();
            throw new AssertionError("combined native failures must be preserved");
        } catch (IllegalStateException expected) {
            require(expected == combinedObservationFailure,
                    "running observation remains the primary failure");
            require(expected.getSuppressed().length == 1
                            && expected.getSuppressed()[0] == combinedStopFailure,
                    "fallback stop failure is retained as suppressed context");
        }

        FakeAgent wirelessAgent = new FakeAgent();
        ManualClock wirelessClock = new ManualClock();
        Cat6ReadyLifecycleCoordinator wirelessLifecycle =
                new Cat6ReadyLifecycleCoordinator(
                        wirelessAgent, wirelessClock::now);
        MobileTransportEndpoint wireless =
                MobileTransportEndpointTestFixtures.wirelessLan(
                        61L, "192.168.1.42");
        MobileTransportEndpoint discovered =
                wireless.withDiscoveredHost("192.168.1.18");
        require(wirelessLifecycle.update(discovered),
                "Wi-Fi readiness starts after Host discovery");
        require(wirelessAgent.calls.endsWith(
                        ":192.168.1.18:239.57.23.57:255.255.255.255"),
                "Wi-Fi ready announcements remain multicast plus broadcast after discovery");
        require(wirelessLifecycle.update(discovered.forWirelessHostDiscovery()),
                "explicit rediscovery restarts the ready agent");
        require(wirelessAgent.calls.contains(
                        ":192.168.1.18:239.57.23.57:255.255.255.255,stop,start:61:"),
                "rediscovery clears native requester state through restart");
    }

    private static MobileTransportEndpoint endpoint(long networkHandle) {
        return MobileTransportEndpointTestFixtures.cat6(networkHandle);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static final class FakeAgent implements Cat6ReadyAgentPort {
        private String calls = "";
        private boolean startResult = true;
        private boolean running;
        private boolean partialStartOnFailure;
        private RuntimeException startFailure;
        private RuntimeException isRunningFailure;
        private LinkageError stopFailure;

        @Override
        public boolean start(MobileTransportEndpoint endpoint) {
            String call = "start:" + endpoint.networkHandle + ":" + endpoint.localIpv4
                    + ":" + endpoint.hostIpv4;
            if (!endpoint.isCat6()) {
                call += ":" + endpoint.readyAnnouncementIpv4()
                        + ":" + endpoint.readyAnnouncementBroadcastIpv4();
            }
            append(call);
            if (startFailure != null) throw startFailure;
            running = startResult || partialStartOnFailure;
            return startResult;
        }

        @Override
        public void stop() {
            append("stop");
            if (stopFailure != null) throw stopFailure;
            running = false;
        }

        @Override
        public boolean isRunning() {
            if (isRunningFailure != null) throw isRunningFailure;
            return running;
        }

        @Override
        public String report() {
            return "fake-ready-report";
        }

        private void append(String value) {
            calls = calls.isEmpty() ? value : calls + "," + value;
        }

        private void simulateWorkerFailure() {
            running = false;
        }
    }

    private static final class ManualClock {
        private long nowNanos;

        long now() {
            return nowNanos;
        }

        void advance(long deltaNanos) {
            nowNanos += deltaNanos;
        }
    }
}
