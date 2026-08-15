package com.visionforge.inferencebenchmark;

/** Narrow native boundary for the fixed CAT6 readiness agent. */
interface Cat6ReadyAgentPort {
    boolean start(MobileTransportEndpoint endpoint);

    void stop();

    boolean isRunning();

    String report();
}
