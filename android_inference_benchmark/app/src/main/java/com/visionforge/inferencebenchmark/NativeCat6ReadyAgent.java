package com.visionforge.inferencebenchmark;

/** Production JNI adapter for the fixed CAT6 readiness agent. */
final class NativeCat6ReadyAgent implements Cat6ReadyAgentPort {
    @Override
    public boolean start(MobileTransportEndpoint endpoint) {
        if (endpoint == null) return false;
        return QnnHtpBridge.startNativeCat6ReadyAgent(
                endpoint.localIpv4,
                endpoint.readyAnnouncementIpv4(),
                endpoint.readyAnnouncementBroadcastIpv4(),
                endpoint.networkHandle);
    }

    @Override
    public void stop() {
        QnnHtpBridge.stopNativeCat6ReadyAgent();
    }

    @Override
    public boolean isRunning() {
        return QnnHtpBridge.isNativeCat6ReadyAgentRunning();
    }

    @Override
    public String report() {
        return QnnHtpBridge.getNativeCat6ReadyAgentReport();
    }
}
