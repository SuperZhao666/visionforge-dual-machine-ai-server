package com.visionforge.inferencebenchmark;

import android.net.Network;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/** Host-JVM fixtures that avoid Android framework constructors hidden from apps. */
final class MobileTransportEndpointTestFixtures {
    private MobileTransportEndpointTestFixtures() {}

    static MobileTransportEndpoint cat6(long networkHandle) {
        return create(
                networkHandle,
                MobileTransportEndpoint.Kind.CAT6,
                EthernetTransportContract.MOBILE_IPV4,
                EthernetTransportContract.HOST_IPV4,
                true);
    }

    static MobileTransportEndpoint wirelessLan(long networkHandle, String localIpv4) {
        return create(
                networkHandle,
                MobileTransportEndpoint.Kind.WIRELESS_LAN_UDP,
                localIpv4,
                MobileTransportEndpoint.WIRELESS_DISCOVERY_IPV4,
                false);
    }

    static MobileTransportEndpoint loopbackProbe(
            long networkHandle,
            String localIpv4,
            String hostIpv4) {
        return create(
                new Network(),
                networkHandle,
                MobileTransportEndpoint.Kind.WIRELESS_LAN_UDP,
                localIpv4,
                hostIpv4,
                true);
    }

    private static MobileTransportEndpoint create(
            long networkHandle,
            MobileTransportEndpoint.Kind kind,
            String localIpv4,
            String hostIpv4,
            boolean hostDiscovered) {
        return create(
                null,
                networkHandle,
                kind,
                localIpv4,
                hostIpv4,
                hostDiscovered);
    }

    private static MobileTransportEndpoint create(
            Network network,
            long networkHandle,
            MobileTransportEndpoint.Kind kind,
            String localIpv4,
            String hostIpv4,
            boolean hostDiscovered) {
        if (networkHandle <= 0L) throw new IllegalArgumentException("networkHandle");
        try {
            Constructor<MobileTransportEndpoint> constructor =
                    MobileTransportEndpoint.class.getDeclaredConstructor(
                            Network.class,
                            long.class,
                            MobileTransportEndpoint.Kind.class,
                            String.class,
                            String.class,
                            boolean.class);
            constructor.setAccessible(true);
            return constructor.newInstance(
                    network,
                    networkHandle,
                    kind,
                    localIpv4,
                    hostIpv4,
                    hostDiscovered);
        } catch (NoSuchMethodException | InstantiationException
                 | IllegalAccessException | InvocationTargetException failure) {
            throw new AssertionError("Cannot create mobile transport endpoint fixture", failure);
        }
    }
}
