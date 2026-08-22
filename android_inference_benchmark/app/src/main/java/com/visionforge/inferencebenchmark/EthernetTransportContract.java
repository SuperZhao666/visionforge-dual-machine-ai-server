package com.visionforge.inferencebenchmark;

/** Fixed CAT6 point-to-point contract for the production video path. */
final class EthernetTransportContract {
    static final String INTERFACE_NAME = "eth0";
    static final String HOST_IPV4 = "10.57.23.1";
    static final String MOBILE_IPV4 = "10.57.23.2";
    static final int PREFIX_LENGTH = 24;
    static final int MOUSE_BUTTON_PORT = 5005;

    private EthernetTransportContract() {
    }

    static boolean accepts(boolean ethernetTransport, String interfaceName, String ipv4,
                           int prefixLength) {
        return evaluate(ethernetTransport, interfaceName, ipv4, prefixLength).accepted;
    }

    static Validation evaluate(boolean ethernetTransport, String interfaceName, String ipv4,
                               int prefixLength) {
        if (!ethernetTransport) {
            return Validation.rejected("transport_not_ethernet");
        }
        if (interfaceName == null || interfaceName.isBlank()) {
            return Validation.rejected("interface_name_missing");
        }
        if (!INTERFACE_NAME.equals(interfaceName)) {
            return Validation.rejected(
                    "interface_name_mismatch expected=" + INTERFACE_NAME
                            + " actual=" + interfaceName);
        }
        if (ipv4 == null || ipv4.isBlank()) {
            return Validation.rejected("ip_address_missing");
        }
        if (!MOBILE_IPV4.equals(ipv4)) {
            return Validation.rejected(
                    "ip_address_mismatch expected=" + MOBILE_IPV4 + " actual=" + ipv4);
        }
        if (prefixLength != PREFIX_LENGTH) {
            return Validation.rejected(
                    "prefix_length_mismatch expected=" + PREFIX_LENGTH
                            + " actual=" + prefixLength);
        }
        return Validation.accepted();
    }

    static String requiredLink() {
        return INTERFACE_NAME + " " + MOBILE_IPV4 + "/" + PREFIX_LENGTH;
    }

    static final class Validation {
        final boolean accepted;
        final String reason;

        private Validation(boolean accepted, String reason) {
            this.accepted = accepted;
            this.reason = reason;
        }

        static Validation accepted() {
            return new Validation(true, "accepted");
        }

        static Validation rejected(String reason) {
            return new Validation(false, reason);
        }
    }
}
