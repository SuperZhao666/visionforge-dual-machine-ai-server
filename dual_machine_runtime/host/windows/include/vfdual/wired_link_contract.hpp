#pragma once

#include <cstdint>

namespace vfdual {

/**
 * Fixed addressing contract for the physically isolated CAT6 data link.
 *
 * The host never installs a gateway or DNS server on this subnet. Keeping the
 * address and port contract in one header prevents session, DHCP and video
 * transport from silently drifting onto an Internet-facing adapter.
 */
inline constexpr char kWiredHostIpv4[] = "10.57.23.1";
inline constexpr char kWiredMobileIpv4[] = "10.57.23.2";
inline constexpr char kWiredSubnetMask[] = "255.255.255.0";
inline constexpr std::uint16_t kWiredDhcpServerPort = 67;
inline constexpr std::uint16_t kWiredDhcpClientPort = 68;
inline constexpr std::uint16_t kWiredVideoPort = 5000;
inline constexpr std::uint16_t kWiredIdrPort = 5001;
// A stable source port lets Android distinguish a restarted Host process from
// a foreign concurrent sender without needlessly replacing MediaCodec.
inline constexpr std::uint16_t kWiredVideoSourcePort = 5002;
inline constexpr std::uint16_t kWiredAnnouncementPort = 5003;
inline constexpr std::uint16_t kWiredProbePort = 5004;
inline constexpr std::uint16_t kWiredMouseButtonPort = 5005;

// The Wi-Fi fallback is always available when CAT6 is not reachable. Android
// announces on this administratively scoped multicast group, then all data
// traffic switches to the discovered unicast endpoints.
inline constexpr char kWirelessLanDiscoveryIpv4[] = "239.57.23.57";
inline constexpr char kCat6TransportName[] = "cat6";
inline constexpr char kWirelessLanUdpTransportName[] = "wireless_lan_udp";

}  // namespace vfdual
