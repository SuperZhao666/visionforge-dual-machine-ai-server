#pragma once

#include "vf/host/domain/frame_identity.hpp"
#include "vf/wire_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace vf::host::infrastructure {

// IPv4 UDP 的最大安全 payload。即便生产网络使用 IPv6，也不允许生成一个依赖
// 巨型 IP 分片才能发送的数据报。
inline constexpr std::size_t kMaximumUdpDatagramBytes = 65'507;

struct FragmentationConfig {
    std::size_t max_datagram_bytes{1200};
    std::uint16_t max_fragments{kMaxFragments};
    std::size_t max_access_unit_bytes{2U * 1024U * 1024U};
};

/**
 * 将一个完整 H.264 access unit 切成有界 UDP 数据报。发送端上限与 APP/C++ 接收端
 * 默认上限一致，避免“Host 能发、APP 必然拒绝”的跨端配置裂缝。
 */
class DatagramFragmenter {
public:
    explicit DatagramFragmenter(FragmentationConfig config = {});

    [[nodiscard]] std::vector<std::vector<std::uint8_t>> fragment(
        host::domain::FrameIdentity identity,
        std::span<const std::uint8_t> access_unit) const;

    [[nodiscard]] std::vector<std::uint8_t> repeat(
        host::domain::FrameIdentity identity) const;

    [[nodiscard]] std::size_t payload_capacity() const noexcept {
        return config_.max_datagram_bytes - kWireHeaderSize;
    }
    [[nodiscard]] std::size_t max_access_unit_bytes() const noexcept {
        return config_.max_access_unit_bytes;
    }

private:
    FragmentationConfig config_;
};

}  // namespace vf::host::infrastructure
