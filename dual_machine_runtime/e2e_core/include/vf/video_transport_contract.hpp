#pragma once

#include "vf/wire_protocol.hpp"

#include <cstdint>
#include <limits>
#include <string_view>

namespace vf::transport {

/**
 * 视频数据面的稳定协议契约。
 *
 * 这里集中声明跨 Host/C++ 与 APP/Java 必须保持一致的数值约束。业务代码不得自行
 * 复制这些常量，否则一次“只改一端”的改动就可能把可编译问题变成线上静默丢帧。
 */
inline constexpr std::uint32_t kProtocolVersion = 2;
inline constexpr std::uint64_t kMinimumStreamEpoch = 1;
inline constexpr std::uint64_t kMaximumStreamEpoch = kMaxStreamEpoch;
inline constexpr std::uint32_t kMaximumFrameSequence =
    std::numeric_limits<std::uint32_t>::max();
inline constexpr std::uint16_t kMaximumFragmentCount = kMaxFragments;
inline constexpr std::size_t kHeaderBytes = kWireHeaderSize;

static_assert(kHeaderBytes == 20, "v2 wire header size must remain stable");
static_assert(kMaximumFragmentCount == 1561, "fragment-count contract drifted");

enum class ContractViolation {
    None,
    ZeroEpoch,
    EpochOutOfRange,
    ZeroFragmentCount,
    TooManyFragments,
    FragmentIndexOutOfRange,
    RepeatShapeInvalid,
};

/** Host 在 uint32 序号耗尽前必须切换到新的 stream_epoch，绝不能回绕复用旧序号。 */
[[nodiscard]] constexpr bool requires_epoch_rollover(std::uint32_t sequence) noexcept {
    return sequence == kMaximumFrameSequence;
}

[[nodiscard]] ContractViolation validate(const WireHeader& header) noexcept;
[[nodiscard]] std::string_view violation_name(ContractViolation violation) noexcept;

}  // namespace vf::transport
