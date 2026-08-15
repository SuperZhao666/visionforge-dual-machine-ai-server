#pragma once

#include <cstdint>

namespace vfdual_android {

/** Pure timeout policy: UDP remains blocking, while idle wakeups become sparse. */
class ReceiverIdleBackoff final {
public:
  [[nodiscard]] static constexpr std::uint64_t receive_timeout_us(
      std::uint64_t idle_us) noexcept {
    if (idle_us < 1'000'000U) return 100'000U;
    if (idle_us < 5'000'000U) return 500'000U;
    if (idle_us < 15'000'000U) return 1'000'000U;
    return 5'000'000U;
  }
};

}  // namespace vfdual_android
