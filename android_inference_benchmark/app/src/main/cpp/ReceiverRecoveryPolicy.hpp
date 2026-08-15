#pragma once

#include <cstdint>

namespace vfdual_android {

/** Pure timing policy for loss/reconnect recovery on the UDP video receiver. */
class ReceiverRecoveryPolicy final {
public:
  [[nodiscard]] bool observe_fragment(std::uint64_t now_us, bool completed_access_unit,
                                      bool source_changed, bool reassembly_expired) noexcept;
  [[nodiscard]] bool observe_idle(std::uint64_t now_us, bool sender_known) noexcept;
  void mark_idr_requested(std::uint64_t now_us) noexcept;
  void mark_idle_idr_requested(std::uint64_t now_us) noexcept;
  void reset() noexcept;

private:
  [[nodiscard]] bool request_due(std::uint64_t now_us) const noexcept;

  std::uint64_t first_fragment_us_{};
  std::uint64_t last_fragment_us_{};
  std::uint64_t last_completed_us_{};
  std::uint64_t last_idr_request_us_{};
  std::uint32_t consecutive_idr_requests_{};
  std::uint32_t consecutive_idle_idr_requests_{};
};

}  // namespace vfdual_android
