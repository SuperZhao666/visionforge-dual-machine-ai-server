#pragma once

#include <cstdint>

namespace vfdual_android {

enum class ReceiverSourceDecision : std::uint8_t {
  accept,
  restart_source_port,
  reject_foreign
};

/** Prevents fragments from concurrent host processes entering one H.264 decoder session. */
class ReceiverSourceSession final {
public:
  explicit ReceiverSourceSession(std::uint32_t expected_ipv4) noexcept;
  [[nodiscard]] ReceiverSourceDecision observe(std::uint32_t ipv4, std::uint16_t port,
                                               std::uint64_t now_us) noexcept;
  void reset(std::uint32_t expected_ipv4) noexcept;

private:
  std::uint32_t expected_ipv4_{};
  std::uint32_t ipv4_{};
  std::uint16_t port_{};
  std::uint64_t last_accepted_us_{};
  bool active_{};
};

}  // namespace vfdual_android
