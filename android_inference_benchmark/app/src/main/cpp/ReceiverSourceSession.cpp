#include "ReceiverSourceSession.hpp"

namespace vfdual_android {
namespace {
constexpr std::uint64_t kSourcePortRestartSilenceUs = 300'000;
}

ReceiverSourceSession::ReceiverSourceSession(std::uint32_t expected_ipv4) noexcept
    : expected_ipv4_(expected_ipv4) {}

ReceiverSourceDecision ReceiverSourceSession::observe(std::uint32_t ipv4, std::uint16_t port,
                                                      std::uint64_t now_us) noexcept {
  if (expected_ipv4_ == 0U || ipv4 != expected_ipv4_) {
    return ReceiverSourceDecision::reject_foreign;
  }
  if (!active_) {
    ipv4_ = ipv4;
    port_ = port;
    last_accepted_us_ = now_us;
    active_ = true;
    return ReceiverSourceDecision::accept;
  }
  if (ipv4 == ipv4_ && port == port_) {
    last_accepted_us_ = now_us;
    return ReceiverSourceDecision::accept;
  }
  if (now_us >= last_accepted_us_ &&
      now_us - last_accepted_us_ >= kSourcePortRestartSilenceUs && ipv4 == ipv4_) {
    port_ = port;
    last_accepted_us_ = now_us;
    return ReceiverSourceDecision::restart_source_port;
  }
  return ReceiverSourceDecision::reject_foreign;
}

void ReceiverSourceSession::reset(std::uint32_t expected_ipv4) noexcept {
  expected_ipv4_ = expected_ipv4;
  ipv4_ = 0U;
  port_ = 0U;
  last_accepted_us_ = 0U;
  active_ = false;
}

}  // namespace vfdual_android
