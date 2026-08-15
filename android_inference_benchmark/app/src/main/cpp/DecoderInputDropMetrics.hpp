#pragma once

#include <cstdint>
#include <string_view>

namespace vfdual_android {

enum class JavaAccessUnitOfferResult : std::int32_t {
  accepted = 0,
  invalid = 1,
  not_running = 2,
  queue_capacity = 3,
  restarting = 4,
  reference_recovery = 5,
  bridge_failure = 6,
};

/** Reason counters shared by synchronous admission and asynchronous MediaCodec failure paths. */
struct DecoderInputDropMetrics final {
  std::uint64_t no_input_buffer{};
  std::uint64_t stale_before_codec{};
  std::uint64_t queue_capacity{};
  std::uint64_t buffer_capacity{};
  std::uint64_t codec_exception{};
  std::uint64_t state_exception{};
  std::uint64_t restart{};
  std::uint64_t reference_recovery{};
  std::uint64_t not_running{};
  std::uint64_t invalid{};
  std::uint64_t bridge_failure{};
  std::uint64_t fatal_flush{};
  std::uint64_t recovery_flush{};
  std::uint64_t stop_flush{};
  std::uint64_t other{};

  void reset() noexcept { *this = {}; }

  void record_offer(JavaAccessUnitOfferResult result) noexcept {
    switch (result) {
      case JavaAccessUnitOfferResult::accepted: return;
      case JavaAccessUnitOfferResult::invalid: ++invalid; return;
      case JavaAccessUnitOfferResult::not_running: ++not_running; return;
      case JavaAccessUnitOfferResult::queue_capacity: ++queue_capacity; return;
      case JavaAccessUnitOfferResult::restarting: ++restart; return;
      case JavaAccessUnitOfferResult::reference_recovery: ++reference_recovery; return;
      case JavaAccessUnitOfferResult::bridge_failure: ++bridge_failure; return;
    }
    ++other;
  }

  void record_async(std::string_view reason) noexcept {
    if (reason == "input_no_buffer_stall") ++no_input_buffer;
    else if (reason == "input_stale_before_codec") ++stale_before_codec;
    else if (reason == "input_buffer_capacity") ++buffer_capacity;
    else if (reason == "input_codec_exception") ++codec_exception;
    else if (reason == "input_state_exception") ++state_exception;
    else if (reason == "input_fatal_flush") ++fatal_flush;
    else if (reason == "input_restart_flush") ++restart;
    else if (reason == "input_recovery_flush") ++recovery_flush;
    else if (reason == "input_stop_flush") ++stop_flush;
    else ++other;
  }

  [[nodiscard]] std::uint64_t total() const noexcept {
    return no_input_buffer + stale_before_codec + queue_capacity + buffer_capacity + codec_exception +
        state_exception + restart + reference_recovery + not_running + invalid + bridge_failure +
        fatal_flush + recovery_flush + stop_flush + other;
  }
};

}  // namespace vfdual_android
