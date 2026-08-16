#include "vfdual/protocol.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <span>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
constexpr std::size_t kIterations = 500'000U;
constexpr std::size_t kWarmupIterations = 10'000U;

[[nodiscard]] std::uint64_t consume_view(
    std::span<const std::byte> packet, std::size_t iterations) {
  std::uint64_t checksum{};
  for (std::size_t iteration{}; iteration < iterations; ++iteration) {
    vfdual::VideoFragmentView decoded{};
    if (!vfdual::decode_video_packet_view(packet, decoded)) std::abort();
    checksum += decoded.identity.stream_epoch;
    checksum += decoded.identity.frame_sequence;
    checksum += decoded.access_unit_part.size();
    checksum += std::to_integer<std::uint8_t>(decoded.access_unit_part.front());
    checksum += std::to_integer<std::uint8_t>(decoded.access_unit_part.back());
  }
  return checksum;
}

[[nodiscard]] std::uint64_t consume_owning(
    std::span<const std::byte> packet, std::size_t iterations) {
  std::uint64_t checksum{};
  for (std::size_t iteration{}; iteration < iterations; ++iteration) {
    // This mirrors the former receiver hot path: a new owning fragment was
    // constructed for every datagram, forcing payload allocation and copying.
    vfdual::VideoFragment decoded{};
    if (!vfdual::decode_video_packet(packet, decoded)) std::abort();
    checksum += decoded.identity.stream_epoch;
    checksum += decoded.identity.frame_sequence;
    checksum += decoded.access_unit_part.size();
    checksum += std::to_integer<std::uint8_t>(decoded.access_unit_part.front());
    checksum += std::to_integer<std::uint8_t>(decoded.access_unit_part.back());
  }
  return checksum;
}

[[nodiscard]] double nanos_per_operation(
    Clock::duration elapsed, std::size_t iterations) {
  const double nanoseconds = static_cast<double>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
  return nanoseconds / static_cast<double>(iterations);
}
}  // namespace

int main() {
  std::vector<std::byte> payload(vfdual::kVideoPacketPayloadBytes);
  for (std::size_t index{}; index < payload.size(); ++index) {
    payload[index] = std::byte(index & 0xffU);
  }
  vfdual::VideoFragment source{
      {42U, 7U}, false, 0U, 1U, payload};
  const std::vector<std::byte> packet = vfdual::encode_video_packet(source);
  if (packet.size() != vfdual::kMaxDatagramBytes) {
    std::cerr << "unexpected encoded datagram size\n";
    return 2;
  }

  const std::uint64_t warm_view = consume_view(packet, kWarmupIterations);
  const std::uint64_t warm_owning = consume_owning(packet, kWarmupIterations);
  if (warm_view != warm_owning) {
    std::cerr << "warmup checksum mismatch\n";
    return 3;
  }

  const auto view_started = Clock::now();
  const std::uint64_t view_checksum = consume_view(packet, kIterations);
  const auto view_elapsed = Clock::now() - view_started;

  const auto owning_started = Clock::now();
  const std::uint64_t owning_checksum = consume_owning(packet, kIterations);
  const auto owning_elapsed = Clock::now() - owning_started;
  if (view_checksum != owning_checksum) {
    std::cerr << "benchmark checksum mismatch\n";
    return 4;
  }

  const double view_ns = nanos_per_operation(view_elapsed, kIterations);
  const double owning_ns = nanos_per_operation(owning_elapsed, kIterations);
  const double speedup = owning_ns / view_ns;

  std::cout << std::fixed << std::setprecision(3)
            << "{\n"
            << "  \"schema_version\": \"visionforge.video-decode-benchmark.v1\",\n"
            << "  \"status\": \"PASS\",\n"
            << "  \"iterations\": " << kIterations << ",\n"
            << "  \"payload_bytes\": " << payload.size() << ",\n"
            << "  \"zero_copy_view_ns_per_datagram\": " << view_ns << ",\n"
            << "  \"legacy_owning_ns_per_datagram\": " << owning_ns << ",\n"
            << "  \"measured_speedup\": " << speedup << ",\n"
            << "  \"checksum\": " << view_checksum << "\n"
            << "}\n";
  return 0;
}
