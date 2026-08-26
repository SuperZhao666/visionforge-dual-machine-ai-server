#include "vfdual/access_unit_fragmenter.hpp"
#include "vfdual/access_unit_reassembler.hpp"
#include "vfdual/protocol.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <span>
#include <vector>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
  if (condition) return;
  std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
  std::exit(EXIT_FAILURE);
}

#define CHECK(expression) \
  require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

std::vector<std::byte> make_payload(std::mt19937_64& engine, std::size_t bytes) {
  std::vector<std::byte> payload(bytes);
  for (std::byte& value : payload) {
    value = static_cast<std::byte>(engine() & 0xffU);
  }
  return payload;
}

std::optional<vfdual::CompletedAccessUnit> deliver_shuffled_round_trip(
    std::uint64_t epoch,
    std::uint32_t sequence,
    bool repeated,
    std::span<const std::byte> access_unit,
    std::mt19937_64& engine) {
  auto fragments = vfdual::fragment_access_unit(
      {epoch, sequence}, access_unit, repeated);
  CHECK(!fragments.empty());

  // Exercise the production allocation-free wire decoder before random
  // reordering. Datagram storage remains alive while each view is consumed.
  std::vector<std::vector<std::byte>> datagrams;
  datagrams.reserve(fragments.size() + fragments.size() / 4U + 1U);
  for (const auto& fragment : fragments) {
    auto datagram = vfdual::encode_video_packet(fragment);
    CHECK(datagram.size() ==
          vfdual::kVideoPacketHeaderBytes + fragment.access_unit_part.size());
    vfdual::VideoFragmentView round_trip{};
    CHECK(vfdual::decode_video_packet_view(datagram, round_trip));
    CHECK(round_trip.identity == fragment.identity);
    CHECK(round_trip.repeated_content == fragment.repeated_content);
    CHECK(round_trip.fragment_index == fragment.fragment_index);
    CHECK(round_trip.fragment_count == fragment.fragment_count);
    CHECK(std::equal(
        round_trip.access_unit_part.begin(), round_trip.access_unit_part.end(),
        fragment.access_unit_part.begin(), fragment.access_unit_part.end()));
    datagrams.push_back(std::move(datagram));

    // Identical duplicate datagrams are deliberately injected. They must be
    // idempotent, never counted as a corrupt or second completed frame.
    if ((engine() % 4U) == 0U) datagrams.push_back(datagrams.back());
  }
  std::shuffle(datagrams.begin(), datagrams.end(), engine);

  vfdual::AccessUnitReassembler reassembler;
  CHECK(reassembler.activate_epoch(epoch));
  std::optional<vfdual::CompletedAccessUnit> completed;
  std::uint64_t now_us = 1U;
  for (const auto& datagram : datagrams) {
    vfdual::VideoFragmentView fragment{};
    CHECK(vfdual::decode_video_packet_view(datagram, fragment));
    auto candidate = reassembler.push_view(fragment, now_us++);
    if (candidate.has_value()) {
      CHECK(!completed.has_value());
      completed = std::move(candidate);
    }
  }
  if (!completed.has_value()) completed = reassembler.pop_completed();
  CHECK(reassembler.conflicting_duplicate_losses() == 0U);
  CHECK(reassembler.inflight_frame_count() == 0U);
  CHECK(reassembler.inflight_byte_count() == 0U);
  return completed;
}

void run_success_matrix() {
  for (std::uint64_t seed = 1U; seed <= 256U; ++seed) {
    std::mt19937_64 engine(seed * 0x9e37'79b9'7f4a'7c15ULL);
    const std::size_t bytes = 1U + static_cast<std::size_t>(engine() % 180'000U);
    const auto payload = make_payload(engine, bytes);
    const std::uint64_t epoch = 10'000U + seed;
    const std::uint32_t sequence =
        1U + static_cast<std::uint32_t>(engine() % 100'000U);
    const bool repeated = (seed % 7U) == 0U;

    const auto completed = deliver_shuffled_round_trip(
        epoch, sequence, repeated, payload, engine);
    CHECK(completed.has_value());
    CHECK(completed->identity ==
          (vfdual::VideoFrameIdentity{epoch, sequence}));
    CHECK(completed->repeated_content == repeated);
    CHECK(completed->bytes == payload);
  }
}

void run_loss_and_conflict_matrix() {
  for (std::uint64_t seed = 1U; seed <= 128U; ++seed) {
    std::mt19937_64 engine(seed * 0xd1b5'4a32'd192'ed03ULL);
    const auto payload = make_payload(engine, 8'000U + (engine() % 12'000U));
    auto fragments = vfdual::fragment_access_unit(
        {20'000U + seed, 1U}, payload, false, 700U);
    CHECK(fragments.size() >= 2U);

    const std::size_t dropped = static_cast<std::size_t>(engine() % fragments.size());
    vfdual::AccessUnitReassembler missing_reassembler;
    CHECK(missing_reassembler.activate_epoch(20'000U + seed));
    for (std::size_t index = 0U; index < fragments.size(); ++index) {
      if (index == dropped) continue;
      CHECK(!missing_reassembler.push(fragments[index], index + 1U));
    }
    CHECK(!missing_reassembler.pop_completed().has_value());
    CHECK(missing_reassembler.discard_expired(100'000U, 1'000U) == 1U);
    CHECK(missing_reassembler.incomplete_access_unit_losses() == 1U);
    CHECK(missing_reassembler.inflight_byte_count() == 0U);

    vfdual::AccessUnitReassembler conflict_reassembler;
    const std::uint64_t conflict_epoch = 30'000U + seed;
    CHECK(conflict_reassembler.activate_epoch(conflict_epoch));
    auto first = fragments.front();
    first.identity.stream_epoch = conflict_epoch;
    CHECK(!conflict_reassembler.push(first, 1U));
    auto conflicting = first;
    conflicting.access_unit_part.front() = static_cast<std::byte>(
        std::to_integer<unsigned int>(conflicting.access_unit_part.front()) ^ 0x5aU);
    CHECK(!conflict_reassembler.push(std::move(conflicting), 2U));
    CHECK(conflict_reassembler.conflicting_duplicate_losses() == 1U);
    CHECK(conflict_reassembler.incomplete_access_unit_losses() == 1U);
    CHECK(conflict_reassembler.inflight_frame_count() == 0U);
  }
}

void run_epoch_and_corruption_matrix() {
  vfdual::AccessUnitReassembler reassembler;
  CHECK(reassembler.activate_epoch(101U));
  CHECK(reassembler.activate_epoch(202U));
  CHECK(reassembler.is_retired_epoch(101U));
  CHECK(!reassembler.push(
      {{101U, 1U}, false, 0U, 1U, {std::byte{0x65U}}}, 1U));
  CHECK(reassembler.foreign_or_retired_epoch_drops() == 1U);
  CHECK(!reassembler.activate_epoch(101U));
  for (std::uint64_t epoch = 203U; epoch <= 512U; ++epoch) {
    CHECK(reassembler.activate_epoch(epoch));
  }
  CHECK(reassembler.is_retired_epoch(101U));
  CHECK(!reassembler.activate_epoch(101U));

  const vfdual::VideoFragment source{
      {303U, std::numeric_limits<std::uint32_t>::max()},
      false,
      0U,
      1U,
      {std::byte{0x65U}, std::byte{0x80U}}};
  const auto valid = vfdual::encode_video_packet(source);
  CHECK(!valid.empty());

  for (std::size_t index = 0U; index < vfdual::kVideoPacketHeaderBytes; ++index) {
    auto corrupted = valid;
    corrupted[index] = static_cast<std::byte>(
        std::to_integer<unsigned int>(corrupted[index]) ^ 0xffU);
    vfdual::VideoFragment decoded{};
    // Some individual header mutations remain structurally legal (for
    // example, changing one sequence byte). All mutations must at minimum be
    // memory-safe; fields with protocol invariants are rejected below.
    const bool accepted = vfdual::decode_video_packet(corrupted, decoded);
    if (accepted) {
      CHECK(decoded.identity.valid());
      CHECK(decoded.fragment_count > 0U);
      CHECK(decoded.fragment_index < decoded.fragment_count);
    }
  }

  std::uint32_t next{};
  CHECK(!vfdual::advance_video_frame_sequence(
      std::numeric_limits<std::uint32_t>::max(), next));
}

}  // namespace

int main() {
  static_assert(vfdual::kMaxVideoFragmentsPerAccessUnit == 1561U);
  run_success_matrix();
  run_loss_and_conflict_matrix();
  run_epoch_and_corruption_matrix();
  std::cout << "video_transport_simulation_tests: PASS\n";
  return EXIT_SUCCESS;
}
