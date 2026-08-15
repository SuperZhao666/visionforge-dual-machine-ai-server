#pragma once

#include "vfdual/protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace vfdual {

struct CompletedAccessUnit {
    std::uint32_t frame_id{};
    std::vector<std::byte> bytes;
};

/** Bounded, decode-order-preserving reassembly for UDP encoded access units. */
class AccessUnitReassembler final {
public:
    explicit AccessUnitReassembler(std::size_t max_inflight_frames = 8) noexcept;
    /** Takes fragment ownership so the receiver performs no second payload allocation/copy. */
    [[nodiscard]] std::optional<CompletedAccessUnit> push(
        VideoFragment fragment, std::uint64_t now_us);
    /** Drains another already-complete AU only when every older AU was drained. */
    [[nodiscard]] std::optional<CompletedAccessUnit> pop_completed();
    [[nodiscard]] std::size_t discard_expired(
        std::uint64_t now_us, std::uint64_t ttl_us = 50'000) noexcept;
    [[nodiscard]] std::size_t inflight_frame_count() const noexcept;
    /** Cumulative incomplete AUs lost to conflict, bounds, or expiry. */
    [[nodiscard]] std::uint64_t incomplete_access_unit_losses() const noexcept;

private:
    struct PendingFrame {
        std::uint16_t expected_fragments{};
        std::uint16_t received_fragments{};
        std::size_t total_bytes{};
        std::uint64_t first_seen_us{};
        std::uint64_t arrival_order{};
        std::vector<bool> received;
        std::vector<std::vector<std::byte>> parts;
    };

    void discard_oldest() noexcept;

    std::size_t max_inflight_frames_{};
    std::uint64_t next_arrival_order_{};
    std::uint64_t incomplete_access_unit_losses_{};
    std::optional<std::uint32_t> last_delivered_sequence_;
    std::unordered_map<std::uint32_t, PendingFrame> pending_;
};

}  // namespace vfdual
