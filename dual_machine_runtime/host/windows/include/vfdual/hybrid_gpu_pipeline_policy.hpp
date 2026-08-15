#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <type_traits>
#include <utility>

namespace vfdual {

/** Overflow-safe conversion for QPC values; zero frequency is invalid. */
[[nodiscard]] inline std::uint64_t qpc_ticks_to_microseconds(
    std::uint64_t ticks, std::uint64_t frequency) noexcept {
    if (frequency == 0U) return 0U;
    constexpr std::uint64_t scale = 1'000'000U;
    constexpr std::uint64_t maximum = (std::numeric_limits<std::uint64_t>::max)();
    const std::uint64_t whole_seconds = ticks / frequency;
    const std::uint64_t remainder_ticks = ticks % frequency;
    if (whole_seconds > maximum / scale) return maximum;
    const std::uint64_t converted_remainder = remainder_ticks <= maximum / scale
        ? (remainder_ticks * scale) / frequency
        : static_cast<std::uint64_t>(
              (static_cast<long double>(remainder_ticks) * scale) /
              static_cast<long double>(frequency));
    const std::uint64_t remainder_microseconds = converted_remainder < scale
        ? converted_remainder
        : scale - 1U;
    const std::uint64_t whole_microseconds = whole_seconds * scale;
    return remainder_microseconds <= maximum - whole_microseconds
        ? whole_microseconds + remainder_microseconds
        : maximum;
}

/**
 * Pure state policy for the three GPU readback slots.
 *
 * The owner serializes access because D3D11 immediate-context operations are
 * deliberately confined to one submit/poll thread.
 */
template <std::size_t SlotCount>
class PendingSlotPolicy final {
public:
    [[nodiscard]] std::optional<std::size_t> acquire() noexcept {
        for (std::size_t offset = 0; offset < SlotCount; ++offset) {
            const std::size_t index = (next_ + offset) % SlotCount;
            if (pending_[index]) continue;
            pending_[index] = true;
            next_ = (index + 1U) % SlotCount;
            return index;
        }
        return std::nullopt;
    }

    void release(std::size_t index) noexcept {
        if (index < SlotCount) pending_[index] = false;
    }

    [[nodiscard]] bool is_pending(std::size_t index) const noexcept {
        return index < SlotCount && pending_[index];
    }

    [[nodiscard]] std::size_t pending_count() const noexcept {
        std::size_t count{};
        for (const bool pending : pending_) count += pending ? 1U : 0U;
        return count;
    }

    void reset() noexcept {
        pending_.fill(false);
        next_ = 0;
    }

private:
    std::array<bool, SlotCount> pending_{};
    std::size_t next_{};
};

enum class CpuFrameSlotState { available, writing, mailbox, worker };

/**
 * Capacity-one latest-frame mailbox backed by a fixed CPU slot pool.
 *
 * publish_latest() returns the superseded slot, which has already been made
 * available. The caller uses that return value only for observability.
 */
template <std::size_t SlotCount>
class LatestOnlySlotPolicy final {
public:
    [[nodiscard]] std::optional<std::size_t> acquire_for_write() noexcept {
        for (std::size_t index = 0; index < SlotCount; ++index) {
            if (states_[index] != CpuFrameSlotState::available) continue;
            states_[index] = CpuFrameSlotState::writing;
            return index;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<std::size_t> publish_latest(std::size_t index) noexcept {
        if (index >= SlotCount || states_[index] != CpuFrameSlotState::writing) {
            return std::nullopt;
        }
        std::optional<std::size_t> superseded;
        if (mailbox_.has_value()) {
            superseded = mailbox_;
            states_[*mailbox_] = CpuFrameSlotState::available;
        }
        mailbox_ = index;
        states_[index] = CpuFrameSlotState::mailbox;
        return superseded;
    }

    [[nodiscard]] std::optional<std::size_t> take_latest() noexcept {
        if (!mailbox_.has_value()) return std::nullopt;
        const std::size_t index = *mailbox_;
        mailbox_.reset();
        states_[index] = CpuFrameSlotState::worker;
        return index;
    }

    void cancel_write(std::size_t index) noexcept {
        if (index < SlotCount && states_[index] == CpuFrameSlotState::writing) {
            states_[index] = CpuFrameSlotState::available;
        }
    }

    void release_worker(std::size_t index) noexcept {
        if (index < SlotCount && states_[index] == CpuFrameSlotState::worker) {
            states_[index] = CpuFrameSlotState::available;
        }
    }

    [[nodiscard]] bool has_mailbox_frame() const noexcept { return mailbox_.has_value(); }
    [[nodiscard]] std::optional<std::size_t> mailbox_index() const noexcept {
        return mailbox_;
    }
    [[nodiscard]] CpuFrameSlotState state(std::size_t index) const noexcept {
        return index < SlotCount ? states_[index] : CpuFrameSlotState::available;
    }

    void reset() noexcept {
        states_.fill(CpuFrameSlotState::available);
        mailbox_.reset();
    }

private:
    std::array<CpuFrameSlotState, SlotCount> states_{};
    std::optional<std::size_t> mailbox_;
};

enum class SharedTextureSlotState {
    available,
    writing,
    mailbox,
    retired,
    worker,
};

/**
 * Capacity-one latest mailbox for keyed shared-texture slots.
 *
 * A replaced mailbox slot becomes retired rather than immediately available:
 * only the worker may acquire its consumer key and return the producer key.
 * The owner serializes every transition with the pipeline worker mutex.
 */
template <std::size_t SlotCount>
class SharedTextureMailboxPolicy final {
public:
    static_assert(SlotCount > 0U);

    [[nodiscard]] std::optional<std::size_t> acquire_for_copy() noexcept {
        for (std::size_t offset = 0; offset < SlotCount; ++offset) {
            const std::size_t index = (next_ + offset) % SlotCount;
            if (states_[index] != SharedTextureSlotState::available) continue;
            states_[index] = SharedTextureSlotState::writing;
            next_ = (index + 1U) % SlotCount;
            return index;
        }
        return std::nullopt;
    }

    void cancel_copy(std::size_t index) noexcept {
        if (index < SlotCount &&
            states_[index] == SharedTextureSlotState::writing) {
            states_[index] = SharedTextureSlotState::available;
        }
    }

    [[nodiscard]] std::optional<std::size_t> publish_latest(
        std::size_t index) noexcept {
        if (index >= SlotCount ||
            states_[index] != SharedTextureSlotState::writing) {
            return std::nullopt;
        }
        std::optional<std::size_t> replaced;
        if (mailbox_.has_value()) {
            replaced = mailbox_;
            states_[*mailbox_] = SharedTextureSlotState::retired;
        }
        mailbox_ = index;
        states_[index] = SharedTextureSlotState::mailbox;
        return replaced;
    }

    [[nodiscard]] std::optional<std::size_t> take_latest() noexcept {
        if (!mailbox_.has_value()) return std::nullopt;
        const std::size_t index = *mailbox_;
        mailbox_.reset();
        states_[index] = SharedTextureSlotState::worker;
        return index;
    }

    [[nodiscard]] std::optional<std::size_t> take_retired() noexcept {
        for (std::size_t index = 0; index < SlotCount; ++index) {
            if (states_[index] != SharedTextureSlotState::retired) continue;
            states_[index] = SharedTextureSlotState::worker;
            return index;
        }
        return std::nullopt;
    }

    /** Restores a timed-out worker slot without displacing a newer mailbox. */
    void defer_worker(std::size_t index) noexcept {
        if (index >= SlotCount ||
            states_[index] != SharedTextureSlotState::worker) {
            return;
        }
        if (!mailbox_.has_value()) {
            mailbox_ = index;
            states_[index] = SharedTextureSlotState::mailbox;
        } else {
            states_[index] = SharedTextureSlotState::retired;
        }
    }

    void retire_worker(std::size_t index) noexcept {
        if (index < SlotCount &&
            states_[index] == SharedTextureSlotState::worker) {
            states_[index] = SharedTextureSlotState::retired;
        }
    }

    /** Call only after ReleaseSync returned the producer key. */
    void release_worker(std::size_t index) noexcept {
        if (index < SlotCount &&
            states_[index] == SharedTextureSlotState::worker) {
            states_[index] = SharedTextureSlotState::available;
        }
    }

    [[nodiscard]] bool has_mailbox_frame() const noexcept {
        return mailbox_.has_value();
    }
    [[nodiscard]] bool has_retired_frame() const noexcept {
        for (const SharedTextureSlotState state : states_) {
            if (state == SharedTextureSlotState::retired) return true;
        }
        return false;
    }
    [[nodiscard]] std::optional<std::size_t> mailbox_index() const noexcept {
        return mailbox_;
    }
    [[nodiscard]] SharedTextureSlotState state(std::size_t index) const noexcept {
        return index < SlotCount
            ? states_[index]
            : SharedTextureSlotState::available;
    }
    [[nodiscard]] std::size_t occupied_count() const noexcept {
        std::size_t count{};
        for (const SharedTextureSlotState state : states_) {
            count += state == SharedTextureSlotState::available ? 0U : 1U;
        }
        return count;
    }

    void reset() noexcept {
        states_.fill(SharedTextureSlotState::available);
        mailbox_.reset();
        next_ = 0U;
    }

private:
    std::array<SharedTextureSlotState, SlotCount> states_{};
    std::optional<std::size_t> mailbox_;
    std::size_t next_{};
};

/**
 * Advances one absolute period without building a backlog.
 *
 * A fast encode retains the original phase. A slow encode schedules the next
 * iteration immediately at completion instead of waiting another full period.
 */
[[nodiscard]] inline std::uint64_t advance_absolute_deadline(
    std::uint64_t previous_deadline, std::uint64_t completed_at,
    std::uint64_t period) noexcept {
    if (period == 0U) return completed_at;
    constexpr std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    const std::uint64_t scheduled = previous_deadline > maximum - period
        ? maximum
        : previous_deadline + period;
    return scheduled < completed_at ? completed_at : scheduled;
}

/** A retained-frame repeat must not run while a fresher GPU readback exists. */
[[nodiscard]] constexpr bool idle_repeat_must_defer_to_source(
    bool fresh_mailbox_frame_available,
    bool source_readback_pending) noexcept {
    return !fresh_mailbox_frame_available && source_readback_pending;
}

/**
 * Converts a positive steady-clock delay to a relative Windows timer due time.
 * Rounding up avoids firing before the absolute cadence deadline; zero still
 * becomes the smallest valid relative delay rather than an absolute timestamp.
 */
[[nodiscard]] inline std::int64_t relative_waitable_timer_due_100ns(
    std::uint64_t delay_ns) noexcept {
    constexpr std::uint64_t nanoseconds_per_tick = 100U;
    std::uint64_t ticks = delay_ns / nanoseconds_per_tick;
    if (delay_ns % nanoseconds_per_tick != 0U) ++ticks;
    if (ticks == 0U) ticks = 1U;
    return -static_cast<std::int64_t>(ticks);
}

/** Fixed-capacity ring that drops the oldest item so diagnostics stay current. */
template <typename Value, std::size_t Capacity>
class FixedLatestRing final {
public:
    static_assert(Capacity > 0U);
    static_assert(std::is_nothrow_move_assignable_v<Value>);

    [[nodiscard]] bool push(Value value) noexcept {
        bool dropped{};
        if (size_ == Capacity) {
            head_ = (head_ + 1U) % Capacity;
            --size_;
            dropped = true;
        }
        values_[(head_ + size_) % Capacity] = std::move(value);
        ++size_;
        return dropped;
    }

    [[nodiscard]] bool pop(Value& destination) noexcept {
        if (size_ == 0) return false;
        destination = std::move(values_[head_]);
        head_ = (head_ + 1U) % Capacity;
        --size_;
        return true;
    }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    void reset() noexcept {
        head_ = 0;
        size_ = 0;
    }

private:
    std::array<Value, Capacity> values_{};
    std::size_t head_{};
    std::size_t size_{};
};

}  // namespace vfdual
