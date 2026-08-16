#pragma once

#include "vf/wire_protocol.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

namespace vf {

enum class RecoveryPhase { Running, WaitingFreshIdr, RecoveryRequired, Exhausted };
enum class RecoveryAction { None, RequestIdr, RebuildSession };

class ReceiverRepeatResyncPolicy {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    ReceiverRepeatResyncPolicy(std::chrono::milliseconds wait_timeout, unsigned max_retries);
    void on_repeat(TimePoint now);
    [[nodiscard]] bool should_accept(bool is_idr, bool is_repeat, bool content_updated, TimePoint now);
    [[nodiscard]] RecoveryAction poll_action(TimePoint now);
    void on_session_rebuilt(TimePoint now);
    [[nodiscard]] RecoveryPhase phase() const noexcept { return phase_; }
    [[nodiscard]] unsigned retries() const noexcept { return retries_; }

private:
    void update_timeout(TimePoint now);
    std::chrono::milliseconds wait_timeout_;
    unsigned max_retries_{};
    unsigned retries_{};
    RecoveryPhase phase_{RecoveryPhase::Running};
    std::optional<TimePoint> deadline_;
};

enum class GateDecision { Allowed, Blocked, RecoveryRequired };

class PostAckVisibilityGate {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    explicit PostAckVisibilityGate(std::chrono::milliseconds timeout);

    /** 新调用点必须传入完整帧身份与同一单调时钟域中的绝对 deadline。 */
    void arm_until(
        std::uint64_t source_epoch,
        std::uint32_t source_sequence,
        TimePoint ack_time,
        TimePoint absolute_deadline);
    /** 兼容相对超时调用点；内部会换算成绝对 deadline。 */
    void arm(
        std::uint64_t source_epoch,
        std::uint32_t source_sequence,
        TimePoint ack_time,
        TimePoint now);
    /** 旧单 epoch 适配器兼容入口。 */
    void arm(std::uint64_t source_sequence, TimePoint ack_time, TimePoint now);

    [[nodiscard]] GateDecision evaluate(
        bool content_updated,
        std::uint64_t observed_epoch,
        std::uint32_t frame_sequence,
        TimePoint observed_at,
        TimePoint now);
    /** 旧单 epoch 适配器兼容入口。 */
    [[nodiscard]] GateDecision evaluate(
        bool content_updated,
        std::uint64_t frame_sequence,
        TimePoint observed_at,
        TimePoint now);

    void reset() noexcept;
    [[nodiscard]] bool armed() const noexcept { return armed_; }
    [[nodiscard]] std::optional<std::uint64_t> source_epoch() const noexcept;
    [[nodiscard]] std::optional<std::uint32_t> source_sequence() const noexcept;

private:
    static void validate_identity(std::uint64_t epoch, std::uint64_t sequence);

    std::chrono::milliseconds timeout_;
    bool armed_{};
    bool recovery_required_{};
    std::uint64_t source_epoch_{};
    std::uint32_t source_sequence_{};
    TimePoint ack_time_{};
    TimePoint deadline_{};
};

enum class TicketResult { Completed, Expired, Cancelled, Stale, WrongTicket };

class ExactTicket {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    void begin(std::uint64_t ticket_id, TimePoint deadline);
    [[nodiscard]] TicketResult complete(std::uint64_t ticket_id, TimePoint now);
    [[nodiscard]] TicketResult expire(TimePoint now);
    [[nodiscard]] TicketResult cancel() noexcept;
    [[nodiscard]] bool pending() const noexcept { return pending_; }
    [[nodiscard]] std::uint64_t transition_id() const noexcept { return transition_id_; }

private:
    bool pending_{};
    std::uint64_t ticket_id_{};
    std::uint64_t highest_ticket_id_{};
    TimePoint deadline_{};
    std::uint64_t transition_id_{};
};

enum class ControlBlocker {
    Runnable,
    WaitingFreshIdr,
    WaitingPostAckVisibility,
    TicketPending,
    TicketDeadlineExpired,
    PostAckVisibilityTimeout,
    DetectedNotTrackEligible,
    ResponseGuardNoProgress,
    SubcountUnresolvable,
    TransportNotReady,
    CircuitOpen,
    RecoveryExhausted,
};

class BlockerTracker {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    explicit BlockerTracker(TimePoint now) : changed_at_(now) {}
    void set(ControlBlocker blocker, TimePoint now) noexcept;
    [[nodiscard]] ControlBlocker current() const noexcept { return current_; }
    [[nodiscard]] std::uint64_t transition_id() const noexcept { return transition_id_; }
    [[nodiscard]] std::chrono::milliseconds age(TimePoint now) const noexcept;

private:
    ControlBlocker current_{ControlBlocker::Runnable};
    std::uint64_t transition_id_{};
    TimePoint changed_at_{};
};

[[nodiscard]] std::string_view blocker_name(ControlBlocker blocker) noexcept;

}  // namespace vf
