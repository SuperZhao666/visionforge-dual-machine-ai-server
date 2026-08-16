#pragma once

#include "vf/host/domain/frame_identity.hpp"
#include "vf/recovery.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace vf::host::application {

enum class ControlObservation {
    CommandStarted,
    AckAccepted,
    WrongAck,
    LateAck,
    StaleAck,
    VisibilityBlocked,
    VisibilityConfirmed,
    RecoveryRequired,
};

/**
 * 将精确 ticket、绝对 deadline 与 ACK 后画面可见性合并成单一控制状态机。
 * 任何迟到 ACK、错 ticket、旧 epoch 画面、未来时间戳或超时都 fail-closed。
 */
class ControlCommandCoordinator {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    ControlCommandCoordinator(
        std::chrono::milliseconds visibility_timeout,
        TimePoint now);

    [[nodiscard]] ControlObservation begin(
        std::uint64_t ticket_id,
        host::domain::FrameIdentity source_frame,
        TimePoint ticket_deadline,
        TimePoint now);

    [[nodiscard]] ControlObservation on_ack(
        std::uint64_t ticket_id,
        TimePoint acknowledged_at,
        TimePoint now);

    [[nodiscard]] ControlObservation observe_frame(
        host::domain::FrameIdentity frame,
        bool content_updated,
        TimePoint observed_at,
        TimePoint now);

    [[nodiscard]] ControlObservation poll(TimePoint now);

    /** 仅在外部已验证会话重建和新鲜 IDR 后调用，清除失败态并恢复输出资格。 */
    void on_recovery_verified(TimePoint now) noexcept;

    [[nodiscard]] bool output_allowed() const noexcept;
    [[nodiscard]] ControlBlocker blocker() const noexcept { return blockers_.current(); }
    [[nodiscard]] std::uint64_t transition_id() const noexcept { return blockers_.transition_id(); }
    [[nodiscard]] std::chrono::milliseconds blocker_age(TimePoint now) const noexcept {
        return blockers_.age(now);
    }

private:
    ExactTicket ticket_;
    PostAckVisibilityGate visibility_;
    BlockerTracker blockers_;
    std::optional<host::domain::FrameIdentity> source_frame_;
    std::optional<TimePoint> command_started_at_;
};

}  // namespace vf::host::application
