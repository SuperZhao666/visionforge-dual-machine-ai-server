#include "vf/host/application/video_delivery_ledger.hpp"

#include <algorithm>
#include <stdexcept>

namespace vf::host::application {

void VideoDeliveryLedger::begin(
    host::domain::FrameIdentity identity,
    bool is_idr,
    std::uint16_t fragment_count) {
    if (active_ && !terminal_) {
        throw std::logic_error("a video delivery is already active");
    }
    if (!identity.valid() || fragment_count == 0 || fragment_count > kMaxFragments) {
        throw std::invalid_argument("invalid video delivery identity or fragment count");
    }
    identity_ = identity;
    active_ = true;
    terminal_ = false;
    is_idr_ = is_idr;
    socket_error_ = false;
    terminal_outcome_ = DeliveryOutcome::InProgress;
    sent_.assign(fragment_count, false);
    sent_count_ = 0;
}

DeliveryOutcome VideoDeliveryLedger::record_fragment(
    host::domain::FrameIdentity identity,
    std::uint16_t fragment_index,
    bool sent) noexcept {
    if (!active_ || terminal_) {
        return DeliveryOutcome::StaleTerminal;
    }
    if (identity != identity_) {
        return DeliveryOutcome::WrongFrame;
    }
    if (socket_error_) {
        // 第一次发送失败后，这个 access unit 已不可能再成为完整交付。后续异步
        // 回调只能观察失败，不能补发并把它重新变成 Complete。
        return DeliveryOutcome::Failed;
    }
    if (fragment_index >= sent_.size()) {
        return DeliveryOutcome::InvalidFragment;
    }
    if (!sent) {
        socket_error_ = true;
        return DeliveryOutcome::Failed;
    }
    if (sent_[fragment_index]) {
        return DeliveryOutcome::DuplicateFragment;
    }
    sent_[fragment_index] = true;
    ++sent_count_;
    return sent_count_ == sent_.size() ? DeliveryOutcome::Complete
                                       : DeliveryOutcome::InProgress;
}

DeliverySnapshot VideoDeliveryLedger::finalize(host::domain::FrameIdentity identity) noexcept {
    if (!active_ || terminal_) {
        return {.identity = identity, .terminal = true,
                .outcome = DeliveryOutcome::StaleTerminal};
    }
    if (identity != identity_) {
        return {.identity = identity_, .is_idr = is_idr_,
                .fragments_total = sent_.size(), .fragments_sent = sent_count_,
                .socket_error = socket_error_, .terminal = false,
                .outcome = DeliveryOutcome::WrongFrame};
    }
    terminal_ = true;
    terminal_outcome_ = !socket_error_ && sent_count_ == sent_.size()
        ? DeliveryOutcome::Complete
        : DeliveryOutcome::Failed;
    return *snapshot();
}

std::optional<DeliverySnapshot> VideoDeliveryLedger::snapshot() const noexcept {
    if (!active_) {
        return std::nullopt;
    }
    return DeliverySnapshot{
        .identity = identity_,
        .is_idr = is_idr_,
        .fragments_total = sent_.size(),
        .fragments_sent = sent_count_,
        .socket_error = socket_error_,
        .terminal = terminal_,
        .outcome = terminal_ ? terminal_outcome_ : DeliveryOutcome::InProgress,
    };
}

void VideoDeliveryLedger::reset() noexcept {
    identity_ = {};
    active_ = false;
    terminal_ = false;
    is_idr_ = false;
    socket_error_ = false;
    terminal_outcome_ = DeliveryOutcome::InProgress;
    sent_.clear();
    sent_count_ = 0;
}

}  // namespace vf::host::application
