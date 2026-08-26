#pragma once

#include <cstdint>
#include <optional>

namespace vfdual {

/**
 * One-shot, process-local proof that the Host operator requested a new start.
 *
 * This gate never grants data-plane access.  It only lets an authenticated
 * control session claim one pending UI start so Android can request the real
 * server lease without waiting for forbidden pre-lease video.  A claim is
 * completed only after the raw lease commit succeeds.  If the authenticated
 * channel disappears first, the pending intent is reissued with a new token
 * so an interrupted, unbilled attempt can recover without replaying the old
 * claim.
 */
class HostStartIntentGate final {
public:
    /** Creates one pending intent, or returns the already-pending token. */
    [[nodiscard]] std::uint64_t offer() noexcept {
        if (pending_token_ == 0U) {
            pending_token_ = allocate_token();
            claimed_ = false;
        }
        return pending_token_;
    }

    /** Claims the current intent exactly once on an authenticated channel. */
    [[nodiscard]] std::optional<std::uint64_t> claim() noexcept {
        if (pending_token_ == 0U || claimed_) return std::nullopt;
        claimed_ = true;
        return pending_token_;
    }

    /** Burns a failed channel's claimed token but preserves operator intent. */
    void authenticated_channel_closed() noexcept {
        if (pending_token_ == 0U || !claimed_) return;
        pending_token_ = allocate_token();
        claimed_ = false;
    }

    /** Consumes the intent after lease commit or an authorized Host start. */
    void complete() noexcept {
        pending_token_ = 0U;
        claimed_ = false;
    }

    /** Cancels the operator request (Stop/shutdown). */
    void cancel() noexcept { complete(); }

    [[nodiscard]] bool pending() const noexcept {
        return pending_token_ != 0U;
    }

    [[nodiscard]] bool claimed() const noexcept { return claimed_; }

private:
    [[nodiscard]] std::uint64_t allocate_token() noexcept {
        std::uint64_t token = next_token_++;
        if (token == 0U) token = next_token_++;
        if (next_token_ == 0U) next_token_ = 1U;
        return token;
    }

    std::uint64_t next_token_{1U};
    std::uint64_t pending_token_{};
    bool claimed_{};
};

}  // namespace vfdual
