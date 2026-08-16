#pragma once

#include "vfdual/protocol.hpp"

#include <cstdint>
#include <optional>

namespace vfdual {

enum class VideoPublicationStage : std::uint8_t {
  none,
  validation,
  authorization,
  encoding,
  socket_send,
  complete,
};

struct VideoPublicationReceipt final {
  VideoFrameIdentity identity{};
  std::uint16_t expected_fragments{};
  std::uint16_t fragments_sent{};
  bool keyframe{};
  bool repeated_content{};
  VideoPublicationStage stage{VideoPublicationStage::none};

  [[nodiscard]] constexpr bool completely_published() const noexcept {
    return identity.valid() && expected_fragments != 0U &&
        fragments_sent == expected_fragments &&
        stage == VideoPublicationStage::complete;
  }
};

struct VideoDeliveryDecision final {
  bool publication_complete{};
  bool reference_chain_established{};
  bool idr_request_consumed{};
  bool recovery_still_required{};
};

/**
 * Commits reference-chain state only after a complete, real IDR publication.
 * An encoder success or a partial UDP send is deliberately insufficient.
 */
class VideoDeliveryLedger final {
 public:
  void request_idr(std::uint64_t generation) noexcept {
    if (generation > requested_idr_generation_) {
      requested_idr_generation_ = generation;
    }
  }

  [[nodiscard]] std::uint64_t requested_idr_generation() const noexcept {
    return requested_idr_generation_;
  }

  [[nodiscard]] std::uint64_t consumed_idr_generation() const noexcept {
    return consumed_idr_generation_;
  }

  [[nodiscard]] bool recovery_required() const noexcept {
    return requested_idr_generation_ > consumed_idr_generation_;
  }

  [[nodiscard]] std::optional<VideoFrameIdentity> last_complete_frame() const noexcept {
    return last_complete_frame_;
  }

  [[nodiscard]] std::optional<VideoFrameIdentity> last_complete_idr() const noexcept {
    return last_complete_idr_;
  }

  [[nodiscard]] VideoDeliveryDecision record(
      const VideoPublicationReceipt& receipt,
      std::uint64_t encoded_for_idr_generation = 0U) noexcept {
    const bool complete = receipt.completely_published();
    if (complete) last_complete_frame_ = receipt.identity;

    const bool real_complete_idr = complete && receipt.keyframe &&
        !receipt.repeated_content;
    if (real_complete_idr) last_complete_idr_ = receipt.identity;

    bool consumed{};
    if (real_complete_idr && encoded_for_idr_generation != 0U &&
        encoded_for_idr_generation == requested_idr_generation_ &&
        encoded_for_idr_generation > consumed_idr_generation_) {
      consumed_idr_generation_ = encoded_for_idr_generation;
      consumed = true;
    }

    return VideoDeliveryDecision{
        complete,
        real_complete_idr,
        consumed,
        recovery_required(),
    };
  }

 private:
  std::uint64_t requested_idr_generation_{};
  std::uint64_t consumed_idr_generation_{};
  std::optional<VideoFrameIdentity> last_complete_frame_;
  std::optional<VideoFrameIdentity> last_complete_idr_;
};

}  // namespace vfdual
