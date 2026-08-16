#pragma once

#include "vf/host/domain/frame_identity.hpp"
#include "vf/wire_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace vf::host::application {

enum class DeliveryOutcome {
    InProgress,
    Complete,
    Failed,
    DuplicateFragment,
    WrongFrame,
    InvalidFragment,
    StaleTerminal,
};

struct DeliverySnapshot {
    host::domain::FrameIdentity identity{};
    bool is_idr{};
    std::size_t fragments_total{};
    std::size_t fragments_sent{};
    bool socket_error{};
    bool terminal{};
    DeliveryOutcome outcome{DeliveryOutcome::InProgress};

    [[nodiscard]] bool fully_published() const noexcept {
        return terminal && outcome == DeliveryOutcome::Complete && !socket_error &&
               fragments_total > 0 && fragments_sent == fragments_total;
    }
};

/**
 * 一次访问单元发布的精确账本。
 *
 * ACK 的对象不是“编码器产生过 IDR”，而是“这个 IDR 的每个唯一分片都成功交给
 * 传输适配器”。任何 socket 失败、漏分片、错帧回调都不能把 IDR 请求错误清除。
 */
class VideoDeliveryLedger {
public:
    void begin(host::domain::FrameIdentity identity, bool is_idr, std::uint16_t fragment_count);
    [[nodiscard]] DeliveryOutcome record_fragment(
        host::domain::FrameIdentity identity,
        std::uint16_t fragment_index,
        bool sent) noexcept;
    [[nodiscard]] DeliverySnapshot finalize(host::domain::FrameIdentity identity) noexcept;
    [[nodiscard]] std::optional<DeliverySnapshot> snapshot() const noexcept;
    void reset() noexcept;

private:
    host::domain::FrameIdentity identity_{};
    bool active_{};
    bool terminal_{};
    bool is_idr_{};
    bool socket_error_{};
    DeliveryOutcome terminal_outcome_{DeliveryOutcome::InProgress};
    std::vector<bool> sent_;
    std::size_t sent_count_{};
};

}  // namespace vf::host::application
