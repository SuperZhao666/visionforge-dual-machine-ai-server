#pragma once

#include "vf/wire_protocol.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace vf {

struct DesktopBounds {
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t width{};
    std::int32_t height{};
};

struct CaptureRegion {
    std::int32_t left{};
    std::int32_t top{};
    std::int32_t width{};
    std::int32_t height{};

    [[nodiscard]] bool valid_within(const DesktopBounds& desktop) const noexcept;
};

enum class CaptureStatus { Frame, WaitTimeout, AccessLost, DeviceRemoved, Failed };

struct PublishSummary {
    std::size_t fragments_total{};
    std::size_t fragments_sent{};
    bool socket_error{};

    [[nodiscard]] bool complete() const noexcept {
        return !socket_error && fragments_total > 0 && fragments_sent == fragments_total;
    }
};

/**
 * IDR 请求与完整发布确认账本。
 *
 * <p>只有一个身份严格更新、且全部唯一分片都已成功交给传输适配器的 IDR，才能
 * 清除请求。旧 IDR 的迟到重复发布既不增加计数，也不能清除后来产生的新请求。</p>
 */
class IdrDeliveryTracker {
public:
    void request_idr() noexcept { idr_requested_ = true; }
    void on_access_unit(
        std::uint64_t stream_epoch,
        std::uint32_t frame_sequence,
        bool is_idr,
        const PublishSummary& summary) noexcept;

    [[nodiscard]] bool idr_requested() const noexcept { return idr_requested_; }
    [[nodiscard]] std::uint64_t delivered_idr_count() const noexcept {
        return delivered_idr_count_;
    }
    [[nodiscard]] std::optional<std::uint64_t> last_delivered_epoch() const noexcept {
        return last_delivered_epoch_;
    }
    [[nodiscard]] std::optional<std::uint32_t> last_delivered_sequence() const noexcept {
        return last_delivered_sequence_;
    }

private:
    [[nodiscard]] static bool identity_is_newer(
        std::uint64_t stream_epoch,
        std::uint32_t frame_sequence,
        const std::optional<std::uint64_t>& other_epoch,
        const std::optional<std::uint32_t>& other_sequence) noexcept;

    [[nodiscard]] static bool identity_is_same(
        std::uint64_t stream_epoch,
        std::uint32_t frame_sequence,
        const std::optional<std::uint64_t>& other_epoch,
        const std::optional<std::uint32_t>& other_sequence) noexcept;

    bool idr_requested_{true};
    std::uint64_t delivered_idr_count_{};
    std::optional<std::uint64_t> latest_observed_idr_epoch_;
    std::optional<std::uint32_t> latest_observed_idr_sequence_;
    std::optional<std::uint64_t> last_delivered_epoch_;
    std::optional<std::uint32_t> last_delivered_sequence_;
};

}  // namespace vf
