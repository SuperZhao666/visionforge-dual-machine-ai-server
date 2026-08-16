#pragma once

#include "vf/host/infrastructure/datagram_fragmenter.hpp"
#include "vf/host_pipeline.hpp"

#include <cstdint>
#include <mutex>
#include <span>

namespace vf::host::interfaces {

/** 传输端口：生产实现可封装 UDP socket；测试实现可精确注入第 N 个分片失败。 */
class DatagramSink {
public:
    virtual ~DatagramSink() = default;
    [[nodiscard]] virtual bool send(std::span<const std::uint8_t> datagram) = 0;
};

/**
 * Host 数据面组合门面。
 *
 * <p>分片与逐分片交付账本属于单次调用局部状态，因此多个编码线程不会共享一个
 * 可被覆盖的“当前帧”。只有 IDR 确认账本需要短临界区；外部 socket 调用绝不在
 * 该锁内执行，避免传输回调造成重入死锁。</p>
 */
class HostRuntimeFacade {
public:
    explicit HostRuntimeFacade(
        infrastructure::FragmentationConfig config = {})
        : fragmenter_(config) {}

    [[nodiscard]] PublishSummary publish_access_unit(
        domain::FrameIdentity identity,
        bool is_idr,
        std::span<const std::uint8_t> access_unit,
        DatagramSink& sink);

    [[nodiscard]] bool publish_repeat(
        domain::FrameIdentity identity,
        DatagramSink& sink) const;

    [[nodiscard]] bool idr_requested() const;
    [[nodiscard]] std::uint64_t delivered_idr_count() const;
    void request_idr();

private:
    infrastructure::DatagramFragmenter fragmenter_;
    mutable std::mutex tracker_mutex_;
    IdrDeliveryTracker idr_tracker_;
};

}  // namespace vf::host::interfaces
