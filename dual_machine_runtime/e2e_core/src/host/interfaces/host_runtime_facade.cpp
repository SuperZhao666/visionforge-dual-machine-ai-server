#include "vf/host/interfaces/host_runtime_facade.hpp"

#include "vf/host/application/video_delivery_ledger.hpp"

namespace vf::host::interfaces {

PublishSummary HostRuntimeFacade::publish_access_unit(
    domain::FrameIdentity identity,
    bool is_idr,
    std::span<const std::uint8_t> access_unit,
    DatagramSink& sink) {
    const auto datagrams = fragmenter_.fragment(identity, access_unit);
    application::VideoDeliveryLedger delivery;
    delivery.begin(identity, is_idr, static_cast<std::uint16_t>(datagrams.size()));

    for (std::size_t index = 0; index < datagrams.size(); ++index) {
        bool sent = false;
        try {
            sent = sink.send(datagrams[index]);
        } catch (...) {
            // socket/adapter 异常属于本帧交付失败，不允许异常越过组合根导致线程退出，
            // 更不能让 IDR 请求在没有完整发布的情况下被清除。
            sent = false;
        }
        static_cast<void>(delivery.record_fragment(
            identity, static_cast<std::uint16_t>(index), sent));
        if (!sent) {
            break;
        }
    }

    const auto terminal = delivery.finalize(identity);
    const PublishSummary summary{
        .fragments_total = terminal.fragments_total,
        .fragments_sent = terminal.fragments_sent,
        .socket_error = terminal.socket_error || !terminal.fully_published(),
    };
    {
        std::scoped_lock lock(tracker_mutex_);
        idr_tracker_.on_access_unit(
            identity.stream_epoch, identity.frame_sequence, is_idr, summary);
    }
    return summary;
}

bool HostRuntimeFacade::publish_repeat(
    domain::FrameIdentity identity,
    DatagramSink& sink) const {
    const auto datagram = fragmenter_.repeat(identity);
    try {
        return sink.send(datagram);
    } catch (...) {
        return false;
    }
}

bool HostRuntimeFacade::idr_requested() const {
    std::scoped_lock lock(tracker_mutex_);
    return idr_tracker_.idr_requested();
}

std::uint64_t HostRuntimeFacade::delivered_idr_count() const {
    std::scoped_lock lock(tracker_mutex_);
    return idr_tracker_.delivered_idr_count();
}

void HostRuntimeFacade::request_idr() {
    std::scoped_lock lock(tracker_mutex_);
    idr_tracker_.request_idr();
}

}  // namespace vf::host::interfaces
