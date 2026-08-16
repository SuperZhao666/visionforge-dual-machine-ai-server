#include "test_support.hpp"
#include "vf/host/interfaces/host_runtime_composition_root.hpp"
#include "vf/reassembly.hpp"
#include "vf/wire_protocol.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <iostream>
#include <span>
#include <vector>

namespace {
using namespace std::chrono_literals;
using vf::AccessUnitReassembler;
using vf::CaptureStatus;
using vf::IngestCode;
using vf::PacketKind;
using vf::parse_wire_header;
using vf::host::domain::PipelineBlocker;
using vf::host::interfaces::DatagramSink;
using vf::host::interfaces::HostRuntimeCode;
using vf::host::interfaces::HostRuntimeCompositionRoot;
using vf::test::expect;

class CollectingSink final : public DatagramSink {
public:
    bool send(std::span<const std::uint8_t> datagram) override {
        datagrams.emplace_back(datagram.begin(), datagram.end());
        return true;
    }
    std::vector<std::vector<std::uint8_t>> datagrams;
};


class ObservingSink final : public DatagramSink {
public:
    explicit ObservingSink(HostRuntimeCompositionRoot& runtime) : runtime_(runtime) {}
    bool send(std::span<const std::uint8_t> datagram) override {
        // 生产 socket/遥测适配器可能同步查询状态；组合根不得在外部调用期间持有状态锁。
        static_cast<void>(runtime_.status(HostRuntimeCompositionRoot::TimePoint{}));
        static_cast<void>(runtime_.last_published_frame());
        datagrams.emplace_back(datagram.begin(), datagram.end());
        return true;
    }
    std::vector<std::vector<std::uint8_t>> datagrams;
private:
    HostRuntimeCompositionRoot& runtime_;
};

class FailingSink final : public DatagramSink {
public:
    explicit FailingSink(std::size_t fail_at) : fail_at_(fail_at) {}
    bool send(std::span<const std::uint8_t>) override {
        const bool ok = calls_ != fail_at_;
        ++calls_;
        return ok;
    }
private:
    std::size_t fail_at_{};
    std::size_t calls_{};
};

void run() {
    const auto t0 = HostRuntimeCompositionRoot::TimePoint{};
    HostRuntimeCompositionRoot runtime(
        12, t0,
        {.max_datagram_bytes = 24, .max_fragments = 32, .max_access_unit_bytes = 128});

    CollectingSink empty_sink;
    auto result = runtime.on_capture(CaptureStatus::WaitTimeout, {}, false, empty_sink, t0 + 1ms);
    expect(result.code == HostRuntimeCode::WaitingFirstFrame && empty_sink.datagrams.empty(),
           "timeout before first frame fabricated a repeat packet");

    const std::array<std::uint8_t, 10> idr{0, 0, 0, 1, 0x65, 1, 2, 3, 4, 5};
    CollectingSink idr_sink;
    result = runtime.on_capture(CaptureStatus::Frame, idr, true, idr_sink, t0 + 2ms);
    expect(result.code == HostRuntimeCode::FramePublished && result.publish.complete(),
           "complete IDR was not published");
    expect(!runtime.idr_requested() && result.status.blocker == PipelineBlocker::Runnable,
           "complete IDR did not clear startup recovery request");

    AccessUnitReassembler receiver({.max_inflight_frames = 8,
                                    .max_total_bytes = 4096,
                                    .max_access_unit_bytes = 1024,
                                    .frame_timeout = 100ms,
                                    .retired_epoch_capacity = 1});
    std::vector<std::uint8_t> rebuilt;
    for (const auto& datagram : idr_sink.datagrams) {
        const auto header = parse_wire_header(std::span(datagram).first(vf::kWireHeaderSize));
        expect(header.has_value(), "Host emitted malformed wire header");
        const auto ingest = receiver.ingest(
            *header,
            std::span(datagram).subspan(vf::kWireHeaderSize),
            t0 + 2ms);
        if (ingest.code == IngestCode::Complete) {
            expect(ingest.requires_epoch_commit,
                   "initial Host IDR did not require receiver epoch confirmation");
            rebuilt = ingest.access_unit;
            expect(receiver.commit_candidate_epoch(ingest.stream_epoch),
                   "validated Host IDR candidate did not commit");
        }
    }
    expect(rebuilt == std::vector<std::uint8_t>(idr.begin(), idr.end()),
           "Host datagrams did not reconstruct byte-for-byte at receiver");

    CollectingSink repeat_sink;
    result = runtime.on_capture(CaptureStatus::WaitTimeout, {}, false, repeat_sink, t0 + 3ms);
    expect(result.code == HostRuntimeCode::RepeatPublished && repeat_sink.datagrams.size() == 1,
           "capture timeout did not publish exactly one repeat after first frame");
    const auto repeat_header = parse_wire_header(repeat_sink.datagrams.front());
    expect(repeat_header && repeat_header->kind == PacketKind::Repeat &&
               repeat_header->stream_epoch == 12 && repeat_header->frame_sequence == 0,
           "repeat did not reference the last published frame identity");
    expect(runtime.idr_requested(), "repeat did not preserve/request a fresh IDR");

    const std::array<std::uint8_t, 6> predicted{0, 0, 0, 1, 0x41, 9};
    CollectingSink p_sink;
    result = runtime.on_capture(CaptureStatus::Frame, predicted, false, p_sink, t0 + 4ms);
    expect(result.code == HostRuntimeCode::FramePublished && runtime.idr_requested() &&
               result.status.blocker == PipelineBlocker::WaitingCompleteIdrPublish,
           "predictive frame incorrectly satisfied an IDR recovery request");

    CollectingSink recovered_idr_sink;
    result = runtime.on_capture(CaptureStatus::Frame, idr, true, recovered_idr_sink, t0 + 5ms);
    expect(result.code == HostRuntimeCode::FramePublished && !runtime.idr_requested() &&
               result.identity->frame_sequence == 2,
           "fresh complete IDR did not recover stream in order");
    expect(!runtime.mark_app_decoded({12, 99}),
           "APP reported an impossible future decoded frame");
    expect(runtime.mark_app_decoded({12, 2}),
           "APP decoded identity matching a published frame was rejected");
    expect(runtime.mark_app_decoded({12, 2}),
           "idempotent APP decoded callback was rejected");
    expect(!runtime.mark_app_decoded({12, 1}),
           "stale APP decoded callback regressed the decoded high-water mark");
    expect(!runtime.mark_app_decoded({11, 99}),
           "retired APP epoch callback was accepted");

    ObservingSink observing(runtime);
    result = runtime.on_capture(CaptureStatus::Frame, predicted, false, observing, t0 + 5ms + 1us);
    expect(result.code == HostRuntimeCode::FramePublished && !observing.datagrams.empty(),
           "state-observing transport callback deadlocked or failed publication");

    FailingSink failing(1);
    result = runtime.on_capture(CaptureStatus::Frame, idr, true, failing, t0 + 6ms);
    expect(result.code == HostRuntimeCode::FramePublishFailed && runtime.idr_requested() &&
               result.status.blocker == PipelineBlocker::TransportFailure,
           "partial socket publication was reported as successful");
    expect(runtime.last_published_frame()->frame_sequence == 3,
           "failed publication advanced last-published identity");

    CollectingSink ignored;
    result = runtime.on_capture(CaptureStatus::AccessLost, {}, false, ignored, t0 + 7ms);
    expect(result.code == HostRuntimeCode::RecreateDuplication &&
               result.status.blocker == PipelineBlocker::CaptureAccessLost,
           "DXGI access-lost was confused with ordinary timeout");

    runtime.rotate_to_reserved_epoch(13, t0 + 8ms);
    expect(runtime.idr_requested() && !runtime.last_published_frame() &&
               runtime.status(t0 + 8ms).blocker ==
                   PipelineBlocker::WaitingCompleteIdrPublish,
           "persisted epoch rotation did not reset publication state");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "HOST_RUNTIME_COMPOSITION_ROOT_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HOST_RUNTIME_COMPOSITION_ROOT_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
