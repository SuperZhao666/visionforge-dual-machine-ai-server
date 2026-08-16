#include "test_support.hpp"
#include "vf/host/infrastructure/datagram_fragmenter.hpp"
#include "vf/reassembly.hpp"
#include "vf/video_transport_contract.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <span>
#include <vector>

namespace {
using vf::AccessUnitReassembler;
using vf::IngestCode;
using vf::PacketKind;
using vf::WireHeader;
using vf::host::domain::FrameIdentity;
using vf::host::infrastructure::DatagramFragmenter;
using vf::host::infrastructure::FragmentationConfig;
using vf::test::expect;

void contract_and_round_trip() {
    const WireHeader valid{PacketKind::Data, 1, 0, 0, 1};
    expect(vf::transport::validate(valid) == vf::transport::ContractViolation::None,
           "valid header rejected by transport contract");
    expect(vf::transport::requires_epoch_rollover(0xffff'ffffU),
           "terminal sequence did not require epoch rollover");
    expect(vf::transport::validate(WireHeader{PacketKind::Repeat, 1, 0, 0, 2}) ==
               vf::transport::ContractViolation::RepeatShapeInvalid,
           "invalid repeat shape was accepted");

    DatagramFragmenter fragmenter(FragmentationConfig{
        .max_datagram_bytes = 24,
        .max_fragments = 8,
        .max_access_unit_bytes = 32,
    });
    const std::array<std::uint8_t, 10> access_unit{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const auto datagrams = fragmenter.fragment(FrameIdentity{5, 6}, access_unit);
    expect(datagrams.size() == 3, "unexpected fragmentation count");

    AccessUnitReassembler receiver({.max_inflight_frames = 4,
                                    .max_total_bytes = 1024,
                                    .max_access_unit_bytes = 128,
                                    .frame_timeout = std::chrono::milliseconds(100),
                                    .retired_epoch_capacity = 2});
    auto now = AccessUnitReassembler::TimePoint{};
    std::vector<std::uint8_t> rebuilt;
    for (const auto& datagram : datagrams) {
        const auto header = vf::parse_wire_header(datagram);
        expect(header.has_value(), "fragmenter emitted unparsable header");
        const auto payload = std::span<const std::uint8_t>{datagram}.subspan(vf::kWireHeaderSize);
        auto result = receiver.ingest(*header, payload, now);
        if (result.code == IngestCode::Complete) {
            expect(result.requires_epoch_commit,
                   "initial round-trip did not require candidate epoch confirmation");
            rebuilt = std::move(result.access_unit);
            expect(receiver.commit_candidate_epoch(result.stream_epoch),
                   "round-trip candidate epoch did not commit");
        } else {
            expect(result.code == IngestCode::Accepted,
                   "receiver rejected a valid intermediate fragment");
        }
        now += std::chrono::milliseconds(1);
    }
    expect(rebuilt == std::vector<std::uint8_t>(access_unit.begin(), access_unit.end()),
           "host fragmenter and receiver reassembler did not round-trip");

    // 高水位检查不依赖 retired ring 容量。
    const std::array<std::uint8_t, 1> byte{42};
    for (std::uint64_t epoch = 6; epoch < 20; ++epoch) {
        auto result = receiver.ingest({PacketKind::Data, epoch, 0, 0, 1}, byte, now);
        expect(result.code == IngestCode::Complete && result.requires_epoch_commit,
               "new epoch was not accepted as a candidate");
        expect(receiver.commit_candidate_epoch(epoch), "new epoch candidate did not commit");
        now += std::chrono::milliseconds(1);
    }
    const auto stale = receiver.ingest({PacketKind::Data, 5, 99, 0, 1}, byte, now);
    expect(stale.code == IngestCode::RetiredEpoch,
           "old epoch reclaimed receiver after retirement pressure");
}
}  // namespace

int main() {
    try {
        contract_and_round_trip();
        std::cout << "VIDEO_TRANSPORT_CONTRACT_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "VIDEO_TRANSPORT_CONTRACT_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
