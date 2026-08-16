#include "test_support.hpp"
#include "vf/host/domain/decoded_frame_metadata_ledger.hpp"

#include <chrono>
#include <exception>
#include <iostream>

namespace {
using vf::host::domain::DecodedFrameMetadata;
using vf::host::domain::DecodedFrameMetadataLedger;
using vf::host::domain::FrameDisposition;
using vf::host::domain::FrameIdentity;
using vf::test::expect;
using namespace std::chrono_literals;

DecodedFrameMetadata frame(
    std::uint64_t epoch,
    std::uint32_t sequence,
    std::uint64_t fingerprint,
    bool updated = true,
    bool repeat = false) {
    return {
        .identity = FrameIdentity{epoch, sequence},
        .content_fingerprint = fingerprint,
        .is_idr = sequence == 0,
        .is_repeat = repeat,
        .content_updated = updated,
        .decoded_at = std::chrono::steady_clock::time_point{} + 1ms,
    };
}

void run() {
    DecodedFrameMetadataLedger ledger;
    auto result = ledger.observe(frame(10, 0, 100));
    expect(result.disposition == FrameDisposition::EpochAdvanced &&
               result.accepted_for_inference && result.epoch_changed,
           "first fresh epoch was not accepted");

    result = ledger.observe(frame(10, 0, 100));
    expect(result.disposition == FrameDisposition::Duplicate &&
               !result.accepted_for_inference,
           "duplicate frame was treated as fresh");

    result = ledger.observe(frame(10, 0, 101));
    expect(result.disposition == FrameDisposition::SequenceConflict,
           "same sequence with different content was not rejected");

    result = ledger.observe(frame(10, 1, 100, false, true));
    expect(result.disposition == FrameDisposition::NotFresh &&
               !result.accepted_for_inference,
           "repeat frame was treated as new content");

    result = ledger.observe(frame(11, 0, 200));
    expect(result.disposition == FrameDisposition::EpochAdvanced,
           "new epoch was not selected");

    result = ledger.observe(frame(10, 99, 999));
    expect(result.disposition == FrameDisposition::RetiredEpoch,
           "retired epoch reclaimed the receiver");

    // 即使经历许多后续 epoch，更低 epoch 仍由高水位永久拒绝。
    for (std::uint64_t epoch = 12; epoch < 100; ++epoch) {
        static_cast<void>(ledger.observe(frame(epoch, 0, epoch)));
    }
    result = ledger.observe(frame(10, 100, 1000));
    expect(result.disposition == FrameDisposition::RetiredEpoch,
           "old epoch returned after retirement history pressure");

    result = ledger.observe(frame(101, 1, 300));
    expect(result.disposition == FrameDisposition::EpochRequiresIdr &&
               ledger.current_epoch() == 99,
           "new epoch predictive frame stole decoder ownership");
    result = ledger.observe(frame(101, 0, 301));
    expect(result.disposition == FrameDisposition::EpochAdvanced &&
               ledger.current_epoch() == 101,
           "new epoch IDR did not establish decoder ownership");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "DECODED_FRAME_METADATA_LEDGER_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "DECODED_FRAME_METADATA_LEDGER_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
