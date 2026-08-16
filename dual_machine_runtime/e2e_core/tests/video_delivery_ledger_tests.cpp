#include "test_support.hpp"
#include "vf/host/application/video_delivery_ledger.hpp"

#include <exception>
#include <iostream>

namespace {
using vf::host::application::DeliveryOutcome;
using vf::host::application::VideoDeliveryLedger;
using vf::host::domain::FrameIdentity;
using vf::test::expect;

void complete_delivery_requires_every_unique_fragment() {
    VideoDeliveryLedger ledger;
    const FrameIdentity frame{7, 3};
    ledger.begin(frame, true, 3);
    expect(ledger.record_fragment(frame, 0, true) == DeliveryOutcome::InProgress,
           "first fragment terminated delivery");
    expect(ledger.record_fragment(frame, 0, true) == DeliveryOutcome::DuplicateFragment,
           "duplicate fragment was double-counted");
    expect(ledger.record_fragment(frame, 1, true) == DeliveryOutcome::InProgress,
           "second fragment terminated delivery");
    auto partial = ledger.finalize(frame);
    expect(partial.outcome == DeliveryOutcome::Failed && !partial.fully_published(),
           "partial IDR was reported as fully published");
    expect(ledger.record_fragment(frame, 2, true) == DeliveryOutcome::StaleTerminal,
           "late fragment changed a terminal delivery");
}

void socket_failure_is_terminally_visible() {
    VideoDeliveryLedger ledger;
    const FrameIdentity frame{8, 1};
    ledger.begin(frame, false, 2);
    expect(ledger.record_fragment(frame, 0, true) == DeliveryOutcome::InProgress,
           "first fragment not accepted");
    expect(ledger.record_fragment(frame, 1, false) == DeliveryOutcome::Failed,
           "socket failure not recorded");
    const auto failed = ledger.finalize(frame);
    expect(failed.socket_error && failed.outcome == DeliveryOutcome::Failed,
           "socket failure disappeared at finalize");
}

void exact_frame_identity_is_enforced() {
    VideoDeliveryLedger ledger;
    const FrameIdentity active{9, 2};
    ledger.begin(active, true, 1);
    expect(ledger.record_fragment(FrameIdentity{9, 3}, 0, true) == DeliveryOutcome::WrongFrame,
           "wrong frame callback completed active delivery");
    expect(ledger.record_fragment(active, 0, true) == DeliveryOutcome::Complete,
           "correct frame could not complete");
    const auto complete = ledger.finalize(active);
    expect(complete.fully_published(), "complete delivery not recognized");
}
}  // namespace

int main() {
    try {
        complete_delivery_requires_every_unique_fragment();
        socket_failure_is_terminally_visible();
        exact_frame_identity_is_enforced();
        std::cout << "VIDEO_DELIVERY_LEDGER_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "VIDEO_DELIVERY_LEDGER_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
