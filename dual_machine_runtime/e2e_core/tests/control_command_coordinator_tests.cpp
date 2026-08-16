#include "test_support.hpp"
#include "vf/host/application/control_command_coordinator.hpp"

#include <chrono>
#include <exception>
#include <iostream>

namespace {
using namespace std::chrono_literals;
using vf::ControlBlocker;
using vf::host::application::ControlCommandCoordinator;
using vf::host::application::ControlObservation;
using vf::host::domain::FrameIdentity;
using vf::test::expect;

void run() {
    const auto t0 = ControlCommandCoordinator::TimePoint{};
    ControlCommandCoordinator coordinator(10ms, t0);
    expect(coordinator.output_allowed(), "fresh coordinator is not runnable");

    expect(coordinator.begin(1, FrameIdentity{7, 10}, t0 + 20ms, t0 + 1ms) ==
               ControlObservation::CommandStarted,
           "command did not enter pending state");
    expect(!coordinator.output_allowed() && coordinator.blocker() == ControlBlocker::TicketPending,
           "ticket pending did not close output");
    expect(coordinator.on_ack(2, t0 + 2ms, t0 + 3ms) == ControlObservation::WrongAck,
           "wrong ACK completed command");
    expect(coordinator.on_ack(1, t0, t0 + 3ms) == ControlObservation::StaleAck,
           "pre-command ACK timestamp was accepted");
    expect(coordinator.on_ack(1, t0 + 4ms, t0 + 3ms) == ControlObservation::StaleAck,
           "future ACK timestamp was accepted");
    expect(coordinator.on_ack(1, t0 + 2ms, t0 + 3ms) == ControlObservation::AckAccepted,
           "correct ACK did not arm visibility gate");
    expect(coordinator.observe_frame(FrameIdentity{7, 10}, true, t0 + 4ms, t0 + 4ms) ==
               ControlObservation::VisibilityBlocked,
           "source frame itself opened post-ACK gate");
    expect(coordinator.observe_frame(FrameIdentity{7, 11}, true, t0 + 5ms, t0 + 5ms) ==
               ControlObservation::VisibilityConfirmed,
           "new visible content did not open post-ACK gate");
    expect(coordinator.output_allowed(), "confirmed visibility did not restore output");

    expect(coordinator.begin(2, FrameIdentity{7, 11}, t0 + 25ms, t0 + 5ms) ==
               ControlObservation::CommandStarted,
           "invalid-frame scenario did not start");
    expect(coordinator.on_ack(2, t0 + 6ms, t0 + 6ms) ==
               ControlObservation::AckAccepted,
           "invalid-frame scenario ACK was rejected");
    expect(coordinator.observe_frame(FrameIdentity{0, 0}, true, t0 + 7ms, t0 + 7ms) ==
               ControlObservation::RecoveryRequired,
           "invalid frame identity did not fail closed");
    expect(!coordinator.output_allowed(), "invalid frame reopened control output");
    coordinator.on_recovery_verified(t0 + 8ms);

    expect(coordinator.begin(3, FrameIdentity{7, 11}, t0 + 30ms, t0 + 6ms) ==
               ControlObservation::CommandStarted,
           "second command did not enter pending state");
    expect(coordinator.on_ack(3, t0 + 7ms, t0 + 7ms) ==
               ControlObservation::AckAccepted,
           "second command ACK was rejected");
    expect(coordinator.poll(t0 + 17ms) == ControlObservation::RecoveryRequired,
           "visibility deadline did not fail closed");
    expect(coordinator.blocker() == ControlBlocker::PostAckVisibilityTimeout &&
               !coordinator.output_allowed(),
           "timeout incorrectly auto-released output");
    coordinator.on_recovery_verified(t0 + 18ms);
    expect(coordinator.output_allowed(), "verified recovery did not reset coordinator");

    expect(coordinator.begin(4, FrameIdentity{8, 0}, t0 + 40ms, t0 + 19ms) ==
               ControlObservation::CommandStarted,
           "third command did not enter pending state");
    expect(coordinator.poll(t0 + 40ms) == ControlObservation::RecoveryRequired &&
               coordinator.blocker() == ControlBlocker::TicketDeadlineExpired,
           "ticket absolute deadline was not enforced");
    bool fail_closed_restart_rejected = false;
    try {
        static_cast<void>(coordinator.begin(5, FrameIdentity{8, 1},
                                            t0 + 60ms, t0 + 41ms));
    } catch (const std::invalid_argument&) {
        fail_closed_restart_rejected = true;
    }
    expect(fail_closed_restart_rejected,
           "new command bypassed required recovery after ticket timeout");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "CONTROL_COMMAND_COORDINATOR_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CONTROL_COMMAND_COORDINATOR_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
