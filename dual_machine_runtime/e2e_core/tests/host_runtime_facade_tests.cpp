#include "test_support.hpp"
#include "vf/host/interfaces/host_runtime_facade.hpp"

#include <array>
#include <cstddef>
#include <exception>
#include <iostream>
#include <span>
#include <stdexcept>

namespace {
using vf::host::domain::FrameIdentity;
using vf::host::interfaces::DatagramSink;
using vf::host::interfaces::HostRuntimeFacade;
using vf::test::expect;

class FailingSink final : public DatagramSink {
public:
    explicit FailingSink(std::size_t fail_at) : fail_at_(fail_at) {}

    bool send(std::span<const std::uint8_t>) override {
        const bool success = calls_ != fail_at_;
        ++calls_;
        return success;
    }

    [[nodiscard]] std::size_t calls() const noexcept { return calls_; }

private:
    std::size_t fail_at_;
    std::size_t calls_{};
};

class ThrowingSink final : public DatagramSink {
public:
    bool send(std::span<const std::uint8_t>) override {
        throw std::runtime_error("synthetic socket failure");
    }
};

void run() {
    const std::array<std::uint8_t, 10> access_unit{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    HostRuntimeFacade facade({
        .max_datagram_bytes = 24,
        .max_fragments = 8,
        .max_access_unit_bytes = 32,
    });

    FailingSink partial(1);
    auto summary = facade.publish_access_unit(FrameIdentity{1, 0}, true, access_unit, partial);
    expect(!summary.complete() && facade.idr_requested(),
           "partial IDR incorrectly cleared recovery request");

    FailingSink complete(static_cast<std::size_t>(-1));
    summary = facade.publish_access_unit(FrameIdentity{1, 1}, true, access_unit, complete);
    expect(summary.complete() && !facade.idr_requested() &&
               facade.delivered_idr_count() == 1,
           "fully published IDR did not clear recovery request");

    facade.request_idr();
    FailingSink duplicate(static_cast<std::size_t>(-1));
    summary = facade.publish_access_unit(FrameIdentity{1, 1}, true, access_unit, duplicate);
    expect(summary.complete() && facade.idr_requested() &&
               facade.delivered_idr_count() == 1,
           "duplicate old IDR cleared a newer recovery request or double-counted");

    FailingSink newer(static_cast<std::size_t>(-1));
    summary = facade.publish_access_unit(FrameIdentity{1, 2}, true, access_unit, newer);
    expect(summary.complete() && !facade.idr_requested() &&
               facade.delivered_idr_count() == 2,
           "new complete IDR did not satisfy recovery exactly once");

    ThrowingSink throwing;
    summary = facade.publish_access_unit(FrameIdentity{1, 3}, true, access_unit, throwing);
    expect(!summary.complete() && facade.idr_requested(),
           "transport exception escaped or was reported as successful");

    FailingSink repeat_sink(static_cast<std::size_t>(-1));
    expect(facade.publish_repeat(FrameIdentity{1, 2}, repeat_sink),
           "repeat packet could not be published");
}
}  // namespace

int main() {
    try {
        run();
        std::cout << "HOST_RUNTIME_FACADE_TESTS_OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HOST_RUNTIME_FACADE_TESTS_FAILED: " << error.what() << '\n';
        return 1;
    }
}
