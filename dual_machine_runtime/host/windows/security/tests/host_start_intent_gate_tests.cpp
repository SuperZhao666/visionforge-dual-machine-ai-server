#include "vfdual/host_start_intent_gate.hpp"

#include <cstdlib>
#include <iostream>

#define VFDUAL_TEST_REQUIRE(condition)                                    \
    do {                                                                  \
        if (!(condition)) {                                               \
            std::cerr << "requirement failed: " #condition << '\n';       \
            return EXIT_FAILURE;                                          \
        }                                                                 \
    } while (false)

int main() {
    vfdual::HostStartIntentGate gate;
    VFDUAL_TEST_REQUIRE(!gate.pending());
    VFDUAL_TEST_REQUIRE(!gate.claim().has_value());

    const std::uint64_t first = gate.offer();
    VFDUAL_TEST_REQUIRE(first != 0U);
    VFDUAL_TEST_REQUIRE(gate.offer() == first);
    VFDUAL_TEST_REQUIRE(gate.pending());
    VFDUAL_TEST_REQUIRE(!gate.claimed());

    const auto claimed = gate.claim();
    VFDUAL_TEST_REQUIRE(claimed.has_value());
    VFDUAL_TEST_REQUIRE(*claimed == first);
    VFDUAL_TEST_REQUIRE(gate.claimed());
    VFDUAL_TEST_REQUIRE(!gate.claim().has_value());
    VFDUAL_TEST_REQUIRE(gate.offer() == first);

    gate.authenticated_channel_closed();
    VFDUAL_TEST_REQUIRE(gate.pending());
    VFDUAL_TEST_REQUIRE(!gate.claimed());
    const auto recovered = gate.claim();
    VFDUAL_TEST_REQUIRE(recovered.has_value());
    VFDUAL_TEST_REQUIRE(*recovered != first);

    gate.complete();
    VFDUAL_TEST_REQUIRE(!gate.pending());
    VFDUAL_TEST_REQUIRE(!gate.claimed());
    VFDUAL_TEST_REQUIRE(!gate.claim().has_value());

    const std::uint64_t next = gate.offer();
    VFDUAL_TEST_REQUIRE(next != 0U);
    VFDUAL_TEST_REQUIRE(next != *recovered);
    gate.cancel();
    VFDUAL_TEST_REQUIRE(!gate.pending());

    std::cout << "host start intent gate tests passed\n";
    return EXIT_SUCCESS;
}
