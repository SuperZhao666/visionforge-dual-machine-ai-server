#include "vfdual/host_cat6_protocol.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    const auto ready = vfdual::parse_cat6_ready_message(
        "VF_CAT6_READY_V1|10.57.23.2|42");
    CHECK(ready.has_value());
    CHECK(ready->ipv4 == "10.57.23.2" && ready->sequence == 42U);
    CHECK(!vfdual::parse_cat6_ready_message("VF_CAT6_READY_V1|10.57.23.3|2|extra"));
    CHECK(!vfdual::parse_cat6_ready_message("VF_OTHER_READY_V1|10.57.23.2|2"));

    auto probe = vfdual::build_cat6_probe(123U, 1200U);
    CHECK(probe.size() == 1200U);
    const std::string ack_header = "VF_CAT6_PROBE_ACK_V1|123|";
    std::copy(ack_header.begin(), ack_header.end(), probe.begin());
    CHECK(vfdual::parse_cat6_probe_ack(probe) == 123U);
    probe[0] = 'X';
    CHECK(!vfdual::parse_cat6_probe_ack(probe));
    return 0;
}
