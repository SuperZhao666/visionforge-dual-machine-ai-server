#include "vfdual/host_outbound_rate_tracker.hpp"

#include <cstdlib>
#include <iostream>
#include <cmath>

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
    vfdual::HostOutboundRateTracker tracker;
    CHECK(!tracker.observe(0, 1'000).has_value());
    const auto first_rate = tracker.observe(60, 2'000);
    CHECK(first_rate.has_value() && std::fabs(*first_rate - 60.0) < 0.001);
    const auto cached_rate = tracker.observe(84, 2'400);
    CHECK(cached_rate.has_value() && std::fabs(*cached_rate - 60.0) < 0.001);
    const auto next_rate = tracker.observe(120, 3'000);
    CHECK(next_rate.has_value() && std::fabs(*next_rate - 60.0) < 0.001);
    CHECK(!tracker.observe(4, 4'000).has_value());
    const auto reset_rate = tracker.observe(34, 5'000);
    CHECK(reset_rate.has_value() && std::fabs(*reset_rate - 30.0) < 0.001);
    tracker.reset();
    CHECK(!tracker.observe(0, 6'000).has_value());
    return 0;
}
