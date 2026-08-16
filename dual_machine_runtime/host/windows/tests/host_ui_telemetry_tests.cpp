#include "vfdual/host_idle_ui_state.hpp"
#include "vfdual/host_ui_phase.hpp"
#include "vfdual/host_ui_telemetry.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace {

bool near(double left, double right) {
    return std::abs(left - right) < 0.001;
}

bool contains(std::wstring_view value, std::wstring_view needle) {
    return value.find(needle) != std::wstring_view::npos;
}

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }
    std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", expression, file, line);
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

void require_idle_contract(const vfdual::HostIdleUiText& text) {
    VFDUAL_TEST_REQUIRE(!text.ready_state.empty());
    VFDUAL_TEST_REQUIRE(!text.ready_detail.empty());
    VFDUAL_TEST_REQUIRE(!text.hero.empty());
    VFDUAL_TEST_REQUIRE(!text.encoder.empty());
    VFDUAL_TEST_REQUIRE(!text.phone.empty());
    VFDUAL_TEST_REQUIRE(!text.link.empty());
    VFDUAL_TEST_REQUIRE(!text.topology_host.empty());
    VFDUAL_TEST_REQUIRE(!text.topology_link.empty());
    VFDUAL_TEST_REQUIRE(!text.topology_mobile.empty());
    VFDUAL_TEST_REQUIRE(!contains(text.encoder, L"\u6b63\u5728\u68c0\u6d4b"));
    VFDUAL_TEST_REQUIRE(!contains(text.ready_state, L"\u6b63\u5728\u4f20\u8f93"));
    VFDUAL_TEST_REQUIRE(!contains(text.ready_detail, L"\u4f20\u8f93\u4e2d"));
    VFDUAL_TEST_REQUIRE(!contains(text.link, L"\u4f20\u8f93\u4e2d"));
}

vfdual::host::application::HostRuntimeReadModel metrics(
    std::uint64_t published, std::uint64_t capture_us,
    std::uint64_t encode_us, std::uint64_t publish_us, double rtt_ms) {
    vfdual::host::application::HostRuntimeReadModel value{};
    value.published_frames = published;
    value.capture_us = capture_us;
    value.bridge_us = 1000U;
    value.encode_us = encode_us;
    value.publish_us = publish_us;
    value.rtt_ms = rtt_ms;
    return value;
}

}  // namespace

int main() {
    VFDUAL_TEST_REQUIRE(!vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::idle));
    VFDUAL_TEST_REQUIRE(!vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::discovering));
    VFDUAL_TEST_REQUIRE(vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::streaming));
    VFDUAL_TEST_REQUIRE(vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::mobile_stale));
    VFDUAL_TEST_REQUIRE(vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::recovering));
    VFDUAL_TEST_REQUIRE(!vfdual::host_ui_phase_requires_polling(vfdual::HostUiPhase::failed));

    const auto not_checked = vfdual::host_idle_ui_text(
        vfdual::HostIdleEndpointState::not_checked);
    const auto reachable = vfdual::host_idle_ui_text(
        vfdual::HostIdleEndpointState::reachable);
    const auto unreachable = vfdual::host_idle_ui_text(
        vfdual::HostIdleEndpointState::unreachable);

    require_idle_contract(not_checked);
    require_idle_contract(reachable);
    require_idle_contract(unreachable);

    VFDUAL_TEST_REQUIRE(contains(not_checked.phone, L"VF Mobile"));
    VFDUAL_TEST_REQUIRE(contains(reachable.phone, L"VF Mobile"));
    VFDUAL_TEST_REQUIRE(contains(unreachable.phone, L"VF Mobile"));
    VFDUAL_TEST_REQUIRE(!contains(not_checked.phone, L"VisionForge"));
    VFDUAL_TEST_REQUIRE(!contains(reachable.phone, L"VisionForge"));
    VFDUAL_TEST_REQUIRE(!contains(unreachable.phone, L"VisionForge"));

    VFDUAL_TEST_REQUIRE(contains(not_checked.ready_state, L"\u5c1a\u672a\u68c0\u6d4b"));
    VFDUAL_TEST_REQUIRE(contains(not_checked.topology_link, L"\u5f85\u68c0\u6d4b"));
    VFDUAL_TEST_REQUIRE(contains(reachable.ready_state, L"\u5df2\u5c31\u7eea"));
    VFDUAL_TEST_REQUIRE(contains(reachable.ready_detail, L"\u4e3b\u673a\u672a\u5728\u4f20\u8f93"));
    VFDUAL_TEST_REQUIRE(contains(reachable.phone, L"\u7aef\u70b9\u53ef\u8fbe"));
    VFDUAL_TEST_REQUIRE(contains(reachable.topology_link, L"\u7aef\u70b9\u53ef\u8fbe"));
    VFDUAL_TEST_REQUIRE(contains(reachable.topology_mobile, L"\u5df2\u5c31\u7eea"));
    VFDUAL_TEST_REQUIRE(contains(unreachable.ready_state, L"\u672a\u54cd\u5e94"));
    VFDUAL_TEST_REQUIRE(contains(unreachable.ready_detail, L"\u53ef\u91cd\u65b0\u68c0\u6d4b"));
    VFDUAL_TEST_REQUIRE(contains(unreachable.link, L"\u6682\u4e0d\u53ef\u8fbe"));
    VFDUAL_TEST_REQUIRE(contains(unreachable.topology_mobile, L"\u672a\u54cd\u5e94"));

    vfdual::HostUiTelemetry telemetry(8U);
    static_cast<void>(telemetry.observe(
        metrics(1U, 1000U, 3000U, 1000U, 2.0), 1000U));
    static_cast<void>(telemetry.observe(
        metrics(2U, 2000U, 4000U, 2000U, 4.0), 2000U));
    const auto snapshot = telemetry.observe(
        metrics(4U, 3000U, 5000U, 3000U, 6.0), 3000U);

    VFDUAL_TEST_REQUIRE(snapshot.capture_ms.has_value());
    VFDUAL_TEST_REQUIRE(near(snapshot.capture_ms->current, 3.0));
    VFDUAL_TEST_REQUIRE(near(snapshot.capture_ms->p50, 2.0));
    VFDUAL_TEST_REQUIRE(near(snapshot.capture_ms->p95, 3.0));
    VFDUAL_TEST_REQUIRE(snapshot.encode_ms.has_value() && near(snapshot.encode_ms->p50, 4.0));
    VFDUAL_TEST_REQUIRE(
        snapshot.publish_ms.has_value() && near(snapshot.publish_ms->p95, 3.0));
    VFDUAL_TEST_REQUIRE(snapshot.total_ms.has_value() && near(snapshot.total_ms->current, 12.0));
    VFDUAL_TEST_REQUIRE(
        snapshot.link_rtt_ms.has_value() && near(snapshot.link_rtt_ms->p50, 4.0));
    VFDUAL_TEST_REQUIRE(snapshot.output_fps.has_value());
    VFDUAL_TEST_REQUIRE(near(snapshot.output_fps->current, 2.0));

    telemetry.reset();
    const auto reset_snapshot = telemetry.snapshot();
    VFDUAL_TEST_REQUIRE(!reset_snapshot.capture_ms.has_value());
    VFDUAL_TEST_REQUIRE(!reset_snapshot.encode_ms.has_value());
    VFDUAL_TEST_REQUIRE(!reset_snapshot.publish_ms.has_value());
    VFDUAL_TEST_REQUIRE(!reset_snapshot.total_ms.has_value());
    VFDUAL_TEST_REQUIRE(!reset_snapshot.link_rtt_ms.has_value());
    VFDUAL_TEST_REQUIRE(!reset_snapshot.output_fps.has_value());

    const auto first_new_session = telemetry.observe(
        metrics(100U, 9000U, 8000U, 7000U, 5.0), 4000U);
    VFDUAL_TEST_REQUIRE(first_new_session.capture_ms.has_value());
    VFDUAL_TEST_REQUIRE(!first_new_session.output_fps.has_value());
    const auto second_new_session = telemetry.observe(
        metrics(102U, 6000U, 5000U, 4000U, 3.0), 5000U);
    VFDUAL_TEST_REQUIRE(second_new_session.output_fps.has_value());
    VFDUAL_TEST_REQUIRE(near(second_new_session.output_fps->current, 2.0));
    return 0;
}
