#pragma once

#include <string_view>

namespace vfdual {

enum class HostIdleEndpointState {
    not_checked,
    reachable,
    unreachable,
};

struct HostIdleUiText final {
    std::wstring_view ready_state;
    std::wstring_view ready_detail;
    std::wstring_view hero;
    std::wstring_view encoder;
    std::wstring_view phone;
    std::wstring_view link;
    std::wstring_view topology_host;
    std::wstring_view topology_link;
    std::wstring_view topology_mobile;
};

/**
 * Returns the complete non-streaming presentation for one mobile endpoint state.
 * This contract deliberately makes no encoder-readiness claim: encoder probing
 * starts only when the operator starts the stream.
 */
[[nodiscard]] constexpr HostIdleUiText host_idle_ui_text(
        HostIdleEndpointState endpoint_state) noexcept {
    constexpr std::wstring_view encoder =
        L"\u5f00\u59cb\u4f20\u8f93\u65f6\u81ea\u52a8\u9009\u62e9 H.264 \u7f16\u7801\u5668";
    switch (endpoint_state) {
        case HostIdleEndpointState::not_checked:
            return {
                L"手机端点尚未检测",
                L"主机未在传输·CAT6 优先，无线自动回退",
                L"等待手机端点检测",
                encoder,
                L"VF Mobile\u00b7 \u5c1a\u672a\u68c0\u6d4b",
                L"自动传输链路·端点状态待检测",
                L"\u5f85\u542f\u52a8",
                L"\u5f85\u68c0\u6d4b",
                L"\u5f85\u68c0\u6d4b",
            };
        case HostIdleEndpointState::reachable:
            return {
                L"手机端点已就绪",
                L"手机在线·链路可达·主机未在传输",
                L"VF Mobile 已就绪",
                encoder,
                L"VF Mobile·端点可达",
                L"自动传输链路·端点可达，等待传输",
                L"\u5f85\u542f\u52a8",
                L"\u7aef\u70b9\u53ef\u8fbe",
                L"\u5df2\u5c31\u7eea",
            };
        case HostIdleEndpointState::unreachable:
            return {
                L"手机端点未响应",
                L"主机未在传输·可重新检测手机传输端点",
                L"VF Mobile 暂未响应",
                encoder,
                L"VF Mobile·暂未响应",
                L"自动传输链路·端点暂不可达",
                L"\u5f85\u542f\u52a8",
                L"\u7b49\u5f85\u7aef\u70b9",
                L"\u672a\u54cd\u5e94",
            };
    }
    return host_idle_ui_text(HostIdleEndpointState::not_checked);
}

}  // namespace vfdual
