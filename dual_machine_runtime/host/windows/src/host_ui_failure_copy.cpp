#include "vfdual/host_ui_failure_copy.hpp"

namespace vfdual {

bool host_failure_is_authorization_pending(
    std::string_view error) noexcept {
    return error.find("verified server usage lease authorization closed") !=
               std::string_view::npos ||
        error.find("Authenticated Host/Android peer session") !=
               std::string_view::npos ||
        error.find("current verified server usage lease") !=
               std::string_view::npos ||
        error.find("fresh-pair activation request was not received") !=
               std::string_view::npos;
}

std::wstring widen_ascii(std::string_view value) {
    std::wstring result;
    result.reserve(value.size());
    for (const unsigned char character : value) {
        result.push_back(
            character < 0x80U ? static_cast<wchar_t>(character) : L'?');
    }
    return result;
}

std::wstring friendly_host_failure(std::string_view error) {
    if (error.find("verified server usage lease authorization closed") !=
            std::string_view::npos) {
        return L"短时租约续签中，主机已安全停流并等待自动恢复";
    }
    if (error.find("fresh-pair activation request was not received") !=
            std::string_view::npos) {
        return L"\u7b49\u5f85\u624b\u673a\u63d0\u4ea4\u65e5\u5361\u6fc0\u6d3b";
    }
    if (host_failure_is_authorization_pending(error)) {
        return L"\u7b49\u5f85\u624b\u673a\u5b8c\u6210\u6fc0\u6d3b\u4e0e\u8ba4\u8bc1";
    }
    if (error.find("ambiguous_same_name_rule") != std::string_view::npos) {
        return L"\u68c0\u6d4b\u5230\u51b2\u7a81\u7684\u65e7\u7248 Windows \u9632\u706b\u5899\u89c4\u5219";
    }
    if (error.find("wireless_firewall_status=failed") !=
            std::string_view::npos ||
        error.find("failure_stage=firewall") != std::string_view::npos ||
        error.find("CAT6 firewall provisioning failed") !=
            std::string_view::npos) {
        return L"Windows \u9632\u706b\u5899\u6700\u5c0f\u653e\u884c\u89c4\u5219\u914d\u7f6e\u5931\u8d25";
    }
    if (error.find("Automatic wireless-LAN UDP fallback was unavailable") !=
            std::string_view::npos ||
        error.find("wireless_discovery={") != std::string_view::npos) {
        return L"\u65e0\u7ebf\u5c40\u57df\u7f51\u672a\u53d1\u73b0 VF Mobile";
    }
    if (error.find("Host DHCP received zero packets") !=
            std::string_view::npos ||
        error.find("not exposing an app-usable IPv4") !=
            std::string_view::npos) {
        return L"\u624b\u673a\u6709\u7ebf\u7f51\u672a\u83b7\u5f97 10.57.23.2/24 IPv4";
    }
    if (error.find("failure_stage=mobile_ready_timeout") !=
            std::string_view::npos ||
        error.find("heartbeat") != std::string_view::npos) {
        return L"\u672a\u6536\u5230\u624b\u673a CAT6 \u5fc3\u8df3";
    }
    if (error.find("failure_stage=dhcp") != std::string_view::npos ||
        error.find("CAT6 DHCP bootstrap failed") != std::string_view::npos) {
        return L"CAT6 DHCP \u542f\u52a8\u5931\u8d25";
    }
    if (error.find("direct-link") != std::string_view::npos ||
        error.find("wired") != std::string_view::npos) {
        return L"CAT6 \u6709\u7ebf\u63a5\u53e3\u81ea\u52a8\u914d\u7f6e\u5931\u8d25";
    }
    if (error.find("display") != std::string_view::npos ||
        error.find("DXGI") != std::string_view::npos) {
        return L"\u684c\u9762\u6355\u83b7\u521d\u59cb\u5316\u5931\u8d25";
    }
    if (error.find("H.264") != std::string_view::npos ||
        error.find("UDP") != std::string_view::npos) {
        return L"\u7f16\u7801\u6216 CAT6 \u53d1\u9001\u521d\u59cb\u5316\u5931\u8d25";
    }
    return L"\u4e3b\u673a\u4f20\u8f93\u542f\u52a8\u5931\u8d25";
}

}  // namespace vfdual
