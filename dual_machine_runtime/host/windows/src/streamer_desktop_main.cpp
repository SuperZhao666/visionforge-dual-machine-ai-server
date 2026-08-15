#include "vfdual/streamer_desktop_app.hpp"
#include "vfdual/host_crash_diagnostics.hpp"
#include "vfdual/host_direct_link_provisioner.hpp"

#include <cwctype>
#include <exception>
#include <memory>
#include <string>
#include <string_view>

namespace {

constexpr wchar_t kMainInstanceMutexName[] =
    L"Global\\VisionForge.Host.MainInstance.v1";

class MainInstanceMutex final {
public:
    MainInstanceMutex() noexcept {
        handle_ = CreateMutexW(nullptr, TRUE, kMainInstanceMutexName);
        create_error_ = GetLastError();
    }

    MainInstanceMutex(const MainInstanceMutex&) = delete;
    MainInstanceMutex& operator=(const MainInstanceMutex&) = delete;

    ~MainInstanceMutex() {
        if (handle_ == nullptr) return;
        if (create_error_ != ERROR_ALREADY_EXISTS) ReleaseMutex(handle_);
        CloseHandle(handle_);
    }

    [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
    [[nodiscard]] bool already_exists() const noexcept {
        return handle_ != nullptr && create_error_ == ERROR_ALREADY_EXISTS;
    }
    [[nodiscard]] DWORD create_error() const noexcept { return create_error_; }

private:
    HANDLE handle_{};
    DWORD create_error_{};
};

void enable_per_monitor_dpi_awareness() noexcept {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) return;
    using SetAwarenessContext = BOOL(WINAPI*)(HANDLE);
    const auto set_awareness = reinterpret_cast<SetAwarenessContext>(
        GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
    if (set_awareness != nullptr) {
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 is the documented -4 value.
        if (set_awareness(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-4)))) return;
    }
    SetProcessDPIAware();
}

bool command_line_is(PWSTR command_line, std::wstring_view expected) {
    if (command_line == nullptr) return false;
    std::wstring_view value{command_line};
    while (!value.empty() && std::iswspace(value.front()) != 0) value.remove_prefix(1);
    while (!value.empty() && std::iswspace(value.back()) != 0) value.remove_suffix(1);
    if (value.size() >= 2U && value.front() == L'"' && value.back() == L'"') {
        value.remove_prefix(1);
        value.remove_suffix(1);
    }
    return value == expected;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR command_line, int) {
    vfdual::install_host_crash_diagnostics();
    try {
        if (command_line_is(command_line, vfdual::kHostDirectLinkWorkerArgument)) {
            return vfdual::run_host_direct_link_provisioning_worker();
        }
        if (command_line_is(command_line, vfdual::kHostDirectLinkRestoreWorkerArgument)) {
            return vfdual::run_host_direct_link_restore_worker();
        }
        if (command_line_is(command_line, vfdual::kHostFirewallWorkerArgument)) {
            return vfdual::run_host_firewall_provisioning_worker();
        }
        MainInstanceMutex main_instance;
        if (!main_instance.valid()) {
            const std::string detail =
                "win32_error=" + std::to_string(main_instance.create_error());
            vfdual::record_host_cpp_exception(
                "main_instance_mutex_create_failed", detail);
            MessageBoxA(
                nullptr, detail.c_str(), "VF Host startup failed",
                MB_OK | MB_ICONERROR);
            return static_cast<int>(main_instance.create_error());
        }
        if (main_instance.already_exists()) {
            MessageBoxW(
                nullptr,
                L"VF Host is already running in this Windows session.",
                L"VF Host", MB_OK | MB_ICONINFORMATION);
            return ERROR_ALREADY_EXISTS;
        }
        enable_per_monitor_dpi_awareness();
        auto application = std::make_unique<vfdual::StreamerDesktopApp>();
        return application->run(
            instance,
            command_line_is(command_line, L"--acceptance-autostart"));
    } catch (const std::exception& error) {
        const std::string detail = "what=[" + std::string{error.what()} + ']';
        vfdual::record_host_cpp_exception("wWinMain_std_exception", detail);
        MessageBoxA(
            nullptr, detail.c_str(), "VF Host fatal error",
            MB_OK | MB_ICONERROR);
        return ERROR_UNHANDLED_EXCEPTION;
    } catch (...) {
        vfdual::record_host_cpp_exception(
            "wWinMain_unknown_exception", "no std::exception detail");
        MessageBoxW(
            nullptr, L"VF Host encountered an unknown fatal exception. "
                     L"A minidump was written to the diagnostics directory.",
            L"VF Host fatal error", MB_OK | MB_ICONERROR);
        return ERROR_UNHANDLED_EXCEPTION;
    }
}
