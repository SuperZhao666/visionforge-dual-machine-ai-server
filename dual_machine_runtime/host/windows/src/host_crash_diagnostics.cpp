#include "vfdual/host_crash_diagnostics.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace vfdual {
namespace {

std::atomic_bool g_installed{};

std::filesystem::path crash_directory() {
    wchar_t local_app_data[32'768]{};
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", local_app_data,
        static_cast<DWORD>(std::size(local_app_data)));
    if (length == 0U || length >= std::size(local_app_data)) return {};
    return std::filesystem::path{local_app_data} /
        "VisionForge" / "DualMachine" / "crashes";
}

std::wstring crash_stem() {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t stem[128]{};
    swprintf_s(
        stem, L"VFHost-%04u%02u%02u-%02u%02u%02u-%03u-pid%lu-tid%lu",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
        time.wSecond, time.wMilliseconds, GetCurrentProcessId(),
        GetCurrentThreadId());
    return stem;
}

std::string capture_stack_addresses() {
    std::array<void*, 64> frames{};
    const USHORT count = CaptureStackBackTrace(
        0U, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    std::ostringstream output;
    output << '[';
    for (USHORT index = 0; index < count; ++index) {
        if (index != 0U) output << ',';
        output << "0x" << std::hex
               << reinterpret_cast<std::uintptr_t>(frames[index]) << std::dec;
    }
    output << ']';
    return output.str();
}

void write_crash_artifacts(
    std::string_view category,
    std::string_view detail,
    EXCEPTION_POINTERS* exception) noexcept {
    try {
        const std::filesystem::path directory = crash_directory();
        if (directory.empty()) return;
        std::error_code directory_error;
        std::filesystem::create_directories(directory, directory_error);
        if (directory_error) return;

        const std::wstring stem = crash_stem();
        const std::filesystem::path dump_path = directory / (stem + L".dmp");
        const std::filesystem::path text_path = directory / (stem + L".txt");
        HANDLE dump = CreateFileW(
            dump_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        BOOL dump_written = FALSE;
        DWORD dump_error = ERROR_SUCCESS;
        if (dump != INVALID_HANDLE_VALUE) {
            MINIDUMP_EXCEPTION_INFORMATION exception_information{};
            exception_information.ThreadId = GetCurrentThreadId();
            exception_information.ExceptionPointers = exception;
            exception_information.ClientPointers = FALSE;
            const auto dump_type = static_cast<MINIDUMP_TYPE>(
                MiniDumpNormal | MiniDumpWithThreadInfo |
                MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory);
            dump_written = MiniDumpWriteDump(
                GetCurrentProcess(), GetCurrentProcessId(), dump, dump_type,
                exception == nullptr ? nullptr : &exception_information,
                nullptr, nullptr);
            if (!dump_written) dump_error = GetLastError();
            CloseHandle(dump);
        } else {
            dump_error = GetLastError();
        }

        std::ofstream report(text_path, std::ios::trunc);
        if (!report) return;
        report << "timestamp_unix_ms="
               << std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count()
               << '\n'
               << "pid=" << GetCurrentProcessId() << '\n'
               << "thread_id=" << GetCurrentThreadId() << '\n'
               << "category=" << category << '\n'
               << "detail=" << detail << '\n'
               << "exception_code=0x" << std::hex
               << (exception != nullptr && exception->ExceptionRecord != nullptr
                       ? exception->ExceptionRecord->ExceptionCode : 0UL)
               << std::dec << '\n'
               << "exception_address=0x" << std::hex
               << reinterpret_cast<std::uintptr_t>(
                      exception != nullptr && exception->ExceptionRecord != nullptr
                          ? exception->ExceptionRecord->ExceptionAddress : nullptr)
               << std::dec << '\n'
               << "handler_stack_addresses=" << capture_stack_addresses() << '\n'
               << "minidump_path=" << dump_path.string() << '\n'
               << "minidump_written=" << (dump_written != FALSE) << '\n'
               << "minidump_win32_error=" << dump_error << '\n';
    } catch (...) {
        OutputDebugStringA("VF Host crash artifact writer failed.\n");
    }
}

LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS* exception) {
    write_crash_artifacts("seh_unhandled_exception", {}, exception);
    return EXCEPTION_EXECUTE_HANDLER;
}

[[noreturn]] void terminate_handler() noexcept {
    std::string detail = "std::terminate";
    if (const std::exception_ptr current = std::current_exception()) {
        try {
            std::rethrow_exception(current);
        } catch (const std::exception& error) {
            detail += " what=[" + std::string{error.what()} + ']';
        } catch (...) {
            detail += " current_exception=unknown";
        }
    }
    write_crash_artifacts("cpp_terminate", detail, nullptr);
    std::abort();
}

}  // namespace

void install_host_crash_diagnostics() noexcept {
    if (g_installed.exchange(true)) return;
    SetUnhandledExceptionFilter(unhandled_exception_filter);
    std::set_terminate(terminate_handler);
}

void record_host_cpp_exception(
    std::string_view category, std::string_view detail) noexcept {
    write_crash_artifacts(category, detail, nullptr);
}

}  // namespace vfdual
