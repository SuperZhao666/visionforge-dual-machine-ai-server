#include "vfdual/host_runtime_service.hpp"

#include "vf/host/infrastructure/file_epoch_reservation_store.hpp"
#include "vfdual/host_cat6_bootstrap.hpp"
#include "vfdual/host_cat6_monitor.hpp"
#include "vfdual/wired_link_contract.hpp"
#include "vfdual/host_application.hpp"
#include "vfdual/host_display_catalog.hpp"
#include "vfdual/host_preferred_probe_log_policy.hpp"
#include "vfdual/host_recovery_policy.hpp"
#include "vfdual/h264_encoder_config.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <optional>
#include <process.h>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

namespace vfdual {
namespace {

std::string current_executable_sha256() {
    std::wstring executable(32'768U, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0U || length >= executable.size()) return {};
    executable.resize(length);
    std::ifstream input(executable, std::ios::binary);
    if (!input) return {};

    HCRYPTPROV provider{};
    HCRYPTHASH hash{};
    if (!CryptAcquireContextW(
            &provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        return {};
    }
    std::array<char, 64U * 1024U> buffer{};
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize read = input.gcount();
        if (read > 0 && !CryptHashData(
                hash, reinterpret_cast<const BYTE*>(buffer.data()),
                static_cast<DWORD>(read), 0)) {
            CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            return {};
        }
    }
    std::array<BYTE, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (!input.eof() ||
        !CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &digest_size, 0) ||
        digest_size != digest.size()) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    constexpr char kHex[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(digest.size() * 2U);
    for (const BYTE byte : digest) {
        encoded.push_back(kHex[byte >> 4U]);
        encoded.push_back(kHex[byte & 0x0fU]);
    }
    return encoded;
}

struct HostEventSession final {
    HostEventSession()
        : started_at(std::chrono::steady_clock::now()),
          trace_id("vfhost-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count()) + "-" +
              std::to_string(_getpid())),
          executable_sha256(current_executable_sha256()) {}

    std::chrono::steady_clock::time_point started_at;
    std::string trace_id;
    std::string executable_sha256;
    std::mutex mutex;
    std::uint64_t sequence{};
    std::uint64_t attempt_sequence{};
};

thread_local std::uint64_t g_host_attempt_id{};
constexpr auto kWirelessLanDiscoveryTimeout = std::chrono::seconds{8};
constexpr auto kPreferredCat6ProbeRetryInterval = std::chrono::seconds{5};

HostPreferredProbeFailureState make_preferred_probe_failure_state(
    const HostCat6BootstrapResult& result) {
    const HostCat6BootstrapFailureStage stage =
        classify_host_cat6_bootstrap_failure(result);
    HostPreferredProbeFailureState state{
        .failure_stage = host_cat6_bootstrap_failure_stage_name(stage),
    };
    switch (stage) {
        case HostCat6BootstrapFailureStage::direct_link:
            state.failure_status =
                host_direct_link_status_name(result.direct_link.status);
            state.failure_reason =
                host_preferred_probe_root_reason(result.direct_link.detail);
            break;
        case HostCat6BootstrapFailureStage::firewall:
            state.failure_status = host_firewall_status_name(result.firewall.status);
            state.failure_reason =
                host_preferred_probe_root_reason(result.firewall.detail);
            break;
        case HostCat6BootstrapFailureStage::dhcp:
            state.failure_status = result.dhcp_runtime_failed
                ? "runtime_failed"
                : (result.dhcp_start_attempted ? "start_failed" : "not_started");
            state.failure_reason =
                host_preferred_probe_root_reason(result.dhcp_detail);
            break;
        case HostCat6BootstrapFailureStage::mobile_ready_timeout:
            state.failure_status = "mobile_ready_timeout";
            state.failure_reason = result.address_watch.empty()
                ? "no_address_transition"
                : "address_transition_observed";
            break;
        case HostCat6BootstrapFailureStage::none:
            state.failure_status = "ready";
            state.failure_reason = "none";
            break;
    }
    return state;
}

HostEventSession& host_event_session() {
    static HostEventSession session;
    return session;
}

std::uint64_t allocate_host_attempt_id() {
    auto& session = host_event_session();
    std::lock_guard lock(session.mutex);
    return ++session.attempt_sequence;
}

void write_emergency_event(
    std::string_view reason, std::string_view event, std::string_view detail) noexcept {
    try {
        wchar_t temporary_directory[MAX_PATH]{};
        const DWORD length = GetTempPathW(MAX_PATH, temporary_directory);
        if (length == 0U || length >= MAX_PATH) {
            OutputDebugStringA("VF Host event logging failed.\n");
            return;
        }
        const std::filesystem::path path =
            std::filesystem::path{temporary_directory} /
            "VFHost-emergency.log";
        std::ofstream output(path, std::ios::app);
        if (!output) {
            OutputDebugStringA("VF Host emergency logging failed.\n");
            return;
        }
        output << "timestamp_unix_ms="
               << std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count()
               << " pid=" << _getpid()
               << " reason=" << reason
               << " event=" << event
               << " detail=" << detail << '\n';
    } catch (...) {
        OutputDebugStringA("VF Host emergency logging threw an exception.\n");
    }
}

std::filesystem::path resolve_local_app_data_directory() {
    char* local_app_data{};
    std::size_t local_app_data_length{};
    const errno_t environment_result = _dupenv_s(
        &local_app_data, &local_app_data_length, "LOCALAPPDATA");
    if (environment_result != 0 || local_app_data == nullptr ||
        local_app_data_length <= 1U) {
        std::free(local_app_data);
        return {};
    }
    const std::filesystem::path directory(local_app_data);
    std::free(local_app_data);
    return directory;
}

std::string resolve_metrics_path() {
    const std::filesystem::path local_app_data = resolve_local_app_data_directory();
    if (local_app_data.empty()) return {};
    const std::filesystem::path directory = local_app_data / "VisionForge" / "DualMachine";
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    // V5 adds explicit static-content refresh semantics after the V4
    // authoritative hybrid-published counter.
    // Keep older append-only evidence intact instead of mixing row schemas.
    return error ? std::string{} : (directory / "host-metrics-v6.csv").string();
}

std::filesystem::path resolve_stream_epoch_state_path() {
    const std::filesystem::path local_app_data = resolve_local_app_data_directory();
    if (local_app_data.empty()) return {};
    const std::filesystem::path directory =
        local_app_data / "VisionForge" / "DualMachine";
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    return error ? std::filesystem::path{}
                 : directory / "stream-epoch-v1.state";
}

std::filesystem::path resolve_event_path() {
    const std::filesystem::path local_app_data = resolve_local_app_data_directory();
    if (local_app_data.empty()) return {};
    const std::filesystem::path directory = local_app_data / "VisionForge" / "DualMachine";
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    return error ? std::filesystem::path{} : directory / "host-events.jsonl";
}

std::string escape_json_string(std::string_view value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char character : value) {
        switch (character) {
            case '\\': escaped += "\\\\"; break;
            case '\"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default: escaped += character; break;
        }
    }
    return escaped;
}

void write_host_event(std::string_view event, std::string_view detail = {}) {
    auto& session = host_event_session();
    std::lock_guard lock(session.mutex);
    const std::filesystem::path path = resolve_event_path();
    if (path.empty()) {
        write_emergency_event("event_path_unavailable", event, detail);
        return;
    }
    std::ofstream output(path, std::ios::app);
    if (!output) {
        write_emergency_event(
            "event_open_failed_errno_" + std::to_string(errno), event, detail);
        return;
    }
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - session.started_at).count();
    output << "{\"timestamp_unix_ms\":" << timestamp
           << ",\"trace_id\":\"" << session.trace_id
           << "\",\"build_sha256\":\"" << session.executable_sha256
           << "\",\"sequence\":" << ++session.sequence
           << ",\"attempt_id\":" << g_host_attempt_id
           << ",\"elapsed_ms\":" << elapsed
           << ",\"event\":\"" << escape_json_string(event)
           << "\",\"detail\":\"" << escape_json_string(detail) << "\"}\n";
    output.flush();
    if (!output) {
        write_emergency_event(
            "event_write_failed_errno_" + std::to_string(errno), event, detail);
    }
}

std::string summarize_bootstrap_diagnostics(
    const std::vector<std::string>& diagnostics) {
    if (diagnostics.empty()) return "count=0";
    return "count=" + std::to_string(diagnostics.size()) +
        " final={" + diagnostics.back() + '}';
}

void write_host_capture_geometry_event(const HostStreamSettings& settings) {
    auto& session = host_event_session();
    std::lock_guard lock(session.mutex);
    const std::filesystem::path path = resolve_event_path();
    if (path.empty()) {
        write_emergency_event(
            "event_path_unavailable", "host_capture_geometry", settings.display_id);
        return;
    }
    std::ofstream output(path, std::ios::app);
    if (!output) {
        write_emergency_event(
            "event_open_failed_errno_" + std::to_string(errno),
            "host_capture_geometry", settings.display_id);
        return;
    }
    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - session.started_at).count();
    output << "{\"timestamp_unix_ms\":" << timestamp
           << ",\"trace_id\":\"" << session.trace_id
           << "\",\"build_sha256\":\"" << session.executable_sha256
           << "\",\"sequence\":" << ++session.sequence
           << ",\"attempt_id\":" << g_host_attempt_id
           << ",\"elapsed_ms\":" << elapsed
           << ",\"event\":\"host_capture_geometry\""
           << ",\"display_id\":\"" << escape_json_string(settings.display_id) << "\""
           << ",\"display_rect\":{\"left\":" << settings.display_left
           << ",\"top\":" << settings.display_top
           << ",\"right\":" << settings.display_right
           << ",\"bottom\":" << settings.display_bottom << "}"
           << ",\"roi_rect\":{\"left\":" << settings.roi_left
           << ",\"top\":" << settings.roi_top
           << ",\"right\":" << settings.roi_right
           << ",\"bottom\":" << settings.roi_bottom << "}"
           << ",\"source_size\":{\"width\":" << settings.source_width
           << ",\"height\":" << settings.source_height << "}"
           << ",\"encoder_size\":{\"width\":" << settings.width
           << ",\"height\":" << settings.height << "}"
           << ",\"fallback_reason\":\"" << escape_json_string(settings.fallback_reason) << "\""
           << ",\"display_selection_reason\":\""
           << escape_json_string(settings.display_selection_reason) << "\"}\n";
    output.flush();
    if (!output) {
        write_emergency_event(
            "event_write_failed_errno_" + std::to_string(errno),
            "host_capture_geometry", settings.display_id);
    }
}

bool current_process_is_elevated() noexcept {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD returned{};
    const bool succeeded = GetTokenInformation(
        token, TokenElevation, &elevation, sizeof(elevation), &returned) != FALSE;
    CloseHandle(token);
    return succeeded && elevation.TokenIsElevated != 0;
}

std::string utf8_from_wide(std::wstring_view value) {
    if (value.empty()) return {};
    const int source_length = static_cast<int>((std::min)(
        value.size(), static_cast<std::size_t>((std::numeric_limits<int>::max)())));
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), source_length,
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string encoded(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), source_length,
        encoded.data(), required, nullptr, nullptr);
    if (written != required) return {};
    return encoded;
}

std::string describe_process_context() {
    std::wstring executable(32'768U, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    if (length == 0U || length >= executable.size()) executable.clear();
    else executable.resize(length);
    const std::string narrow_path = utf8_from_wide(executable);
    DWORD session_id{};
    const bool session_available =
        ProcessIdToSessionId(GetCurrentProcessId(), &session_id) != FALSE;
    OSVERSIONINFOW windows_version{};
    windows_version.dwOSVersionInfoSize = sizeof(windows_version);
    using RtlGetVersionFunction = LONG(WINAPI*)(OSVERSIONINFOW*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto rtl_get_version = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<RtlGetVersionFunction>(
              GetProcAddress(ntdll, "RtlGetVersion"));
    const bool version_available =
        rtl_get_version != nullptr && rtl_get_version(&windows_version) == 0;
    std::ostringstream detail;
    detail << "pid=" << GetCurrentProcessId()
           << " session_id=" << (session_available ? session_id : 0U)
           << " elevated=" << current_process_is_elevated()
           << " pointer_bits=" << (sizeof(void*) * 8U)
           << " remote_session=" << (GetSystemMetrics(SM_REMOTESESSION) != 0)
           << " windows_version=";
    if (version_available) {
        detail << windows_version.dwMajorVersion << '.'
               << windows_version.dwMinorVersion << '.'
               << windows_version.dwBuildNumber;
    } else {
        detail << "unavailable";
    }
    detail
           << " executable=[" << narrow_path << ']';
    return detail.str();
}

std::string capture_stack_addresses() noexcept {
    std::array<void*, 32> frames{};
    const USHORT count = CaptureStackBackTrace(
        0U, static_cast<DWORD>(frames.size()), frames.data(), nullptr);
    std::ostringstream detail;
    detail << "stack_addresses=[";
    for (USHORT index = 0; index < count; ++index) {
        if (index != 0U) detail << ',';
        detail << "0x" << std::hex
               << reinterpret_cast<std::uintptr_t>(frames[index]) << std::dec;
    }
    detail << ']';
    return detail.str();
}

std::string describe_native_error(std::int32_t code) {
    std::ostringstream detail;
    detail << "code=" << code << " hex=0x" << std::hex
           << static_cast<std::uint32_t>(code) << std::dec;
    wchar_t* message{};
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(code), 0,
        reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    if (length != 0U && message != nullptr) {
        std::wstring text{message, length};
        while (!text.empty() &&
               (text.back() == L'\r' || text.back() == L'\n' ||
                text.back() == L' ' || text.back() == L'\t')) {
            text.pop_back();
        }
        const std::string narrow = utf8_from_wide(text);
        if (!narrow.empty()) detail << " message=[" << narrow << ']';
    }
    if (message != nullptr) LocalFree(message);
    return detail.str();
}

HostRuntimeConfig create_runtime_config(
    const HostStreamSettings& settings,
    const std::string& metrics_path,
    std::uint64_t stream_epoch,
    VideoDataPlanePermitSource data_plane_permit) {
    HostRuntimeConfig config{};
    config.video.stream_epoch = stream_epoch;
    config.video.local_host = settings.local_host;
    config.video.local_port = kWiredVideoSourcePort;
    config.video.phone_host = settings.phone_host;
    config.video.phone_port = kWiredVideoPort;
    config.video.encoder.width = settings.width;
    config.video.encoder.height = settings.height;
    config.video.capture_region = settings.capture_region;
    config.video.encoder.frames_per_second = settings.encoder_timing_fps;
    config.video.encoder.keyframe_interval_frames = settings.encoder_timing_fps * 2U;
    config.video.encoder_preference = settings.force_software_encoder
        ? H264EncoderPreference::software
        : settings.skip_nvenc_encoder
            ? H264EncoderPreference::media_foundation
            : settings.skip_async_shared_encoder
                ? H264EncoderPreference::automatic_without_async_shared
                : H264EncoderPreference::automatic;
    config.video.adapter_index = settings.adapter_index;
    config.video.output_index = settings.output_index;
    config.video.data_plane_permit = std::move(data_plane_permit);
    config.metrics_interval_frames = settings.encoder_timing_fps;
    config.metrics_csv_path = metrics_path;
    return config;
}

HostStreamMetrics copy_metrics(const HostApplicationStats& source, std::uint64_t published_offset,
                               std::uint64_t timeout_offset, std::uint64_t stream_epoch,
                               std::uint32_t recovery_count,
                               const Cat6SessionSnapshot& transport_session,
                               const HostCat6MonitorSnapshot& monitor,
                               const HostStreamSettings& settings) {
    const auto& video = source.last_video_step;
    HostStreamMetrics metrics{};
    metrics.stream_epoch = stream_epoch;
    metrics.source_sequence = video.source_sequence;
    metrics.frame_id = video.frame_id;
    metrics.capture_us = video.capture_us;
    metrics.readback_wait_us = video.readback_wait_us;
    metrics.readback_copy_us = video.readback_copy_us;
    metrics.bridge_us = video.bridge_us;
    metrics.upload_us = video.upload_us;
    metrics.encode_us = video.encode_us;
    metrics.publish_us = video.publish_us;
    metrics.capture_to_publish_us = video.capture_to_publish_us;
    metrics.access_unit_bytes = video.access_unit_bytes;
    metrics.datagrams = video.datagrams_sent;
    metrics.keyframe = video.keyframe;
    metrics.status = static_cast<std::int32_t>(video.status);
    metrics.bridge_mode = static_cast<std::int32_t>(video.bridge_mode);
    metrics.native_status = video.native_status;
    metrics.encoder_backend = static_cast<std::int32_t>(video.encoder_backend);
    metrics.capture_vendor = static_cast<std::int32_t>(video.capture_vendor);
    metrics.encoder_vendor = static_cast<std::int32_t>(video.encoder_vendor);
    metrics.encoder_same_adapter = video.encoder_same_adapter;
    metrics.zero_copy = video.zero_copy;
    metrics.asynchronous_pipeline = video.asynchronous_pipeline;
    metrics.async_shared_same_adapter = video.async_shared_same_adapter;
    metrics.encoder_timing_fps = video.encoder_timing_fps;
    metrics.nvenc_stage = static_cast<std::int32_t>(video.nvenc_stage);
    metrics.media_foundation_stage =
        static_cast<std::int32_t>(video.media_foundation_stage);
    metrics.published_frames = published_offset + source.published_frames;
    metrics.capture_timeouts = timeout_offset + source.capture_timeouts;
    metrics.pointer_only_skips = source.pointer_only_skips;
    metrics.outside_region_skips = source.outside_region_skips;
    metrics.staging_busy_drops = source.staging_busy_drops;
    metrics.mouse_button_publisher_running =
        source.mouse_button_publisher.running;
    metrics.mouse_button_transport_ready =
        source.mouse_button_publisher.transport_ready;
    metrics.physical_button_mask =
        source.mouse_button_publisher.current_button_mask;
    metrics.mouse_button_packets_sent =
        source.mouse_button_publisher.packets_sent;
    metrics.mouse_button_send_failures =
        source.mouse_button_publisher.send_failures;
    metrics.mouse_button_socket_error =
        source.mouse_button_publisher.last_socket_error;
    metrics.missed_present_frames = video.missed_present_frames_total;
    metrics.static_content_repeats = video.static_content_repeats;
    metrics.repeated_content = video.repeated_content;
    metrics.hybrid_was_still_drawing = video.hybrid_was_still_drawing;
    metrics.hybrid_mailbox_superseded = video.hybrid_mailbox_superseded;
    metrics.hybrid_mailbox_replaced = video.hybrid_mailbox_replaced;
    metrics.hybrid_ring_busy = video.hybrid_ring_busy;
    metrics.hybrid_keyed_timeout = video.hybrid_keyed_timeout;
    metrics.hybrid_completion_metrics_dropped =
        video.hybrid_completion_metrics_dropped;
    metrics.worker_frame_age_us = video.worker_frame_age_us;
    metrics.hybrid_latest_worker_frame_age_us =
        video.hybrid_latest_worker_frame_age_us;
    metrics.hybrid_maximum_worker_frame_age_us =
        video.hybrid_maximum_worker_frame_age_us;
    metrics.recovery_count = recovery_count;
    metrics.display_id = settings.display_id;
    metrics.display_selection_reason = settings.display_selection_reason;
    metrics.transport = transport_session.transport;
    metrics.mobile_ipv4 = transport_session.mobile_ipv4;
    // A short ready-probe stall must not make the UI claim that an otherwise
    // active transport is disconnected. Recovery has a deliberately wider
    // hysteresis than the diagnostic "probe degraded" signal.
    metrics.mobile_reachable = !monitor.recovery_required;
    metrics.mobile_probe_failures = monitor.consecutive_failures;
    metrics.mobile_last_success_age_ms = monitor.last_success_age_ms;
    metrics.packet_loss_ratio = transport_session.quality.packet_loss_ratio;
    metrics.jitter_ms = transport_session.quality.jitter_ms;
    metrics.rtt_ms = transport_session.quality.rtt_ms;
    metrics.throughput_mbps = transport_session.quality.throughput_mbps;
    return metrics;
}

std::string_view encoder_candidate_name(HostEncoderCandidate candidate) noexcept {
    switch (candidate) {
        case HostEncoderCandidate::nvenc_same_adapter_async_shared:
            return "nvenc_same_adapter_async_shared";
        case HostEncoderCandidate::nvenc_capture_device:
            return "nvenc_capture_device";
        case HostEncoderCandidate::nvenc_cross_adapter:
            return "nvenc_cross_adapter";
        case HostEncoderCandidate::windows_hardware_capture_device:
            return "windows_hardware_capture_device";
        case HostEncoderCandidate::software_cpu:
            return "software_cpu";
    }
    return "unknown";
}

std::string_view desktop_video_initialization_stage_name(
    DesktopVideoInitializationStage stage) noexcept {
    switch (stage) {
        case DesktopVideoInitializationStage::none:
            return "none";
        case DesktopVideoInitializationStage::validate_config:
            return "validate_config";
        case DesktopVideoInitializationStage::capture_initialize:
            return "capture_initialize";
        case DesktopVideoInitializationStage::hybrid_pipeline_initialize:
            return "hybrid_pipeline_initialize";
        case DesktopVideoInitializationStage::frame_bridge_initialize:
            return "frame_bridge_initialize";
        case DesktopVideoInitializationStage::nvenc_initialize:
            return "nvenc_initialize";
        case DesktopVideoInitializationStage::media_foundation_hardware_initialize:
            return "media_foundation_hardware_initialize";
        case DesktopVideoInitializationStage::media_foundation_software_initialize:
            return "media_foundation_software_initialize";
        case DesktopVideoInitializationStage::udp_publisher_connect:
            return "udp_publisher_connect";
        case DesktopVideoInitializationStage::complete:
            return "complete";
    }
    return "unknown";
}

std::string_view host_application_start_stage_name(
    HostApplicationStartStage stage) noexcept {
    switch (stage) {
        case HostApplicationStartStage::none:
            return "none";
        case HostApplicationStartStage::video_initialize:
            return "video_initialize";
        case HostApplicationStartStage::idr_listener_start:
            return "idr_listener_start";
        case HostApplicationStartStage::mouse_button_publisher_start:
            return "mouse_button_publisher_start";
        case HostApplicationStartStage::metrics_csv_open:
            return "metrics_csv_open";
        case HostApplicationStartStage::complete:
            return "complete";
    }
    return "unknown";
}

HostVideoFailureKind host_video_failure_kind(
    DesktopVideoStepStatus status) noexcept {
    switch (status) {
        case DesktopVideoStepStatus::bridge_failed:
            return HostVideoFailureKind::bridge_failed;
        case DesktopVideoStepStatus::encode_failed:
            return HostVideoFailureKind::encode_failed;
        default:
            return HostVideoFailureKind::none;
    }
}

HostEncoderRuntimePath host_encoder_runtime_path(
    const DesktopVideoStepMetrics& metrics) noexcept {
    if (metrics.encoder_backend == H264EncoderBackend::nvenc) {
        if (metrics.async_shared_same_adapter) {
            return HostEncoderRuntimePath::nvenc_same_adapter_async_shared;
        }
        return metrics.encoder_same_adapter
            ? HostEncoderRuntimePath::nvenc_capture_device
            : HostEncoderRuntimePath::nvenc_cross_adapter;
    }
    if (metrics.encoder_backend == H264EncoderBackend::windows_hardware) {
        return HostEncoderRuntimePath::windows_hardware;
    }
    return HostEncoderRuntimePath::other;
}

std::string describe_encoder_diagnostics(
    const DesktopVideoEncoderDiagnostics& diagnostics) {
    std::ostringstream detail;
    detail << "initialization_stage="
           << desktop_video_initialization_stage_name(
                  diagnostics.initialization_stage)
           << " last_failure_stage="
           << desktop_video_initialization_stage_name(
                  diagnostics.last_failure_stage)
           << " backend=" << static_cast<std::int32_t>(diagnostics.backend)
           << " hardware=" << diagnostics.hardware
           << " capture_vendor="
           << static_cast<std::int32_t>(diagnostics.capture_vendor)
           << " encoder_vendor="
           << static_cast<std::int32_t>(diagnostics.encoder_vendor)
           << " same_adapter=" << diagnostics.same_adapter
           << " selected_candidate="
           << (diagnostics.has_selected_candidate
                   ? encoder_candidate_name(diagnostics.selected_candidate)
                   : "none")
           << " transform_name=\"" << diagnostics.transform_name << "\""
           << " transform_clsid=" << diagnostics.transform_clsid
           << " adapter_vendor_id=0x" << std::hex
           << diagnostics.adapter_vendor_id
           << " adapter_luid=0x"
           << static_cast<std::uint32_t>(diagnostics.adapter_luid_high)
           << ':' << diagnostics.adapter_luid_low
           << " matching_hardware_transforms=" << std::dec
           << diagnostics.matching_hardware_transforms
           << " attempted_candidate_mask=0x" << std::hex
           << diagnostics.attempted_candidate_mask
           << " failed_candidate_mask=0x"
           << diagnostics.failed_candidate_mask << std::dec
           << " last_failure_status={"
           << describe_native_error(diagnostics.last_failure_status) << '}'
           << " capture_hresult={"
           << describe_native_error(diagnostics.capture_hresult) << '}'
           << " publisher_socket_error={"
           << describe_native_error(static_cast<std::int32_t>(
                  diagnostics.publisher_socket_error)) << '}';
    if (diagnostics.has_failed_candidate) {
        detail << " last_failed_candidate="
               << encoder_candidate_name(diagnostics.last_failed_candidate);
    }
    return detail.str();
}

std::string describe_application_start_failure(
    const HostApplication& application) {
    std::ostringstream detail;
    detail << "host_start_stage="
           << host_application_start_stage_name(application.last_start_stage())
           << " native_error={"
           << describe_native_error(application.last_error()) << '}';
    if (const auto* diagnostics = application.encoder_diagnostics();
        diagnostics != nullptr) {
        detail << " encoder_diagnostics={"
               << describe_encoder_diagnostics(*diagnostics) << '}';
    }
    detail << ' ' << capture_stack_addresses();
    return detail.str();
}

void write_host_encoder_selected_event(const HostApplication& application) {
    const auto* diagnostics = application.encoder_diagnostics();
    if (diagnostics == nullptr) return;
    write_host_event(
        "host_encoder_selected", describe_encoder_diagnostics(*diagnostics));
}

std::string describe_video_failure(const DesktopVideoStepMetrics& video) {
    const auto failure_stage = [](DesktopVideoStepStatus status) noexcept -> std::string_view {
        switch (status) {
            case DesktopVideoStepStatus::frame_published: return "frame_published";
            case DesktopVideoStepStatus::data_plane_closed: return "data_plane_closed";
            case DesktopVideoStepStatus::capture_timeout: return "capture_timeout";
            case DesktopVideoStepStatus::capture_access_lost: return "capture_access_lost";
            case DesktopVideoStepStatus::capture_device_removed: return "capture_device_removed";
            case DesktopVideoStepStatus::capture_failed: return "capture";
            case DesktopVideoStepStatus::bridge_failed: return "frame_bridge";
            case DesktopVideoStepStatus::encode_failed: return "encode";
            case DesktopVideoStepStatus::publish_failed: return "udp_publish";
            case DesktopVideoStepStatus::frame_queued: return "frame_queued";
            case DesktopVideoStepStatus::capture_pointer_only: return "capture_pointer_only";
            case DesktopVideoStepStatus::capture_outside_region: return "capture_outside_region";
            case DesktopVideoStepStatus::staging_busy: return "staging_busy";
        }
        return "unknown";
    };
    std::ostringstream detail;
    detail << "failure_stage=" << failure_stage(video.status)
           << " status=" << static_cast<std::int32_t>(video.status)
           << " frame_id=" << video.frame_id
           << " native_status={" << describe_native_error(video.native_status) << '}'
           << " bridge_mode=" << static_cast<std::int32_t>(video.bridge_mode)
           << " encoder_backend=" << static_cast<std::int32_t>(video.encoder_backend)
           << " capture_vendor=" << static_cast<std::int32_t>(video.capture_vendor)
           << " encoder_vendor=" << static_cast<std::int32_t>(video.encoder_vendor)
           << " encoder_same_adapter=" << video.encoder_same_adapter
           << " zero_copy=" << video.zero_copy
           << " asynchronous_pipeline=" << video.asynchronous_pipeline
           << " async_shared_same_adapter="
           << video.async_shared_same_adapter
           << " encoder_timing_fps=" << video.encoder_timing_fps
           << " nvenc_stage=" << static_cast<std::int32_t>(video.nvenc_stage)
           << " media_foundation_stage=" << static_cast<std::int32_t>(video.media_foundation_stage)
           << " capture_us=" << video.capture_us
           << " readback_wait_us=" << video.readback_wait_us
           << " readback_copy_us=" << video.readback_copy_us
           << " bridge_us=" << video.bridge_us
           << " upload_us=" << video.upload_us
           << " encode_us=" << video.encode_us
           << " publish_us=" << video.publish_us
           << " capture_to_publish_us=" << video.capture_to_publish_us;
    detail << " worker_frame_age_us=" << video.worker_frame_age_us
           << " mailbox_replaced=" << video.hybrid_mailbox_replaced
           << " ring_busy=" << video.hybrid_ring_busy
           << " keyed_timeout=" << video.hybrid_keyed_timeout
           << " latest_worker_frame_age_us="
           << video.hybrid_latest_worker_frame_age_us
           << " maximum_worker_frame_age_us="
           << video.hybrid_maximum_worker_frame_age_us;
    return detail.str();
}

std::string describe_cat6_session(const Cat6SessionSnapshot& session) {
    std::ostringstream detail;
    detail << "transport=" << session.transport
           << " host_ipv4=" << (session.host_ipv4.empty() ? "auto" : session.host_ipv4)
           << " mobile_ipv4=" << session.mobile_ipv4
           << " loss=" << session.quality.packet_loss_ratio
           << " jitter_ms=" << session.quality.jitter_ms
           << " rtt_ms=" << session.quality.rtt_ms
           << " throughput_mbps=" << session.quality.throughput_mbps
           << " probe_samples=" << session.quality.probe_samples;
    return detail.str();
}

std::string describe_direct_link(const HostDirectLinkProvisioningResult& direct_link) {
    std::ostringstream detail;
    detail << "status=" << host_direct_link_status_name(direct_link.status)
           << " downstream_name=[" << utf8_from_wide(direct_link.downstream_name) << ']'
           << " upstream_name=[" << utf8_from_wide(direct_link.upstream_name) << ']'
           << " detail=" << direct_link.detail
           << " snapshot_path=" << direct_link.snapshot_path
           << " snapshot_sha256=" << direct_link.snapshot_sha256;
    return detail.str();
}

std::string describe_direct_link_restore(
    const HostDirectLinkRestorationResult& restoration) {
    std::ostringstream detail;
    detail << "status=" << host_direct_link_restore_status_name(restoration.status)
           << " downstream_name=[" << utf8_from_wide(restoration.downstream_name) << ']'
           << " detail=" << restoration.detail
           << " snapshot_path=" << restoration.snapshot_path
           << " snapshot_sha256=" << restoration.snapshot_sha256;
    return detail.str();
}

std::string describe_firewall(const HostFirewallProvisioningResult& firewall) {
    std::ostringstream detail;
    detail << "status=" << host_firewall_status_name(firewall.status)
           << " checked_rules=" << firewall.checked_rules
           << " changed_rules=" << firewall.changed_rules
           << " detail=" << firewall.detail;
    return detail.str();
}

HostFirewallProvisioningResult ensure_runtime_firewall() {
    return ensure_host_firewall_rules_automatically();
}

/** Keeps the firewall self-heal contract off the capture/publish hot path. */
class RuntimeFirewallAuditor final {
public:
    ~RuntimeFirewallAuditor() { stop(); }

    [[nodiscard]] bool start() noexcept {
        if (worker_.joinable()) return false;
        {
            std::lock_guard lock(mutex_);
            result_.reset();
        }
        try {
            worker_ = std::jthread([this](std::stop_token stop_token) {
                if (stop_token.stop_requested()) return;
                HostFirewallProvisioningResult result;
                try {
                    result = ensure_runtime_firewall();
                } catch (const std::exception& error) {
                    result.status = HostFirewallStatus::failed;
                    result.detail = "audit_exception";
                    write_emergency_event(
                        "firewall_auditor_exception",
                        "host_firewall_audit_failed", error.what());
                } catch (...) {
                    result.status = HostFirewallStatus::failed;
                    result.detail = "audit_unknown_exception";
                    write_emergency_event(
                        "firewall_auditor_unknown_exception",
                        "host_firewall_audit_failed", "unknown");
                }
                if (stop_token.stop_requested()) return;
                std::lock_guard lock(mutex_);
                result_ = std::move(result);
            });
        } catch (...) {
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<HostFirewallProvisioningResult>
    take_result() noexcept {
        std::optional<HostFirewallProvisioningResult> result;
        {
            std::lock_guard lock(mutex_);
            if (!result_.has_value()) return std::nullopt;
            result = std::move(result_);
            result_.reset();
        }
        join_worker();
        return result;
    }

    [[nodiscard]] bool running() const noexcept {
        return worker_.joinable();
    }

    void stop() noexcept {
        if (worker_.joinable()) worker_.request_stop();
        join_worker();
        std::lock_guard lock(mutex_);
        result_.reset();
    }

private:
    void join_worker() noexcept {
        if (!worker_.joinable()) return;
        try {
            worker_.join();
        } catch (const std::exception& error) {
            write_emergency_event(
                "firewall_auditor_join_exception",
                "host_firewall_audit_join_failed", error.what());
        } catch (...) {
            write_emergency_event(
                "firewall_auditor_join_unknown_exception",
                "host_firewall_audit_join_failed", "unknown");
        }
    }

    mutable std::mutex mutex_;
    std::optional<HostFirewallProvisioningResult> result_;
    std::jthread worker_;
};

std::string describe_dhcp(const IsolatedDhcpMetrics& metrics) {
    const auto startup_stage =
        static_cast<IsolatedDhcpStartupStage>(metrics.startup_stage);
    std::ostringstream detail;
    detail << "received_packets=" << metrics.received_packets
           << " interface_index=" << metrics.interface_index
           << " startup_stage="
           << isolated_dhcp_startup_stage_name(startup_stage)
           << " startup_stage_code=" << metrics.startup_stage
           << " interface_match_count=" << metrics.interface_match_count
           << " discovers=" << metrics.discovers
           << " offers=" << metrics.offers
           << " requests=" << metrics.requests
           << " acknowledgements=" << metrics.acknowledgements
           << " rejected_packets=" << metrics.rejected_packets
           << " malformed_packets=" << metrics.malformed_packets
           << " local_interface_packets=" << metrics.local_interface_packets
           << " client_conflict_packets=" << metrics.client_conflict_packets
           << " request_state_packets=" << metrics.request_state_packets
           << " address_mismatch_packets=" << metrics.address_mismatch_packets
           << " explicit_source_sends=" << metrics.explicit_source_sends
           << " inbound_interface_drops=" << metrics.inbound_interface_drops
           << " inbound_unverified_drops=" << metrics.inbound_unverified_drops
           << " interface_filter_active=" << metrics.interface_filter_active
           << " interface_filter_error={"
           << describe_native_error(static_cast<std::int32_t>(
                  metrics.interface_filter_error)) << '}'
           << " packet_info_active=" << metrics.packet_info_active
           << " packet_info_error={"
           << describe_native_error(static_cast<std::int32_t>(
                  metrics.packet_info_error)) << '}'
           << " last_reject_reason="
           << isolated_dhcp_reject_reason_name(metrics.last_reject_reason)
           << " send_failures=" << metrics.send_failures
           << " last_send_error={"
           << describe_native_error(static_cast<std::int32_t>(
                  metrics.last_send_error)) << '}';
    return detail.str();
}

std::string narrow_display_id(const std::wstring& device_name) {
    std::string value;
    value.reserve(device_name.size());
    for (const wchar_t character : device_name) {
        value.push_back(character >= 0 && character <= 0x7f
            ? static_cast<char>(character) : '?');
    }
    return value;
}

bool refresh_capture_geometry(HostStreamSettings& settings) {
    const auto outputs = enumerate_host_display_outputs();
    const HostDisplayOutput* output = nullptr;

    // The GUI chooses the game display at the action boundary.  Retain that
    // exact attached output across ordinary capture/encoder recovery so an
    // Alt-Tab, notification or overlay cannot silently move the stream.
    if (!settings.display_id.empty()) {
        const auto* retained = select_matching_or_preferred_display_output(
            outputs, settings.display_id);
        if (retained != nullptr &&
            narrow_display_id(retained->device_name) == settings.display_id) {
            output = retained;
        }
    }

    HostDisplaySelection selection{};
    if (output == nullptr) {
        selection = select_host_display_output(
            outputs, enumerate_host_display_window_candidates());
        output = selection.output;
        if (output != nullptr) {
            settings.display_selection_reason =
                host_display_selection_reason_name(selection.reason);
        }
    }
    if (output == nullptr) return false;
    const auto geometry = choose_centered_ai_capture_geometry(*output);
    if (geometry.fallback_reason == HostCaptureFallbackReason::invalid_display_extent) return false;
    settings.adapter_index = output->adapter_index;
    settings.output_index = output->output_index;
    settings.width = geometry.encoder_width;
    settings.height = geometry.encoder_height;
    settings.capture_region = DesktopCaptureRegion{
        static_cast<std::int32_t>(geometry.local_roi_x),
        static_cast<std::int32_t>(geometry.local_roi_y),
        geometry.local_roi_width, geometry.local_roi_height};
    settings.display_id = narrow_display_id(output->device_name);
    settings.display_left = geometry.display_rect.left;
    settings.display_top = geometry.display_rect.top;
    settings.display_right = geometry.display_rect.right;
    settings.display_bottom = geometry.display_rect.bottom;
    settings.roi_left = geometry.roi_rect.left;
    settings.roi_top = geometry.roi_rect.top;
    settings.roi_right = geometry.roi_rect.right;
    settings.roi_bottom = geometry.roi_rect.bottom;
    settings.source_width = geometry.source_width;
    settings.source_height = geometry.source_height;
    settings.fallback_reason = host_capture_fallback_reason_name(geometry.fallback_reason);
    settings.encoder_timing_fps =
        encoder_timing_hint_for_display_refresh(output->refresh_hz);
    return true;
}

bool read_stop_requested(std::mutex& mutex, const bool& flag) {
    std::lock_guard lock(mutex);
    return flag;
}

bool wait_for_retry_or_stop(
    std::mutex& mutex, const bool& stop_requested,
    std::chrono::milliseconds retry_delay) {
    const auto retry_at = std::chrono::steady_clock::now() + retry_delay;
    while (std::chrono::steady_clock::now() < retry_at) {
        if (read_stop_requested(mutex, stop_requested)) return false;
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            retry_at - std::chrono::steady_clock::now());
        std::this_thread::sleep_for((std::min)(std::chrono::milliseconds(20), remaining));
    }
    return !read_stop_requested(mutex, stop_requested);
}

}  // namespace

void log_host_runtime_event(std::string_view event, std::string_view detail) {
    write_host_event(event, detail);
}

HostRuntimeService::HostRuntimeService(
    IsolatedDhcpServer* isolated_dhcp_server,
    std::shared_ptr<HostDataPlaneAuthorizationGate> authorization_gate)
    : isolated_dhcp_server_(isolated_dhcp_server),
      authorization_gate_(authorization_gate != nullptr
          ? std::move(authorization_gate)
          : std::make_shared<HostDataPlaneAuthorizationGate>()) {
    write_host_event("host_process_start", describe_process_context());
}
HostRuntimeService::~HostRuntimeService() { stop(); }

bool HostRuntimeService::start(const HostStreamSettings& settings, std::string& error) {
    stop();
    const std::int64_t roi_right =
        static_cast<std::int64_t>(settings.capture_region.x) +
        settings.capture_region.width;
    const std::int64_t roi_bottom =
        static_cast<std::int64_t>(settings.capture_region.y) +
        settings.capture_region.height;
    if (settings.width != kAiCaptureEdge || settings.height != kAiCaptureEdge ||
        settings.encoder_timing_fps == 0 ||
        settings.capture_region.x < 0 || settings.capture_region.y < 0 ||
        settings.capture_region.width == 0 || settings.capture_region.height == 0 ||
        settings.source_width == 0 || settings.source_height == 0 ||
        roi_right <= settings.capture_region.x ||
        roi_bottom <= settings.capture_region.y ||
        roi_right > settings.source_width || roi_bottom > settings.source_height) {
        std::ostringstream detail;
        detail << "invalid host stream settings"
               << " encoder_size=" << settings.width << 'x' << settings.height
               << " encoder_timing_fps=" << settings.encoder_timing_fps
               << " source_size=" << settings.source_width << 'x'
               << settings.source_height
               << " capture_region=" << settings.capture_region.x << ','
               << settings.capture_region.y << ','
               << settings.capture_region.width << 'x'
               << settings.capture_region.height << ' '
               << capture_stack_addresses();
        error = detail.str();
        write_host_event("host_start_rejected", error);
        return false;
    }
    if (authorization_gate_ == nullptr ||
        !authorization_gate_->permits_data_plane()) {
        error =
            "Authenticated Host/Android peer session and a current verified "
            "server usage lease are required before Host streaming can start.";
        write_host_event(
            "host_start_rejected",
            "reason=host_authorization_closed secure_data_plane_required=true");
        return false;
    }
    {
        std::lock_guard lock(mutex_);
        last_metrics_.reset();
        last_error_.clear();
        stop_requested_ = false;
        start_finished_ = false;
        running_ = false;
        startup_stop_source_ = std::stop_source{};
    }
    const std::stop_token startup_token = startup_stop_source_.get_token();
    try {
        worker_ = std::thread([this, settings, startup_token] {
            g_host_attempt_id = allocate_host_attempt_id();
            try {
                run(settings, startup_token);
            } catch (const std::exception& error) {
                const std::string detail =
                    "exception_type=std::exception what=[" + std::string{error.what()} +
                    "] " + capture_stack_addresses();
                write_host_event("host_worker_exception", detail);
                std::lock_guard lock(mutex_);
                last_error_ = "Host worker exception: " + detail;
                running_ = false;
                start_finished_ = true;
                start_condition_.notify_all();
            } catch (...) {
                const std::string detail =
                    "exception_type=unknown " + capture_stack_addresses();
                write_host_event("host_worker_exception", detail);
                std::lock_guard lock(mutex_);
                last_error_ = "Host worker unknown exception: " + detail;
                running_ = false;
                start_finished_ = true;
                start_condition_.notify_all();
            }
            g_host_attempt_id = 0U;
        });
    } catch (const std::exception& thread_error) {
        const std::string detail =
            "Host worker thread creation failed: exception_type=std::exception what=[" +
            std::string{thread_error.what()} + "] " + capture_stack_addresses();
        {
            std::lock_guard lock(mutex_);
            last_error_ = detail;
            running_ = false;
            start_finished_ = true;
            error = last_error_;
        }
        write_host_event("host_worker_thread_create_failed", detail);
        return false;
    } catch (...) {
        const std::string detail =
            "Host worker thread creation failed: exception_type=unknown " +
            capture_stack_addresses();
        {
            std::lock_guard lock(mutex_);
            last_error_ = detail;
            running_ = false;
            start_finished_ = true;
            error = last_error_;
        }
        write_host_event("host_worker_thread_create_failed", detail);
        return false;
    }
    std::unique_lock lock(mutex_);
    start_condition_.wait(lock, [this] { return start_finished_; });
    error = last_error_;
    return running_;
}

void HostRuntimeService::request_stop() noexcept {
    if (authorization_gate_ != nullptr) authorization_gate_->stop();
    {
        std::lock_guard lock(mutex_);
        stop_requested_ = true;
        startup_stop_source_.request_stop();
    }
}

void HostRuntimeService::stop() noexcept {
    if (authorization_gate_ != nullptr) authorization_gate_->stop();
    const bool worker_joinable = worker_.joinable();
    bool should_log_stop_request = false;
    {
        std::lock_guard lock(mutex_);
        should_log_stop_request =
            running_ || (worker_joinable && !start_finished_);
        stop_requested_ = true;
        startup_stop_source_.request_stop();
    }
    if (should_log_stop_request) write_host_event("host_stop_requested");
    try {
        if (worker_.joinable()) worker_.join();
    } catch (...) {
        try {
            write_host_event("host_stop_join_failed");
        } catch (...) {
        }
    }
}

void HostRuntimeService::restore_direct_link_on_clean_shutdown() noexcept {
    if (isolated_dhcp_server_ != nullptr) isolated_dhcp_server_->stop();
    const HostDirectLinkRestorationResult restoration =
        restore_host_direct_link_ipv4_automatically();
    write_host_event(
        "host_direct_link_clean_shutdown_restore",
        describe_direct_link_restore(restoration));
}

bool HostRuntimeService::is_running() const noexcept {
    std::lock_guard lock(mutex_);
    return running_;
}

std::optional<HostStreamMetrics> HostRuntimeService::last_metrics() const {
    std::lock_guard lock(mutex_);
    return last_metrics_;
}

std::string HostRuntimeService::last_error() const {
    std::lock_guard lock(mutex_);
    return last_error_;
}

void HostRuntimeService::run(HostStreamSettings settings, std::stop_token startup_stop_token) {
    {
        std::ostringstream detail;
        detail << "display_id=" << settings.display_id
               << " adapter_index=" << settings.adapter_index
               << " output_index=" << settings.output_index
               << " encoder_size=" << settings.width << 'x' << settings.height
               << " encoder_timing_fps=" << settings.encoder_timing_fps;
        write_host_event("host_start_attempt", detail.str());
    }
    if (!refresh_capture_geometry(settings)) {
        std::lock_guard lock(mutex_);
        last_error_ =
            "No active Windows display is available for the centered " +
            std::to_string(kAiCaptureEdge) + "x" + std::to_string(kAiCaptureEdge) +
            " capture region; failure_stage=display_refresh " +
            capture_stack_addresses();
        write_host_event("host_display_refresh_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    write_host_capture_geometry_event(settings);
    write_host_event(
        "host_cat6_bootstrap_started",
        "peer_evidence_timeout_ms=" + std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kHostInitialCat6PeerEvidenceTimeout).count()) +
            " adapter_address_state_is_candidate_only=true");
    write_host_event(
        "host_ipv4_unicast_table_before_cat6_bootstrap",
        describe_host_ipv4_unicast_table());
    const auto bootstrap = bootstrap_host_cat6_link(
        kHostInitialCat6PeerEvidenceTimeout,
        isolated_dhcp_server_,
        startup_stop_token);
    write_host_event(
        "host_ipv4_unicast_table_after_cat6_bootstrap",
        describe_host_ipv4_unicast_table());
    if (!bootstrap.diagnostics.empty()) {
        write_host_event(
            "host_cat6_bootstrap_diagnostic",
            summarize_bootstrap_diagnostics(bootstrap.diagnostics));
    }
    write_host_event("host_direct_link_bootstrap", describe_direct_link(bootstrap.direct_link));
    if (bootstrap.firewall_attempted) {
        write_host_event("host_firewall_bootstrap", describe_firewall(bootstrap.firewall));
    } else {
        write_host_event(
            "host_firewall_bootstrap_skipped",
            "blocked_by=direct_link direct_link_status=" +
                std::string(host_direct_link_status_name(bootstrap.direct_link.status)));
    }
    const HostCat6BootstrapFailureStage bootstrap_failure_stage =
        classify_host_cat6_bootstrap_failure(bootstrap);
    if (isolated_dhcp_server_ != nullptr &&
        (bootstrap.dhcp_start_attempted || bootstrap.dhcp_started)) {
        write_host_event(
            "host_dhcp_bootstrap",
            "start_attempted=1 started=" + std::to_string(bootstrap.dhcp_started) +
                " running=" + std::to_string(isolated_dhcp_server_->running()) + " " +
                "failure_stage=" +
                host_cat6_bootstrap_failure_stage_name(bootstrap_failure_stage) +
                " native_error={" +
                describe_native_error(static_cast<std::int32_t>(
                    bootstrap.dhcp_native_error)) + "}" +
                " detail={" + bootstrap.dhcp_detail + "} " +
                describe_dhcp(isolated_dhcp_server_->metrics()));
    } else {
        write_host_event(
            "host_dhcp_bootstrap_skipped",
            "start_attempted=0 started=0 failure_stage=" +
                std::string(host_cat6_bootstrap_failure_stage_name(
                    bootstrap_failure_stage)) +
                " detail={" + bootstrap.dhcp_detail + "}");
    }
    write_host_event(
        "host_mobile_ready_wait",
        "attempted=" + std::to_string(bootstrap.mobile_wait_attempted) +
            " result=" +
            std::string(bootstrap.mobile.has_value() ? "ready" : "not_ready") +
            " timeout_ms=" +
            std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                kHostInitialCat6PeerEvidenceTimeout).count()) +
            " address_watch={" +
            (bootstrap.address_watch.size() > 1500
                ? bootstrap.address_watch.substr(0, 1500)
                : bootstrap.address_watch) +
            "}");
    if (startup_stop_token.stop_requested()) {
        std::lock_guard lock(mutex_);
        last_error_ = kHostStartupCancelledError;
        write_host_event("host_cat6_bootstrap_cancelled");
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    std::optional<Cat6SessionSnapshot> selected_mobile = bootstrap.mobile;
    HostFirewallProvisioningResult wireless_firewall{};
    bool wireless_firewall_attempted = false;
    std::string wireless_discovery_diagnostic{"not_attempted"};
    if (!selected_mobile.has_value() && !startup_stop_token.stop_requested()) {
        write_host_event(
            "host_wireless_lan_fallback_started",
            "reason=cat6_unavailable discovery_ipv4=" +
                std::string{kWirelessLanDiscoveryIpv4} +
                " timeout_ms=" + std::to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        kWirelessLanDiscoveryTimeout).count()));
        wireless_firewall_attempted = true;
        wireless_firewall = ensure_runtime_firewall();
        write_host_event(
            "host_wireless_lan_firewall",
            describe_firewall(wireless_firewall));
        if (host_firewall_is_ready(wireless_firewall.status)) {
            WirelessLanDiscoveryOutcome wireless_discovery =
                discover_wireless_lan_mobile_session(
                kWirelessLanDiscoveryTimeout,
                startup_stop_token);
            selected_mobile = std::move(wireless_discovery.session);
            wireless_discovery_diagnostic = std::move(wireless_discovery.diagnostic);
        }
        write_host_event(
            selected_mobile.has_value()
                ? "host_wireless_lan_fallback_ready"
                : "host_wireless_lan_fallback_not_ready",
            selected_mobile.has_value()
                ? describe_cat6_session(*selected_mobile) +
                    " discovery={" + wireless_discovery_diagnostic + "}"
                : "firewall_status=" + std::string{
                    host_firewall_status_name(wireless_firewall.status)} +
                    " firewall_detail={" + wireless_firewall.detail +
                    "} discovery={" + wireless_discovery_diagnostic + '}');
    }
    if (!selected_mobile.has_value()) {
        std::lock_guard lock(mutex_);
        if (bootstrap_failure_stage == HostCat6BootstrapFailureStage::direct_link) {
            last_error_ = "CAT6 direct-link provisioning failed: status=" +
                std::string(host_direct_link_status_name(bootstrap.direct_link.status)) +
                " detail=" + bootstrap.direct_link.detail;
        } else if (bootstrap_failure_stage == HostCat6BootstrapFailureStage::firewall) {
            last_error_ = "CAT6 firewall provisioning failed: status=" +
                std::string(host_firewall_status_name(bootstrap.firewall.status)) +
                " detail=" + bootstrap.firewall.detail;
        } else if (bootstrap_failure_stage == HostCat6BootstrapFailureStage::dhcp) {
            last_error_ =
                "CAT6 DHCP bootstrap failed; failure_stage=dhcp start_attempted=" +
                std::to_string(bootstrap.dhcp_start_attempted) +
                " started=" + std::to_string(bootstrap.dhcp_started) +
                " native_error={" +
                describe_native_error(static_cast<std::int32_t>(
                    bootstrap.dhcp_native_error)) +
                "} detail={" + bootstrap.dhcp_detail + '}';
        } else if (bootstrap_failure_stage ==
                   HostCat6BootstrapFailureStage::mobile_ready_timeout) {
            last_error_ = "VF Mobile CAT6-ready heartbeat was not received; direct-link status=" +
                std::string(host_direct_link_status_name(bootstrap.direct_link.status)) +
                " mobile_wait_attempted=" +
                std::to_string(bootstrap.mobile_wait_attempted) + ".";
            if (isolated_dhcp_server_ != nullptr) {
                const IsolatedDhcpMetrics dhcp_metrics = isolated_dhcp_server_->metrics();
                if (dhcp_metrics.received_packets == 0U) {
                    last_error_ +=
                        " Host DHCP received zero packets from the mobile endpoint; "
                        "the Android Ethernet adapter is physically present but is "
                        "not exposing an app-usable IPv4 network, so the phone cannot "
                        "start the CAT6 ready agent.";
                }
            }
        } else {
            last_error_ = "CAT6 bootstrap failed with inconsistent result; failure_stage=" +
                std::string(host_cat6_bootstrap_failure_stage_name(
                    bootstrap_failure_stage));
        }
        const std::string cat6_failure_context = last_error_;
        last_error_ =
            "Automatic wireless-LAN UDP fallback was unavailable; "
            "wireless_discovery={" + wireless_discovery_diagnostic + "}.";
        if (wireless_firewall_attempted) {
            last_error_ += " wireless_firewall_status=" + std::string{
                host_firewall_status_name(wireless_firewall.status)} +
                " wireless_firewall_detail={" + wireless_firewall.detail + '}';
        }
        last_error_ += " CAT6_context={" + cat6_failure_context + "}.";
        last_error_ += " " + capture_stack_addresses();
        write_host_event("host_cat6_bootstrap_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    const auto& mobile = selected_mobile;
    settings.local_host = mobile->host_ipv4;
    settings.phone_host = mobile->mobile_ipv4;
    settings.transport = mobile->transport;
    write_host_event(
        mobile->transport == kCat6TransportName
            ? "host_cat6_ready" : "host_wireless_lan_ready",
        describe_cat6_session(*mobile));
    Cat6SessionSnapshot active_session = *mobile;
    const std::string metrics_path = resolve_metrics_path();
    if (metrics_path.empty()) {
        std::lock_guard lock(mutex_);
        last_error_ =
            "Unable to create the host metrics path; stage=metrics_path_resolve " +
            capture_stack_addresses();
        write_host_event("host_runtime_initialization_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    const std::filesystem::path stream_epoch_state_path =
        resolve_stream_epoch_state_path();
    if (stream_epoch_state_path.empty()) {
        std::lock_guard lock(mutex_);
        last_error_ =
            "Unable to create the persistent stream epoch state path; "
            "stage=stream_epoch_state_resolve " + capture_stack_addresses();
        write_host_event("host_runtime_initialization_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    std::unique_ptr<vf::host::infrastructure::FileEpochReservationStore>
        stream_epoch_store;
    std::uint64_t stream_epoch{};
    try {
        stream_epoch_store = std::make_unique<
            vf::host::infrastructure::FileEpochReservationStore>(
                stream_epoch_state_path, kVideoStreamEpochMax);
        stream_epoch = stream_epoch_store->reserve_next();
    } catch (const std::exception& error) {
        std::lock_guard lock(mutex_);
        last_error_ =
            "Unable to reserve a crash-safe stream epoch; "
            "stage=stream_epoch_reservation detail=" + std::string{error.what()} +
            " " + capture_stack_addresses();
        write_host_event("host_runtime_initialization_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    HostApplication application;
    if (!application.start(create_runtime_config(
            settings, metrics_path, stream_epoch,
            [authorization_gate = authorization_gate_]() noexcept {
                return authorization_gate != nullptr &&
                    authorization_gate->permits_data_plane();
            }))) {
        std::lock_guard lock(mutex_);
        last_error_ =
            "Unable to initialize the DXGI/H.264/UDP host runtime; " +
            describe_application_start_failure(application);
        write_host_event("host_runtime_initialization_failed", last_error_);
        start_finished_ = true;
        start_condition_.notify_all();
        return;
    }
    write_host_encoder_selected_event(application);
    HostCat6Monitor cat6_monitor;
    bool cat6_monitor_active = cat6_monitor.start(active_session);
    if (!cat6_monitor_active) {
        write_host_event(
            "host_cat6_monitor_start_failed",
            "stage=initial_stream " + describe_cat6_session(active_session));
    }
    HostCat6MonitorSnapshot monitor_snapshot = cat6_monitor_active
        ? cat6_monitor.snapshot()
        : HostCat6MonitorSnapshot{
            .latest_session = active_session,
            .reachable = true,
            .recovery_required = false,
        };
    {
        std::lock_guard lock(mutex_);
        running_ = true;
        start_finished_ = true;
    }
    start_condition_.notify_all();
    write_host_event("host_stream_started",
                     "stream_epoch=" + std::to_string(stream_epoch) + " " +
                     describe_cat6_session(active_session));
    std::uint64_t published_offset = 0;
    std::uint64_t timeout_offset = 0;
    HostRecoveryPolicy recovery_policy;
    HostVideoForwardProgressPolicy video_forward_progress_policy;
    HostEncoderRecoveryPolicy encoder_recovery_policy({
        .skip_async_shared = settings.skip_async_shared_encoder,
        .skip_nvenc = settings.skip_nvenc_encoder,
        .force_software = settings.force_software_encoder,
    });
    HostPreferredProbeLogPolicy preferred_cat6_probe_log_policy;
    std::uint32_t successful_recoveries = 0U;
    bool last_mobile_probe_healthy = true;
    auto next_quality_event_at = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto next_firewall_audit_at =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    RuntimeFirewallAuditor firewall_auditor;
    std::mutex preferred_cat6_probe_mutex;
    std::optional<HostCat6BootstrapResult> preferred_cat6_probe_result;
    std::optional<Cat6SessionSnapshot> preferred_cat6_upgrade_session;
    std::jthread preferred_cat6_probe;
    auto next_preferred_cat6_probe_at = std::chrono::steady_clock::now();
    const auto stop_preferred_cat6_probe = [&] {
        if (preferred_cat6_probe.joinable()) {
            preferred_cat6_probe.request_stop();
            preferred_cat6_probe.join();
        }
        std::lock_guard lock(preferred_cat6_probe_mutex);
        preferred_cat6_probe_result.reset();
    };
    const auto start_preferred_cat6_probe = [&] {
        write_host_event(
            "host_cat6_preferred_probe_started",
            "active_transport=" + active_session.transport +
                " retry_interval_ms=" + std::to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        kPreferredCat6ProbeRetryInterval).count()));
        preferred_cat6_probe = std::jthread(
            [this, &preferred_cat6_probe_mutex,
             &preferred_cat6_probe_result](std::stop_token stop_token) {
                HostCat6BootstrapResult result = bootstrap_host_cat6_link(
                    kHostCat6MobileReadyTimeout,
                    isolated_dhcp_server_,
                    stop_token);
                std::lock_guard lock(preferred_cat6_probe_mutex);
                preferred_cat6_probe_result = std::move(result);
            });
    };
    const auto take_preferred_cat6_probe_result = [&]()
        -> std::optional<HostCat6BootstrapResult> {
        std::optional<HostCat6BootstrapResult> result;
        {
            std::lock_guard lock(preferred_cat6_probe_mutex);
            if (!preferred_cat6_probe_result.has_value()) return std::nullopt;
            result = std::move(preferred_cat6_probe_result);
            preferred_cat6_probe_result.reset();
        }
        if (preferred_cat6_probe.joinable()) preferred_cat6_probe.join();
        return result;
    };
    const auto activate_recovered_session = [&, this](
        Cat6SessionSnapshot recovered_session,
        std::uint32_t recovery_attempt,
        std::string_view monitor_stage) {
        active_session = std::move(recovered_session);
        settings.local_host = active_session.host_ipv4;
        settings.phone_host = active_session.mobile_ipv4;
        settings.transport = active_session.transport;
        monitor_snapshot = HostCat6MonitorSnapshot{
            .latest_session = active_session,
            .reachable = true,
            .recovery_required = false,
        };
        cat6_monitor_active = cat6_monitor.start(active_session);
        if (!cat6_monitor_active) {
            write_host_event(
                "host_cat6_monitor_start_failed",
                "stage=" + std::string{monitor_stage} + " " +
                    describe_cat6_session(active_session));
        }
        last_mobile_probe_healthy = true;
        write_host_event(
            "host_cat6_link_recovered",
            "attempt=" + std::to_string(recovery_attempt) + " " +
                describe_cat6_session(active_session));
    };
    for (;;) {
        {
            std::lock_guard lock(mutex_);
            if (stop_requested_) break;
        }
        monitor_snapshot = cat6_monitor_active
            ? cat6_monitor.snapshot()
            : HostCat6MonitorSnapshot{
                .latest_session = active_session,
                .reachable = true,
                .recovery_required = false,
            };
        if (monitor_snapshot.latest_session.has_value()) {
            active_session = *monitor_snapshot.latest_session;
        }
        if (monitor_snapshot.reachable != last_mobile_probe_healthy) {
            last_mobile_probe_healthy = monitor_snapshot.reachable;
            write_host_event(
                monitor_snapshot.reachable ? "host_cat6_probe_recovered"
                                           : "host_cat6_probe_degraded",
                "consecutive_probe_failures=" +
                    std::to_string(monitor_snapshot.consecutive_failures) +
                    " monitor_faults=" +
                    std::to_string(monitor_snapshot.monitor_faults) +
                    " last_success_age_ms=" +
                    std::to_string(monitor_snapshot.last_success_age_ms) +
                    " recovery_required=" +
                    std::to_string(monitor_snapshot.recovery_required) +
                    " action=" +
                    std::string(monitor_snapshot.recovery_required
                        ? "recover_link" : "continue_streaming"));
        }
        const bool step_succeeded = application.publish_next();
        const auto& stats = application.stats();
        {
            std::lock_guard lock(mutex_);
            last_metrics_ = copy_metrics(stats, published_offset, timeout_offset, stream_epoch,
                                         successful_recoveries,
                                         active_session, monitor_snapshot, settings);
        }
        const auto now = std::chrono::steady_clock::now();
        const HostVideoForwardProgressDecision video_progress =
            video_forward_progress_policy.observe({
                .monotonic_time_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch()).count()),
                .published_frames = published_offset + stats.published_frames,
                .publication_expected =
                    stats.last_video_step.status !=
                        DesktopVideoStepStatus::data_plane_closed,
                .fresh_frame_published =
                    stats.last_video_step.status ==
                        DesktopVideoStepStatus::frame_published &&
                    !stats.last_video_step.repeated_content,
                .capture_to_publish_us =
                    stats.last_video_step.capture_to_publish_us,
            });
        if (auto probe_result = take_preferred_cat6_probe_result()) {
            if (probe_result->mobile.has_value() &&
                probe_result->mobile->transport == kCat6TransportName) {
                preferred_cat6_probe_log_policy.reset();
                if (!probe_result->diagnostics.empty()) {
                    write_host_event(
                        "host_cat6_preferred_probe_diagnostic",
                        summarize_bootstrap_diagnostics(probe_result->diagnostics));
                }
                preferred_cat6_upgrade_session = *probe_result->mobile;
                write_host_event(
                    "host_cat6_preferred_upgrade_ready",
                    describe_cat6_session(*preferred_cat6_upgrade_session));
            } else {
                if (preferred_cat6_probe_log_policy.should_log_failure(
                        make_preferred_probe_failure_state(*probe_result), now)) {
                    if (!probe_result->diagnostics.empty()) {
                        write_host_event(
                            "host_cat6_preferred_probe_diagnostic",
                            summarize_bootstrap_diagnostics(
                                probe_result->diagnostics));
                    }
                    write_host_event(
                        "host_cat6_preferred_probe_not_ready",
                        "failure_stage=" + std::string{
                            host_cat6_bootstrap_failure_stage_name(
                                classify_host_cat6_bootstrap_failure(*probe_result))} +
                            " direct_link_status=" + std::string{
                                host_direct_link_status_name(
                                    probe_result->direct_link.status)} +
                            " detail={" + probe_result->direct_link.detail + '}');
                }
                next_preferred_cat6_probe_at =
                    now + kPreferredCat6ProbeRetryInterval;
            }
        }
        const bool active_transport_is_cat6 =
            active_session.transport == kCat6TransportName;
        if (should_start_preferred_cat6_probe(
                active_transport_is_cat6,
                preferred_cat6_probe.joinable(),
                preferred_cat6_upgrade_session.has_value(),
                now >= next_preferred_cat6_probe_at)) {
            start_preferred_cat6_probe();
        }
        if (auto firewall_health = firewall_auditor.take_result()) {
            if (firewall_health->status == HostFirewallStatus::provisioned) {
                write_host_event(
                    "host_firewall_self_healed",
                    describe_firewall(*firewall_health));
            } else if (!host_firewall_is_ready(firewall_health->status)) {
                write_host_event(
                    "host_firewall_health_failed",
                    describe_firewall(*firewall_health));
            }
        }
        if (now >= next_firewall_audit_at &&
            !preferred_cat6_probe.joinable() &&
            !firewall_auditor.running()) {
            if (!firewall_auditor.start()) {
                write_host_event(
                    "host_firewall_audit_start_failed",
                    "action=continue_streaming next_retry_ms=5000");
            }
            next_firewall_audit_at = now + std::chrono::seconds(5);
        }
        if (now >= next_quality_event_at) {
            std::ostringstream detail;
            detail << describe_cat6_session(active_session)
                   << " mobile_reachable=" << monitor_snapshot.reachable
                   << " mobile_probe_failures=" << monitor_snapshot.consecutive_failures
                   << " mobile_monitor_faults=" << monitor_snapshot.monitor_faults
                   << " mobile_last_success_age_ms=" << monitor_snapshot.last_success_age_ms
                   << " mobile_recovery_required=" << monitor_snapshot.recovery_required
                   << " stream_epoch=" << stream_epoch
                   << " published_frames=" << published_offset + stats.published_frames
                   << " capture_timeouts=" << timeout_offset + stats.capture_timeouts
                    << " encoder_backend=" << static_cast<std::int32_t>(stats.last_video_step.encoder_backend)
                    << " capture_vendor=" << static_cast<std::int32_t>(stats.last_video_step.capture_vendor)
                    << " encoder_vendor=" << static_cast<std::int32_t>(stats.last_video_step.encoder_vendor)
                    << " encoder_same_adapter=" << stats.last_video_step.encoder_same_adapter
                    << " zero_copy=" << stats.last_video_step.zero_copy
                    << " asynchronous_pipeline=" << stats.last_video_step.asynchronous_pipeline
                    << " async_shared_same_adapter="
                    << stats.last_video_step.async_shared_same_adapter
                    << " bridge_mode=" << static_cast<std::int32_t>(stats.last_video_step.bridge_mode)
                    << " encoder_timing_fps=" << stats.last_video_step.encoder_timing_fps
                    << " capture_us=" << stats.last_video_step.capture_us
                    << " readback_wait_us=" << stats.last_video_step.readback_wait_us
                    << " readback_copy_us=" << stats.last_video_step.readback_copy_us
                    << " bridge_us=" << stats.last_video_step.bridge_us
                    << " upload_us=" << stats.last_video_step.upload_us
                    << " encode_us=" << stats.last_video_step.encode_us
                    << " publish_us=" << stats.last_video_step.publish_us
                    << " capture_to_publish_us=" << stats.last_video_step.capture_to_publish_us
                    << " access_unit_bytes=" << stats.last_video_step.access_unit_bytes
                    << " datagrams=" << stats.last_video_step.datagrams_sent
                    << " pointer_only_skips=" << stats.pointer_only_skips
                    << " outside_region_skips=" << stats.outside_region_skips
                    << " mouse_button_publisher_running="
                    << stats.mouse_button_publisher.running
                    << " mouse_button_transport_ready="
                    << stats.mouse_button_publisher.transport_ready
                    << " physical_button_mask="
                    << static_cast<std::uint32_t>(
                           stats.mouse_button_publisher.current_button_mask)
                    << " mouse_button_packets_sent="
                    << stats.mouse_button_publisher.packets_sent
                    << " mouse_button_send_failures="
                    << stats.mouse_button_publisher.send_failures
                    << " mouse_button_socket_error="
                    << stats.mouse_button_publisher.last_socket_error
                    << " dxgi_duplication_missed_presents="
                     << stats.last_video_step.missed_present_frames_total
                     << " static_content_repeats="
                     << stats.last_video_step.static_content_repeats
                     << " repeated_content="
                     << stats.last_video_step.repeated_content
                     << " staging_busy=" << stats.last_video_step.hybrid_staging_busy
                    << " map_was_still_drawing="
                    << stats.last_video_step.hybrid_was_still_drawing
                    << " mailbox_superseded="
                    << stats.last_video_step.hybrid_mailbox_superseded
                    << " mailbox_replaced="
                    << stats.last_video_step.hybrid_mailbox_replaced
                    << " ring_busy="
                    << stats.last_video_step.hybrid_ring_busy
                    << " keyed_timeout="
                    << stats.last_video_step.hybrid_keyed_timeout
                    << " worker_frame_age_us="
                    << stats.last_video_step.worker_frame_age_us
                    << " latest_worker_frame_age_us="
                    << stats.last_video_step.hybrid_latest_worker_frame_age_us
                    << " maximum_worker_frame_age_us="
                    << stats.last_video_step.hybrid_maximum_worker_frame_age_us
                     << " completion_metrics_dropped="
                     << stats.last_video_step.hybrid_completion_metrics_dropped
                     << " video_no_publish_progress_us="
                     << video_progress.no_publish_progress_us
                     << " video_forward_progress_failure="
                     << static_cast<std::int32_t>(video_progress.failure)
                     << " recovery_count=" << successful_recoveries
                     << " recovery_attempts=" << recovery_policy.total_failures()
                     << " recovery_streak=" << recovery_policy.consecutive_failures();
            write_host_event("host_cat6_quality", detail.str());
            next_quality_event_at = now + std::chrono::seconds(5);
        }
        const bool preferred_transport_upgrade_ready =
            should_commit_preferred_cat6_upgrade(
                active_transport_is_cat6,
                preferred_cat6_upgrade_session.has_value());
        const HostRecoveryCause recovery_cause = choose_host_recovery_cause(
            preferred_transport_upgrade_ready,
            monitor_snapshot.recovery_required,
            step_succeeded && !video_progress.recovery_required());
        if (recovery_cause == HostRecoveryCause::none) {
            if (stats.last_video_step.status == DesktopVideoStepStatus::frame_published &&
                recovery_policy.record_published_frame()) {
                write_host_event(
                    "host_stream_recovery_stabilized",
                    "stable_published_frames=" +
                        std::to_string(recovery_policy.stable_frames_to_reset()) +
                        " total_recovery_attempts=" +
                        std::to_string(recovery_policy.total_failures()));
            }
            continue;
        }
        std::string failure_detail;
        if (recovery_cause == HostRecoveryCause::preferred_transport_upgrade) {
            failure_detail =
                "transition_stage=preferred_transport_upgrade from_transport=" +
                active_session.transport + " to_transport=" +
                preferred_cat6_upgrade_session->transport;
        } else if (recovery_cause == HostRecoveryCause::cat6_link) {
            failure_detail =
                "failure_stage=cat6_link consecutive_probe_failures=" +
                std::to_string(monitor_snapshot.consecutive_failures) +
                " monitor_faults=" +
                std::to_string(monitor_snapshot.monitor_faults) +
                " last_success_age_ms=" +
                std::to_string(monitor_snapshot.last_success_age_ms);
        } else if (step_succeeded && video_progress.recovery_required()) {
            const std::string_view progress_failure =
                video_progress.failure ==
                        HostVideoForwardProgressFailure::publish_stalled
                    ? "publish_stalled"
                    : "fresh_frame_stale";
            failure_detail =
                "failure_stage=video_forward_progress progress_failure=" +
                std::string{progress_failure} +
                " no_publish_progress_us=" +
                std::to_string(video_progress.no_publish_progress_us) +
                " capture_to_publish_us=" +
                std::to_string(video_progress.capture_to_publish_us) +
                " published_frames=" +
                std::to_string(published_offset + stats.published_frames);
        } else {
            failure_detail = describe_video_failure(stats.last_video_step);
        }
        published_offset += stats.published_frames;
        timeout_offset += stats.capture_timeouts;
        const HostEncoderFailoverDecision encoder_failover =
            encoder_recovery_policy.record_failure(
                recovery_cause,
                host_video_failure_kind(stats.last_video_step.status),
                host_encoder_runtime_path(stats.last_video_step));
        settings.skip_async_shared_encoder =
            encoder_failover.breakers.skip_async_shared;
        settings.skip_nvenc_encoder = encoder_failover.breakers.skip_nvenc;
        settings.force_software_encoder = encoder_failover.breakers.force_software;
        if (encoder_failover.action ==
            HostEncoderFailoverAction::skip_async_shared) {
            write_host_event(
                "host_encoder_failover",
                "from=nvenc_same_adapter_async_shared "
                "to=nvenc_capture_device_then_hardware_mft_then_cpu " +
                    failure_detail);
        } else if (encoder_failover.action == HostEncoderFailoverAction::skip_nvenc) {
            // Covers both a real NVENC encode failure and a cross-adapter
            // bridge failure. Recovery then tries the adapter-bound hardware
            // MFT before the CPU codec, without adding an FPS scheduler cap.
            write_host_event(
                "host_encoder_failover",
                "from=" +
                    std::string(stats.last_video_step.status ==
                                    DesktopVideoStepStatus::bridge_failed
                                ? "nvenc_cross_adapter_bridge"
                                : "nvenc") +
                    " to=adapter_hardware_mft_then_cpu " + failure_detail);
        } else if (encoder_failover.action ==
                   HostEncoderFailoverAction::force_software) {
            // Never loop indefinitely on a hardware MFT that activates
            // successfully but rejects a real sample.
            write_host_event(
                "host_encoder_failover",
                "from=adapter_hardware_mft to=microsoft_software " +
                    failure_detail);
        }
        stop_preferred_cat6_probe();
        firewall_auditor.stop();
        application.stop();
        if (recovery_cause != HostRecoveryCause::video_pipeline) {
            cat6_monitor.stop();
            cat6_monitor_active = false;
        }

        std::string recovery_stage;
        if (recovery_cause == HostRecoveryCause::preferred_transport_upgrade) {
            recovery_stage = "preferred_transport_upgrade";
        } else if (recovery_cause == HostRecoveryCause::cat6_link) {
            recovery_stage = "cat6_link";
        } else {
            recovery_stage = "video_pipeline";
        }
        std::string recovery_detail = failure_detail;
        std::optional<Cat6SessionSnapshot> ready_preferred_session;
        if (recovery_cause == HostRecoveryCause::preferred_transport_upgrade) {
            ready_preferred_session =
                std::exchange(preferred_cat6_upgrade_session, std::nullopt);
            write_host_event(
                "host_cat6_preferred_upgrade_scheduled",
                recovery_detail);
        }
        bool recovered = false;
        while (!read_stop_requested(mutex_, stop_requested_)) {
            const bool committing_preferred_transport =
                ready_preferred_session.has_value();
            const HostRecoveryDecision decision = committing_preferred_transport
                ? HostRecoveryDecision{
                    0U,
                    recovery_policy.total_failures(),
                    std::chrono::milliseconds::zero(),
                    false}
                : recovery_policy.record_failure();
            std::ostringstream scheduled_detail;
            scheduled_detail
                << "recovery_stage=" << recovery_stage
                << " attempt=" << decision.consecutive_failures
                << " total_recovery_attempts=" << decision.total_failures
                << " retry_delay_ms=" << decision.retry_delay.count()
                << " backoff_capped=" << decision.backoff_capped
                << " " << recovery_detail;
            {
                std::lock_guard lock(mutex_);
                last_error_ = "Host stream is recovering: " + scheduled_detail.str();
            }
            write_host_event("host_stream_recovery_scheduled", scheduled_detail.str());
            if (!wait_for_retry_or_stop(
                    mutex_, stop_requested_, decision.retry_delay)) {
                break;
            }
            if (cat6_monitor_active) {
                const HostCat6MonitorSnapshot recovery_monitor = cat6_monitor.snapshot();
                if (recovery_monitor.recovery_required) {
                    cat6_monitor.stop();
                    cat6_monitor_active = false;
                    recovery_stage = "cat6_link";
                    recovery_detail =
                        "failure_stage=cat6_link consecutive_probe_failures=" +
                        std::to_string(recovery_monitor.consecutive_failures) +
                        " monitor_faults=" +
                        std::to_string(recovery_monitor.monitor_faults) +
                        " last_success_age_ms=" +
                        std::to_string(recovery_monitor.last_success_age_ms);
                    write_host_event(
                        "host_stream_recovery_attempt_failed",
                        "attempt=" + std::to_string(decision.consecutive_failures) +
                            " " + recovery_detail);
                    continue;
                }
                if (recovery_monitor.latest_session.has_value()) {
                    active_session = *recovery_monitor.latest_session;
                }
            }
            if (!cat6_monitor_active) {
                if (ready_preferred_session.has_value()) {
                    activate_recovered_session(
                        *ready_preferred_session,
                        decision.consecutive_failures,
                        "preferred_transport_upgrade");
                    ready_preferred_session.reset();
                    write_host_event(
                        "host_cat6_preferred_upgrade_selected",
                        describe_cat6_session(active_session));
                } else {
                    write_host_event(
                        "host_cat6_recovery_bootstrap_started",
                        "attempt=" + std::to_string(decision.consecutive_failures));
                    const HostCat6BootstrapResult recovered_link = bootstrap_host_cat6_link(
                        kHostCat6MobileReadyTimeout,
                        isolated_dhcp_server_,
                        startup_stop_token);
                    if (!recovered_link.diagnostics.empty()) {
                        write_host_event(
                            "host_cat6_recovery_diagnostic",
                            summarize_bootstrap_diagnostics(
                                recovered_link.diagnostics));
                    }
                    write_host_event(
                        "host_direct_link_recovery_bootstrap",
                        describe_direct_link(recovered_link.direct_link));
                    if (recovered_link.firewall_attempted) {
                        write_host_event(
                            "host_firewall_recovery_bootstrap",
                            describe_firewall(recovered_link.firewall));
                    } else {
                        write_host_event(
                            "host_firewall_recovery_bootstrap_skipped",
                            "blocked_by=direct_link");
                    }
                    if (isolated_dhcp_server_ != nullptr &&
                        (recovered_link.dhcp_start_attempted || recovered_link.dhcp_started)) {
                        const HostCat6BootstrapFailureStage recovery_failure_stage =
                            classify_host_cat6_bootstrap_failure(recovered_link);
                        write_host_event(
                            "host_dhcp_recovery_bootstrap",
                            "started=" + std::to_string(recovered_link.dhcp_started) +
                                " running=" +
                                std::to_string(isolated_dhcp_server_->running()) +
                                " failure_stage=" +
                                host_cat6_bootstrap_failure_stage_name(
                                    recovery_failure_stage) +
                                " native_error={" +
                                describe_native_error(static_cast<std::int32_t>(
                                    recovered_link.dhcp_native_error)) + "}" +
                                " detail={" + recovered_link.dhcp_detail + "} " +
                                describe_dhcp(isolated_dhcp_server_->metrics()));
                    } else {
                        write_host_event(
                            "host_dhcp_recovery_bootstrap_skipped",
                            "failure_stage=" + std::string(
                                host_cat6_bootstrap_failure_stage_name(
                                    classify_host_cat6_bootstrap_failure(recovered_link))) +
                                " detail={" + recovered_link.dhcp_detail + "}");
                    }
                    if (startup_stop_token.stop_requested()) break;
                    std::optional<Cat6SessionSnapshot> recovered_session =
                        recovered_link.mobile;
                    HostFirewallProvisioningResult recovery_wireless_firewall{};
                    std::string recovery_wireless_discovery{"not_attempted"};
                    if (!recovered_session.has_value()) {
                        write_host_event(
                            "host_wireless_lan_recovery_started",
                            "attempt=" + std::to_string(
                                decision.consecutive_failures));
                        recovery_wireless_firewall = ensure_runtime_firewall();
                        if (host_firewall_is_ready(
                                recovery_wireless_firewall.status)) {
                            WirelessLanDiscoveryOutcome wireless_discovery =
                                discover_wireless_lan_mobile_session(
                                    kWirelessLanDiscoveryTimeout);
                            recovered_session = std::move(wireless_discovery.session);
                            recovery_wireless_discovery =
                                std::move(wireless_discovery.diagnostic);
                        }
                        write_host_event(
                            recovered_session.has_value()
                                ? "host_wireless_lan_recovery_ready"
                                : "host_wireless_lan_recovery_not_ready",
                            recovered_session.has_value()
                                ? describe_cat6_session(*recovered_session) +
                                    " discovery={" + recovery_wireless_discovery + "}"
                                : describe_firewall(recovery_wireless_firewall) +
                                    " discovery={" + recovery_wireless_discovery + "}");
                    }
                    if (!recovered_session.has_value()) {
                        const HostCat6BootstrapFailureStage recovery_failure_stage =
                            classify_host_cat6_bootstrap_failure(recovered_link);
                        recovery_stage = "transport_link";
                        recovery_detail = "failure_stage=" + std::string(
                            host_cat6_bootstrap_failure_stage_name(recovery_failure_stage)) +
                            " direct_link_status=" +
                            std::string(host_direct_link_status_name(
                                recovered_link.direct_link.status)) +
                            " direct_link_detail=" + recovered_link.direct_link.detail +
                            " firewall_status=" +
                            std::string(host_firewall_status_name(
                                recovered_link.firewall.status)) +
                            " firewall_detail=" + recovered_link.firewall.detail +
                            " dhcp_start_attempted=" +
                            std::to_string(recovered_link.dhcp_start_attempted) +
                            " dhcp_started=" + std::to_string(recovered_link.dhcp_started) +
                            " dhcp_native_error={" +
                            describe_native_error(static_cast<std::int32_t>(
                                recovered_link.dhcp_native_error)) + "}" +
                            " dhcp_detail={" + recovered_link.dhcp_detail + '}' +
                            " wireless_firewall_status=" + std::string{
                                host_firewall_status_name(
                                    recovery_wireless_firewall.status)} +
                            " wireless_firewall_detail={" +
                                recovery_wireless_firewall.detail + '}';
                        write_host_event(
                            "host_stream_recovery_attempt_failed",
                            "attempt=" + std::to_string(decision.consecutive_failures) +
                                " " + recovery_detail);
                        continue;
                    }
                    activate_recovered_session(
                        *recovered_session,
                        decision.consecutive_failures,
                        "recovered_stream");
                }
            }
            if (!refresh_capture_geometry(settings)) {
                recovery_stage = "display_refresh";
                recovery_detail =
                    "failure_stage=display_refresh detail=no_active_display_for_centered_roi";
                write_host_event(
                    "host_stream_recovery_attempt_failed",
                    "attempt=" + std::to_string(decision.consecutive_failures) +
                        " " + recovery_detail);
                continue;
            }
            write_host_capture_geometry_event(settings);
            std::uint64_t next_stream_epoch{};
            try {
                next_stream_epoch = stream_epoch_store->reserve_next();
            } catch (const std::exception& error) {
                recovery_stage = "stream_epoch_reservation";
                recovery_detail =
                    "failure_stage=stream_epoch_reservation detail=" +
                    std::string{error.what()};
                {
                    std::lock_guard lock(mutex_);
                    last_error_ =
                        "Host stream recovery stopped because a unique epoch "
                        "could not be durably reserved: " + recovery_detail;
                }
                write_host_event(
                    "host_stream_recovery_fatal", recovery_detail);
                break;
            }
            if (!application.start(create_runtime_config(
                    settings, metrics_path, next_stream_epoch,
                    [authorization_gate = authorization_gate_]() noexcept {
                        return authorization_gate != nullptr &&
                            authorization_gate->permits_data_plane();
                    }))) {
                recovery_stage = "runtime_initialize";
                recovery_detail =
                    "failure_stage=runtime_initialize " +
                    describe_application_start_failure(application) +
                    " skip_async_shared_encoder=" +
                    std::to_string(settings.skip_async_shared_encoder) +
                    " skip_nvenc_encoder=" +
                    std::to_string(settings.skip_nvenc_encoder) +
                    " force_software_encoder=" +
                    std::to_string(settings.force_software_encoder);
                write_host_event(
                    "host_stream_recovery_attempt_failed",
                    "attempt=" + std::to_string(decision.consecutive_failures) +
                        " " + recovery_detail);
                continue;
            }
            write_host_encoder_selected_event(application);
            video_forward_progress_policy.reset();
            stream_epoch = next_stream_epoch;
            if (successful_recoveries !=
                (std::numeric_limits<std::uint32_t>::max)()) {
                ++successful_recoveries;
            }
            {
                std::lock_guard lock(mutex_);
                last_error_.clear();
                if (last_metrics_.has_value()) {
                    last_metrics_->recovery_count = successful_recoveries;
                }
            }
            write_host_event(
                "host_stream_recovered",
                "stream_epoch=" + std::to_string(stream_epoch) +
                    " recovery_attempt=" +
                    std::to_string(decision.consecutive_failures) +
                    " total_recovery_attempts=" +
                    std::to_string(decision.total_failures) +
                    " successful_recoveries=" +
                    std::to_string(successful_recoveries) + " " +
                    describe_cat6_session(active_session));
            if (recovery_cause ==
                HostRecoveryCause::preferred_transport_upgrade) {
                write_host_event(
                    "host_cat6_preferred_upgrade_completed",
                    "stream_epoch=" + std::to_string(stream_epoch) + " " +
                        describe_cat6_session(active_session));
            }
            next_preferred_cat6_probe_at = std::chrono::steady_clock::now();
            recovered = true;
            break;
        }
        if (!recovered) break;
    }
    stop_preferred_cat6_probe();
    firewall_auditor.stop();
    cat6_monitor.stop();
    application.stop();
    std::lock_guard lock(mutex_);
    running_ = false;
    write_host_event("host_stream_stopped");
}

}  // namespace vfdual
