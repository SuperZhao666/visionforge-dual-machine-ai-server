#include "vfdual/desktop_video_agent.hpp"
#include "vfdual/host_display_catalog.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <iostream>
#include <limits>
#include <string_view>
#include <vector>

namespace {
constexpr std::uint64_t kTestConnectionId = 0x1020'3040'5060'7080ULL;

struct TestKey {
    std::array<std::byte, vfdual::kAes256KeyBytes> key{};
    std::array<std::byte, vfdual::kGcmNoncePrefixBytes> prefix{};

    vfdual::PeerHandshakeDataPlaneKeyView view() const noexcept {
        return {key, prefix};
    }
};

TestKey test_key(const std::uint8_t seed) {
    TestKey result;
    for (std::size_t index = 0; index < result.key.size(); ++index) {
        result.key[index] = std::byte{static_cast<std::uint8_t>(seed + index)};
    }
    for (std::size_t index = 0; index < result.prefix.size(); ++index) {
        result.prefix[index] =
            std::byte{static_cast<std::uint8_t>(seed ^ (0xa0U + index))};
    }
    return result;
}

std::shared_ptr<vfdual::HostAuthenticatedDataPlaneSessionV2>
test_authenticated_session() {
    const TestKey video = test_key(0x11U);
    const TestKey presence = test_key(0x22U);
    const TestKey idr = test_key(0x33U);
    const TestKey mouse = test_key(0x44U);
    return vfdual::HostAuthenticatedDataPlaneSessionV2::create_for_test(
        kTestConnectionId, video.view(), presence.view(), idr.view(),
        mouse.view());
}

bool parse_argument(int argc, char** argv, int index, std::uint32_t& value) {
    if (argc <= index) return true;
    const std::string_view text{argv[index]};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && value != 0;
}

std::uint64_t p50(std::vector<std::uint64_t> values) {
    std::sort(values.begin(), values.end());
    return values[values.size() / 2U];
}
}  // namespace

int main(int argc, char** argv) {
    {
        vfdual::DesktopVideoAgent invalid_agent;
        vfdual::DesktopVideoAgentConfig invalid_config{};
        if (invalid_agent.initialize(invalid_config)) return 10;
        const auto& validation = invalid_agent.encoder_diagnostics();
        if (validation.initialization_stage !=
                vfdual::DesktopVideoInitializationStage::validate_config ||
            validation.last_failure_stage !=
                vfdual::DesktopVideoInitializationStage::validate_config ||
            validation.last_failure_status == 0) {
            return 11;
        }
        invalid_agent.reset();
        if (invalid_agent.encoder_diagnostics().initialization_stage !=
            vfdual::DesktopVideoInitializationStage::none) {
            return 12;
        }

        invalid_config.local_host = "127.0.0.1";
        invalid_config.phone_host = "127.0.0.1";
        invalid_config.phone_port = 5600;
        invalid_config.stream_epoch = 1U;
        invalid_config.encoder.width = vfdual::kAiCaptureEdge;
        invalid_config.encoder.height = vfdual::kAiCaptureEdge;
        invalid_config.data_plane_permit = []() noexcept { return true; };
        invalid_config.authenticated_data_plane_session =
            test_authenticated_session();
        if (!invalid_config.authenticated_data_plane_session) return 15;
        invalid_config.adapter_index =
            (std::numeric_limits<std::uint32_t>::max)();
        if (invalid_agent.initialize(invalid_config)) return 13;
        const auto& capture = invalid_agent.encoder_diagnostics();
        if (capture.initialization_stage !=
                vfdual::DesktopVideoInitializationStage::capture_initialize ||
            capture.capture_hresult == 0 ||
            capture.last_failure_status != capture.capture_hresult) {
            return 14;
        }
    }

    std::uint32_t required_frames = 600;
    std::uint32_t encode_width = vfdual::kAiCaptureEdge;
    std::uint32_t encode_height = vfdual::kAiCaptureEdge;
    if (!parse_argument(argc, argv, 1, required_frames) ||
        !parse_argument(argc, argv, 2, encode_width) ||
        !parse_argument(argc, argv, 3, encode_height)) return 2;
    vfdual::DesktopVideoAgent agent;
    vfdual::DesktopVideoAgentConfig config{};
    config.adapter_index = 0;
    config.output_index = 0;
    config.capture_timeout_ms = 1000;
    config.capture_region = vfdual::DesktopCaptureRegion{0, 0, encode_width, encode_height};
    config.encoder = {
        .width = encode_width,
        .height = encode_height,
        .frames_per_second = 60,
        .keyframe_interval_frames = 60,
    };
    if (argc > 4 && std::string_view(argv[4]) == "media_foundation") {
        config.encoder_preference = vfdual::H264EncoderPreference::media_foundation;
    } else if (argc > 4 && std::string_view(argv[4]) == "software") {
        config.encoder_preference = vfdual::H264EncoderPreference::software;
    } else if (argc > 4 && std::string_view(argv[4]) == "nvenc") {
        config.encoder_preference = vfdual::H264EncoderPreference::nvenc;
    }
    if (!parse_argument(argc, argv, 5, config.encoder.frames_per_second)) return 2;
    const auto outputs = vfdual::enumerate_host_display_outputs();
    const auto* output = vfdual::select_preferred_display_output(outputs);
    if (output == nullptr || output->width < encode_width || output->height < encode_height) {
        std::cerr << "SKIP: no attached output can provide the requested capture extent\n";
        return 77;
    }
    config.adapter_index = output->adapter_index;
    config.output_index = output->output_index;
    config.capture_region = vfdual::DesktopCaptureRegion{
        static_cast<std::int32_t>((output->width - encode_width) / 2U),
        static_cast<std::int32_t>((output->height - encode_height) / 2U),
        encode_width,
        encode_height};
    config.local_host = "127.0.0.1";
    config.phone_host = "127.0.0.1";
    config.phone_port = 5600;
    config.stream_epoch = 1U;
    config.data_plane_permit = []() noexcept { return true; };
    config.authenticated_data_plane_session = test_authenticated_session();
    if (!config.authenticated_data_plane_session) return 15;
    if (!agent.initialize(config)) {
        std::cerr << "initialize_failed adapter=" << config.adapter_index
                  << " output=" << config.output_index << '\n';
        return 1;
    }
    const vfdual::DesktopVideoEncoderDiagnostics initialization =
        agent.encoder_diagnostics();
    vfdual::DesktopVideoStepMetrics result{};
    std::uint32_t published_frames = 0;
    std::uint32_t capture_timeouts = 0;
    std::vector<std::uint64_t> capture_timings;
    std::vector<std::uint64_t> bridge_timings;
    std::vector<std::uint64_t> encode_timings;
    std::vector<std::uint64_t> total_timings;
    std::chrono::steady_clock::time_point first_published_at{};
    const auto run_started = std::chrono::steady_clock::now();
    const auto deadline = run_started + std::chrono::seconds(15);
    while (published_frames < required_frames &&
           std::chrono::steady_clock::now() < deadline) {
        const vfdual::DesktopVideoStepMetrics operational = agent.publish_next();
        if (operational.encoder_backend == vfdual::H264EncoderBackend::none) return 4;
        if (operational.status == vfdual::DesktopVideoStepStatus::capture_timeout) {
            ++capture_timeouts;
        } else if (operational.status != vfdual::DesktopVideoStepStatus::frame_published &&
                   operational.status != vfdual::DesktopVideoStepStatus::frame_queued &&
                   operational.status != vfdual::DesktopVideoStepStatus::capture_pointer_only &&
                   operational.status != vfdual::DesktopVideoStepStatus::capture_outside_region &&
                   operational.status != vfdual::DesktopVideoStepStatus::staging_busy) {
            result = operational;
            break;
        }

        if (operational.status == vfdual::DesktopVideoStepStatus::frame_published) {
            result = operational;
            if (published_frames == 0U) {
                first_published_at = std::chrono::steady_clock::now();
            }
            ++published_frames;
        }
        vfdual::DesktopVideoStepMetrics completion{};
        while (agent.try_pop_completed(completion) && published_frames < required_frames) {
            result = completion;
            if (completion.status != vfdual::DesktopVideoStepStatus::frame_published) break;
            if (published_frames == 0U) {
                first_published_at = std::chrono::steady_clock::now();
            }
            ++published_frames;
        }
        if (result.status != vfdual::DesktopVideoStepStatus::frame_published) continue;
        capture_timings.push_back(result.capture_us);
        bridge_timings.push_back(
            result.readback_wait_us + result.readback_copy_us +
            result.bridge_us + result.upload_us);
        encode_timings.push_back(result.encode_us);
        total_timings.push_back(result.capture_to_publish_us != 0U
            ? result.capture_to_publish_us
            : result.capture_us + result.readback_wait_us + result.readback_copy_us +
                result.bridge_us + result.upload_us + result.encode_us + result.publish_us);
    }
    const auto run_completed = std::chrono::steady_clock::now();
    const double elapsed_seconds = std::chrono::duration<double>(
        run_completed - run_started).count();
    const double steady_publish_seconds = first_published_at ==
            std::chrono::steady_clock::time_point{}
        ? 0.0
        : std::chrono::duration<double>(
              run_completed - first_published_at).count();
    std::cerr << "status=" << static_cast<int>(result.status)
              << " frame=" << result.frame_id
              << " published=" << published_frames
              << " size=" << encode_width << 'x' << encode_height
              << " capture_us=" << result.capture_us
              << " bridge_us=" << result.bridge_us
              << " bridge_mode=" << static_cast<int>(result.bridge_mode)
              << " encode_us=" << result.encode_us
              << " publish_us=" << result.publish_us
              << " au_bytes=" << result.access_unit_bytes
              << " datagrams=" << result.datagrams_sent
              << " keyframe=" << result.keyframe
              << " native=" << result.native_status
              << " encoder_backend=" << static_cast<int>(result.encoder_backend)
              << " capture_vendor=" << static_cast<int>(result.capture_vendor)
               << " encoder_vendor=" << static_cast<int>(result.encoder_vendor)
              << " encoder_same_adapter=" << result.encoder_same_adapter
              << " zero_copy=" << result.zero_copy
              << " asynchronous_pipeline=" << result.asynchronous_pipeline
              << " async_shared_same_adapter=" << result.async_shared_same_adapter
              << " encoder_timing_fps=" << result.encoder_timing_fps
              << " selected_candidate="
              << static_cast<int>(initialization.selected_candidate)
              << " attempted_candidate_mask="
              << initialization.attempted_candidate_mask
              << " failed_candidate_mask="
              << initialization.failed_candidate_mask
              << " last_failure_stage="
              << static_cast<int>(initialization.last_failure_stage)
              << " last_failure_status="
              << initialization.last_failure_status
              << " elapsed_seconds=" << elapsed_seconds
              << " published_fps="
              << (elapsed_seconds > 0.0 ? published_frames / elapsed_seconds : 0.0)
              << " steady_published_fps="
              << (steady_publish_seconds > 0.0 && published_frames > 1U
                      ? (published_frames - 1U) / steady_publish_seconds
                      : 0.0)
              << " authoritative_hybrid_published="
              << result.hybrid_published
              << " completion_metrics_dropped="
              << result.hybrid_completion_metrics_dropped
               << " nvenc_stage=" << static_cast<int>(result.nvenc_stage) << '\n';
    if (!total_timings.empty()) {
        std::cerr << "p50_capture_us=" << p50(capture_timings)
                  << " p50_bridge_us=" << p50(bridge_timings)
                  << " p50_encode_us=" << p50(encode_timings)
                  << " p50_total_us=" << p50(total_timings)
                  << " p50_pipeline_fps=" << (1'000'000.0 / p50(total_timings)) << '\n';
    }
    const bool expected_backend = argc > 4 && std::string_view(argv[4]) == "software"
        ? result.encoder_backend == vfdual::H264EncoderBackend::software_cpu
        : argc > 4 && std::string_view(argv[4]) == "media_foundation"
            ? result.encoder_backend == vfdual::H264EncoderBackend::windows_hardware ||
              result.encoder_backend == vfdual::H264EncoderBackend::software_cpu
            : result.encoder_backend != vfdual::H264EncoderBackend::none;
    const bool succeeded = result.status == vfdual::DesktopVideoStepStatus::frame_published
        && result.access_unit_bytes > 0 && published_frames == required_frames && expected_backend;
    agent.reset();
    std::cerr << "agent_reset_complete\n";
    const bool terminal_failure =
        result.status == vfdual::DesktopVideoStepStatus::capture_access_lost ||
        result.status == vfdual::DesktopVideoStepStatus::capture_device_removed ||
        result.status == vfdual::DesktopVideoStepStatus::capture_failed ||
        result.status == vfdual::DesktopVideoStepStatus::bridge_failed ||
        result.status == vfdual::DesktopVideoStepStatus::encode_failed ||
        result.status == vfdual::DesktopVideoStepStatus::publish_failed;
    if (published_frames < required_frames && !terminal_failure) {
        std::cerr << "SKIP: desktop source did not present enough dynamic frames\n";
        return 77;
    }
    return succeeded ? 0 : 1;
}
