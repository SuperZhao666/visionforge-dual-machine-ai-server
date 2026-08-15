#include "vfdual/h264_annex_b_access_units.hpp"
#include "vfdual/udp_video_publisher.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

struct ReplayOptions {
    std::string input_path;
    std::string host;
    std::uint16_t port{5000};
    std::uint16_t source_port{};
    std::uint32_t frames_per_second{10};
    std::uint32_t maximum_frames{};
    std::uint32_t flush_frames{};
    std::uint32_t repeat_count{1};
};

[[nodiscard]] bool parse_unsigned(std::string_view value, std::uint32_t* destination) {
    if (value.empty()) return false;
    std::uint64_t parsed{};
    for (const char character : value) {
        if (character < '0' || character > '9') return false;
        parsed = parsed * 10U + static_cast<std::uint32_t>(character - '0');
        if (parsed > 65535U) return false;
    }
    *destination = static_cast<std::uint32_t>(parsed);
    return true;
}

[[nodiscard]] bool parse_options(int argc, char** argv, ReplayOptions* options) {
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--input" && index + 1 < argc) options->input_path = argv[++index];
        else if (argument == "--host" && index + 1 < argc) options->host = argv[++index];
        else if (argument == "--port" && index + 1 < argc) {
            std::uint32_t value{};
            if (!parse_unsigned(argv[++index], &value) || value == 0U) return false;
            options->port = static_cast<std::uint16_t>(value);
        } else if (argument == "--source-port" && index + 1 < argc) {
            std::uint32_t value{};
            if (!parse_unsigned(argv[++index], &value) || value == 0U) return false;
            options->source_port = static_cast<std::uint16_t>(value);
        } else if (argument == "--fps" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->frames_per_second) || options->frames_per_second == 0U) return false;
        } else if (argument == "--max-frames" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->maximum_frames)) return false;
        } else if (argument == "--flush-frames" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->flush_frames) || options->flush_frames > 8U) return false;
        } else if (argument == "--repeat" && index + 1 < argc) {
            if (!parse_unsigned(argv[++index], &options->repeat_count) ||
                options->repeat_count == 0U || options->repeat_count > 100U) return false;
        } else return false;
    }
    return !options->input_path.empty() && !options->host.empty();
}

[[nodiscard]] std::vector<std::byte> read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.seekg(0, std::ios::end);
    const auto byte_count = input.tellg();
    if (byte_count <= 0) return {};
    std::vector<std::byte> bytes(static_cast<std::size_t>(byte_count));
    input.seekg(0, std::ios::beg);
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return input.good() || input.eof() ? bytes : std::vector<std::byte>{};
}

void print_usage() {
    std::cerr << "usage: VisionForgeDatasetReplay --input dataset.h264 --host PHONE_IP [--port 5000] [--source-port PORT] [--fps 10] [--repeat N] [--max-frames N] [--flush-frames 1]\n";
}

void wait_precisely_until(std::chrono::steady_clock::time_point deadline) {
    // Windows' default scheduler quantum can release sleep_until in bursts at
    // 120+ FPS. Keep the final sub-millisecond window active so this offline
    // harness measures the phone with paced frames instead of batched UDP.
    constexpr auto active_window = std::chrono::microseconds(750);
    const auto now = std::chrono::steady_clock::now();
    if (deadline > now + active_window) {
        std::this_thread::sleep_until(deadline - active_window);
    }
    while (std::chrono::steady_clock::now() < deadline) {
    }
}

}  // namespace

int main(int argc, char** argv) {
    ReplayOptions options;
    if (!parse_options(argc, argv, &options)) {
        print_usage();
        return 2;
    }
    const auto bytes = read_file(options.input_path);
    if (bytes.empty()) {
        std::cerr << "event=dataset_replay_failed reason=input_unreadable\n";
        return 3;
    }
    const auto access_units = vfdual::split_h264_annex_b_access_units(bytes);
    if (access_units.empty()) {
        std::cerr << "event=dataset_replay_failed reason=no_h264_access_units\n";
        return 4;
    }
    const std::uint64_t repeated_frame_count =
        static_cast<std::uint64_t>(access_units.size()) * options.repeat_count;
    if (repeated_frame_count > UINT32_MAX) {
        std::cerr << "event=dataset_replay_failed reason=frame_count_overflow\n";
        return 4;
    }
    const std::uint32_t available_frame_count = static_cast<std::uint32_t>(repeated_frame_count);
    const std::uint32_t frame_count = options.maximum_frames == 0U
        ? available_frame_count
        : std::min(options.maximum_frames, available_frame_count);
    vfdual::UdpVideoPublisher publisher;
    if (!publisher.connect_to(
            options.host, options.port, options.source_port, {},
            []() noexcept { return true; })) {
        std::cerr << "event=dataset_replay_failed reason=udp_connect socket_error=" << publisher.last_socket_error() << '\n';
        return 5;
    }
    std::cout << "event=dataset_replay_started frames=" << frame_count << " fps=" << options.frames_per_second
              << " destination=" << options.host << ':' << options.port
              << " source_port=" << options.source_port << '\n';
    const auto interval = std::chrono::microseconds(1'000'000U / options.frames_per_second);
    const auto replay_started = std::chrono::steady_clock::now();
    auto deadline = replay_started;
    for (std::uint32_t frame_id = 1; frame_id <= frame_count; ++frame_id) {
        const auto monotonic_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        const auto access_unit_index = static_cast<std::size_t>(frame_id - 1U) % access_units.size();
        const auto result = publisher.publish(frame_id, access_units[access_unit_index], monotonic_us);
        if (!result.success) {
            std::cerr << "event=dataset_replay_failed frame_id=" << frame_id
                      << " socket_error=" << publisher.last_socket_error() << '\n';
            return 6;
        }
        if (frame_id == 1U || frame_id == frame_count || frame_id % 50U == 0U) {
            std::cout << "event=dataset_replay_progress frame_id=" << frame_id
                      << " access_unit_bytes=" << access_units[access_unit_index].size()
                      << " datagrams=" << result.fragments_sent << '\n';
        }
        deadline += interval;
        wait_precisely_until(deadline);
    }
    const auto replay_data_completed = std::chrono::steady_clock::now();
    // MediaCodec may retain the final B/P picture until a following access
    // unit arrives. This bounded duplicate is offline-test-only; its frame
    // ID is outside the labelled range and cannot enter the capped trace.
    for (std::uint32_t flush_index{}; flush_index < options.flush_frames; ++flush_index) {
        const std::uint32_t frame_id = frame_count + flush_index + 1U;
        const auto monotonic_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        const auto flush_access_unit_index = static_cast<std::size_t>(frame_count - 1U) % access_units.size();
        const auto result = publisher.publish(frame_id, access_units[flush_access_unit_index], monotonic_us);
        if (!result.success) {
            std::cerr << "event=dataset_replay_failed flush_frame_id=" << frame_id
                      << " socket_error=" << publisher.last_socket_error() << '\n';
            return 6;
        }
        std::cout << "event=dataset_replay_flush frame_id=" << frame_id
                  << " access_unit_bytes=" << access_units[flush_access_unit_index].size()
                  << " datagrams=" << result.fragments_sent << '\n';
        deadline += interval;
        wait_precisely_until(deadline);
    }
    const auto replay_wall_us = std::chrono::duration_cast<std::chrono::microseconds>(
        replay_data_completed - replay_started).count();
    const auto actual_fps = replay_wall_us > 0
        ? static_cast<double>(frame_count) * 1'000'000.0 / static_cast<double>(replay_wall_us)
        : 0.0;
    std::cout << "event=dataset_replay_completed frames=" << frame_count
              << " replay_wall_us=" << replay_wall_us
              << " actual_fps=" << actual_fps << '\n';
    return 0;
}
