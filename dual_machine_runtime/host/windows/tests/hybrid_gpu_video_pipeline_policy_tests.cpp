#include "vfdual/hybrid_gpu_pipeline_policy.hpp"
#include "vfdual/hybrid_gpu_video_pipeline.hpp"
#include "vfdual/h264_encoder_config.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>

#ifndef VFDUAL_SOURCE_DIR
#define VFDUAL_SOURCE_DIR "."
#endif

namespace {

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return;
    }
    std::fprintf(stderr, "CHECK failed: %s (%s:%d)\n", expression, file, line);
    std::exit(EXIT_FAILURE);
}

#define VFDUAL_TEST_REQUIRE(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

std::string read_source(const char* relative_path) {
    const std::string path = std::string{VFDUAL_SOURCE_DIR} + "/" + relative_path;
    std::ifstream input{path, std::ios::binary};
    VFDUAL_TEST_REQUIRE(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

}  // namespace

int main() {
    static_assert(std::is_trivially_copyable_v<vfdual::HybridGpuFrameInput>);
    static_assert(std::is_trivially_copyable_v<vfdual::HybridGpuCompletionMetrics>);
    VFDUAL_TEST_REQUIRE(
        vfdual::qpc_ticks_to_microseconds(10'000'005U, 10'000'000U) == 1'000'000U);
    VFDUAL_TEST_REQUIRE(vfdual::qpc_ticks_to_microseconds(42U, 0U) == 0U);
    VFDUAL_TEST_REQUIRE(
        vfdual::encoder_timing_hint_for_display_refresh(144U) == 144U);
    VFDUAL_TEST_REQUIRE(
        vfdual::encoder_timing_hint_for_display_refresh(360U) == 360U);
    VFDUAL_TEST_REQUIRE(
        vfdual::encoder_timing_hint_for_display_refresh(0U) ==
        vfdual::kFallbackEncoderTimingHintFramesPerSecond);
    VFDUAL_TEST_REQUIRE(vfdual::qpc_ticks_to_microseconds(
        (std::numeric_limits<std::uint64_t>::max)(), 1U) ==
        (std::numeric_limits<std::uint64_t>::max)());
    vfdual::PendingSlotPolicy<3> staging;
    const auto first = staging.acquire();
    const auto second = staging.acquire();
    const auto third = staging.acquire();
    VFDUAL_TEST_REQUIRE(first == 0U && second == 1U && third == 2U);
    VFDUAL_TEST_REQUIRE(!staging.acquire().has_value());
    VFDUAL_TEST_REQUIRE(staging.pending_count() == 3U);
    staging.release(1U);
    VFDUAL_TEST_REQUIRE(staging.acquire() == 1U);

    vfdual::LatestOnlySlotPolicy<3> mailbox;
    const auto frame0 = mailbox.acquire_for_write();
    const auto frame1 = mailbox.acquire_for_write();
    VFDUAL_TEST_REQUIRE(frame0 == 0U && frame1 == 1U);
    VFDUAL_TEST_REQUIRE(!mailbox.publish_latest(*frame0).has_value());
    VFDUAL_TEST_REQUIRE(mailbox.mailbox_index() == frame0);
    const auto superseded = mailbox.publish_latest(*frame1);
    VFDUAL_TEST_REQUIRE(superseded == frame0);
    VFDUAL_TEST_REQUIRE(mailbox.state(*frame0) == vfdual::CpuFrameSlotState::available);
    const auto worker = mailbox.take_latest();
    VFDUAL_TEST_REQUIRE(worker == frame1);
    VFDUAL_TEST_REQUIRE(!mailbox.has_mailbox_frame());

    const auto frame2 = mailbox.acquire_for_write();
    VFDUAL_TEST_REQUIRE(frame2.has_value());
    VFDUAL_TEST_REQUIRE(!mailbox.publish_latest(*frame2).has_value());
    mailbox.release_worker(*worker);
    VFDUAL_TEST_REQUIRE(mailbox.state(*worker) == vfdual::CpuFrameSlotState::available);
    VFDUAL_TEST_REQUIRE(mailbox.take_latest() == frame2);
    mailbox.release_worker(*frame2);

    vfdual::FixedLatestRing<int, 3> completions;
    VFDUAL_TEST_REQUIRE(!completions.push(10));
    VFDUAL_TEST_REQUIRE(!completions.push(20));
    VFDUAL_TEST_REQUIRE(!completions.push(30));
    VFDUAL_TEST_REQUIRE(completions.push(40));
    int value{};
    VFDUAL_TEST_REQUIRE(completions.pop(value) && value == 20);
    VFDUAL_TEST_REQUIRE(completions.pop(value) && value == 30);
    VFDUAL_TEST_REQUIRE(completions.pop(value) && value == 40);
    VFDUAL_TEST_REQUIRE(!completions.pop(value));

    vfdual::SharedTextureMailboxPolicy<3> shared_mailbox;
    const auto shared0 = shared_mailbox.acquire_for_copy();
    const auto shared1 = shared_mailbox.acquire_for_copy();
    VFDUAL_TEST_REQUIRE(shared0 == 0U && shared1 == 1U);
    VFDUAL_TEST_REQUIRE(
        !shared_mailbox.publish_latest(*shared0).has_value());
    VFDUAL_TEST_REQUIRE(
        shared_mailbox.publish_latest(*shared1) == shared0);
    VFDUAL_TEST_REQUIRE(
        shared_mailbox.state(*shared0) ==
        vfdual::SharedTextureSlotState::retired);
    VFDUAL_TEST_REQUIRE(shared_mailbox.mailbox_index() == shared1);
    const auto shared_worker = shared_mailbox.take_latest();
    VFDUAL_TEST_REQUIRE(shared_worker == shared1);
    shared_mailbox.release_worker(*shared_worker);
    VFDUAL_TEST_REQUIRE(
        shared_mailbox.state(*shared_worker) ==
        vfdual::SharedTextureSlotState::available);
    const auto retired_worker = shared_mailbox.take_retired();
    VFDUAL_TEST_REQUIRE(retired_worker == shared0);
    shared_mailbox.release_worker(*retired_worker);

    const auto deferred = shared_mailbox.acquire_for_copy();
    VFDUAL_TEST_REQUIRE(deferred.has_value());
    VFDUAL_TEST_REQUIRE(
        !shared_mailbox.publish_latest(*deferred).has_value());
    const auto timed_out = shared_mailbox.take_latest();
    VFDUAL_TEST_REQUIRE(timed_out == deferred);
    shared_mailbox.defer_worker(*timed_out);
    VFDUAL_TEST_REQUIRE(shared_mailbox.mailbox_index() == deferred);

    const auto newer = shared_mailbox.acquire_for_copy();
    VFDUAL_TEST_REQUIRE(newer.has_value());
    VFDUAL_TEST_REQUIRE(
        shared_mailbox.publish_latest(*newer) == deferred);
    const auto newest_worker = shared_mailbox.take_latest();
    VFDUAL_TEST_REQUIRE(newest_worker == newer);
    shared_mailbox.defer_worker(*newest_worker);
    const auto older_worker = shared_mailbox.take_retired();
    VFDUAL_TEST_REQUIRE(older_worker == deferred);
    shared_mailbox.retire_worker(*older_worker);
    VFDUAL_TEST_REQUIRE(shared_mailbox.has_retired_frame());

    VFDUAL_TEST_REQUIRE(
        vfdual::advance_absolute_deadline(100U, 105U, 10U) == 110U);
    VFDUAL_TEST_REQUIRE(
        vfdual::advance_absolute_deadline(100U, 110U, 10U) == 110U);
    VFDUAL_TEST_REQUIRE(
        vfdual::advance_absolute_deadline(100U, 111U, 10U) == 111U);
    VFDUAL_TEST_REQUIRE(
        vfdual::advance_absolute_deadline(100U, 125U, 0U) == 125U);
    std::uint64_t fast_deadline = 100U;
    fast_deadline = vfdual::advance_absolute_deadline(
        fast_deadline, 105U, 10U);
    VFDUAL_TEST_REQUIRE(fast_deadline == 110U);
    fast_deadline = vfdual::advance_absolute_deadline(
        fast_deadline, 115U, 10U);
    VFDUAL_TEST_REQUIRE(fast_deadline == 120U);
    std::uint64_t slow_deadline = 100U;
    slow_deadline = vfdual::advance_absolute_deadline(
        slow_deadline, 111U, 10U);
    VFDUAL_TEST_REQUIRE(slow_deadline == 111U);
    slow_deadline = vfdual::advance_absolute_deadline(
        slow_deadline, 122U, 10U);
    VFDUAL_TEST_REQUIRE(slow_deadline == 122U);
    VFDUAL_TEST_REQUIRE(
        vfdual::relative_waitable_timer_due_100ns(0U) == -1);
    VFDUAL_TEST_REQUIRE(
        vfdual::relative_waitable_timer_due_100ns(1U) == -1);
    VFDUAL_TEST_REQUIRE(
        vfdual::relative_waitable_timer_due_100ns(100U) == -1);
    VFDUAL_TEST_REQUIRE(
        vfdual::relative_waitable_timer_due_100ns(101U) == -2);
    VFDUAL_TEST_REQUIRE(
        vfdual::relative_waitable_timer_due_100ns(6'666'666U) == -66'667);
    VFDUAL_TEST_REQUIRE(
        vfdual::idle_repeat_must_defer_to_source(false, true));
    VFDUAL_TEST_REQUIRE(
        !vfdual::idle_repeat_must_defer_to_source(true, true));
    VFDUAL_TEST_REQUIRE(
        !vfdual::idle_repeat_must_defer_to_source(false, false));

    vfdual::HybridGpuVideoPipelineConfig default_config{};
    VFDUAL_TEST_REQUIRE(
        default_config.transfer_mode ==
        vfdual::HybridGpuTransferMode::cpu_readback);
    default_config.transfer_mode =
        vfdual::HybridGpuTransferMode::same_adapter_shared_texture;
    VFDUAL_TEST_REQUIRE(
        default_config.transfer_mode ==
        vfdual::HybridGpuTransferMode::same_adapter_shared_texture);

    // Repeated reset models stop/start lifecycle without retaining ownership.
    for (int iteration = 0; iteration < 1'000; ++iteration) {
        mailbox.reset();
        std::array<bool, 3> seen{};
        for (std::size_t index = 0; index < 3U; ++index) {
            const auto slot = mailbox.acquire_for_write();
            VFDUAL_TEST_REQUIRE(slot.has_value() && !seen[*slot]);
            seen[*slot] = true;
        }
        mailbox.cancel_write(0U);
        mailbox.cancel_write(1U);
        mailbox.cancel_write(2U);
    }

    // The production policy is intentionally lock-free internally and is
    // serialized by the pipeline's worker mutex. Stress that exact contract.
    vfdual::LatestOnlySlotPolicy<3> concurrent_mailbox;
    std::array<std::uint64_t, 3> sequences{};
    std::mutex policy_mutex;
    std::atomic<bool> producer_done{};
    std::thread producer([&]() {
        for (std::uint64_t sequence = 1U; sequence <= 50'000U; ++sequence) {
            std::lock_guard lock(policy_mutex);
            const auto slot = concurrent_mailbox.acquire_for_write();
            VFDUAL_TEST_REQUIRE(slot.has_value());
            sequences[*slot] = sequence;
            static_cast<void>(concurrent_mailbox.publish_latest(*slot));
        }
        producer_done.store(true, std::memory_order_release);
    });
    std::thread consumer([&]() {
        std::uint64_t last_sequence{};
        while (true) {
            std::optional<std::size_t> slot;
            {
                std::lock_guard lock(policy_mutex);
                slot = concurrent_mailbox.take_latest();
                if (!slot.has_value() &&
                    producer_done.load(std::memory_order_acquire)) {
                    break;
                }
            }
            if (!slot.has_value()) {
                std::this_thread::yield();
                continue;
            }
            VFDUAL_TEST_REQUIRE(sequences[*slot] > last_sequence);
            last_sequence = sequences[*slot];
            {
                std::lock_guard lock(policy_mutex);
                concurrent_mailbox.release_worker(*slot);
            }
        }
    });
    producer.join();
    consumer.join();

    const std::string source =
        read_source("host/windows/src/hybrid_gpu_video_pipeline.cpp");
    const std::size_t stop_index =
        source.find("void stop_and_release_unlocked() noexcept");
    VFDUAL_TEST_REQUIRE(stop_index != std::string::npos);
    const std::size_t join_index = source.find("worker.join()", stop_index);
    const std::size_t catch_index = source.find("catch (...)", join_index);
    const std::size_t reset_index = source.find("worker_initialization_complete = false", join_index);
    VFDUAL_TEST_REQUIRE(join_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(catch_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(reset_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(catch_index < reset_index);
    VFDUAL_TEST_REQUIRE(
        source.find("HybridGpuFatalStage::worker_exception", catch_index) <
        reset_index);
    VFDUAL_TEST_REQUIRE(
        source.find("D3D11_RESOURCE_MISC_SHARED_NTHANDLE") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("OpenSharedResource1") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("create_device_for_adapter_luid") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("kHighResolutionWaitableTimerFlag") !=
        std::string::npos);
    const std::size_t shared_submit_index =
        source.find("HybridGpuSubmitResult submit_shared_unlocked");
    const std::size_t shared_submit_end =
        source.find("void clear_counters", shared_submit_index);
    VFDUAL_TEST_REQUIRE(shared_submit_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(shared_submit_end != std::string::npos);
    const std::string shared_submit = source.substr(
        shared_submit_index, shared_submit_end - shared_submit_index);
    VFDUAL_TEST_REQUIRE(
        shared_submit.find("CopyResource") != std::string::npos);
    VFDUAL_TEST_REQUIRE(shared_submit.find("Map(") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shared_submit.find("UpdateSubresource") == std::string::npos);
    const std::size_t cpu_pump_index =
        source.find("[[nodiscard]] std::size_t pump_unlocked");
    const std::size_t cpu_pump_end =
        source.find("[[nodiscard]] HRESULT create_source_shared_resources", cpu_pump_index);
    VFDUAL_TEST_REQUIRE(cpu_pump_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(cpu_pump_end != std::string::npos);
    const std::string cpu_pump = source.substr(
        cpu_pump_index, cpu_pump_end - cpu_pump_index);
    const std::size_t cpu_polling_loop =
        cpu_pump.find("for (const std::size_t index : polling_order)");
    const std::size_t batch_slot =
        cpu_pump.find("std::optional<std::size_t> batch_cpu_index;");
    const std::size_t batch_publish =
        cpu_pump.find("cpu_policy.publish_latest(*batch_cpu_index)");
    const std::size_t batch_signal =
        cpu_pump.find("signal_worker();", batch_publish);
    VFDUAL_TEST_REQUIRE(cpu_polling_loop != std::string::npos);
    VFDUAL_TEST_REQUIRE(batch_slot != std::string::npos);
    VFDUAL_TEST_REQUIRE(batch_publish != std::string::npos);
    VFDUAL_TEST_REQUIRE(batch_signal != std::string::npos);
    VFDUAL_TEST_REQUIRE(batch_slot < cpu_polling_loop);
    VFDUAL_TEST_REQUIRE(cpu_polling_loop < batch_publish);
    VFDUAL_TEST_REQUIRE(batch_publish < batch_signal);
    VFDUAL_TEST_REQUIRE(
        cpu_pump.find("signal_worker();", cpu_polling_loop) == batch_signal);
    const std::size_t keys_returned_index = source.find(
        "return worker_keys_returned;", stop_index);
    VFDUAL_TEST_REQUIRE(keys_returned_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(keys_returned_index < join_index);
    const std::size_t shutdown_drain_index =
        source.find("void return_pending_shared_keys");
    const std::size_t wait_helper_index =
        source.find("WorkerWaitStatus wait_for_worker_activity");
    const std::size_t cpu_worker_index =
        source.find("bool run_cpu_worker", wait_helper_index);
    const std::size_t shared_worker_index =
        source.find("bool run_shared_worker", shutdown_drain_index);
    VFDUAL_TEST_REQUIRE(shutdown_drain_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(wait_helper_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(cpu_worker_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(shared_worker_index != std::string::npos);
    const std::string shutdown_drain = source.substr(
        shutdown_drain_index, wait_helper_index - shutdown_drain_index);
    VFDUAL_TEST_REQUIRE(
        shutdown_drain.find("kShutdownKeyedMutexWaitMs") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shutdown_drain.find("INFINITE") == std::string::npos);
    const std::size_t worker_main_index =
        source.find("void worker_main", shared_worker_index);
    VFDUAL_TEST_REQUIRE(worker_main_index != std::string::npos);
    const std::string wait_helper_source = source.substr(
        wait_helper_index, cpu_worker_index - wait_helper_index);
    const std::string cpu_worker_source = source.substr(
        cpu_worker_index, shared_worker_index - cpu_worker_index);
    const std::string shared_worker_source = source.substr(
        shared_worker_index, worker_main_index - shared_worker_index);
    VFDUAL_TEST_REQUIRE(
        wait_helper_source.find("SetWaitableTimerEx") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        wait_helper_source.find("WaitForMultipleObjects") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        wait_helper_source.find("relative_waitable_timer_due_100ns") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        wait_helper_source.find("worker_cv.wait_until") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        wait_helper_source.find("sleep_until") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("wait_for_worker_activity") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("take_latest_cpu_frame") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("idle_repeat_must_defer_to_source") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("source_readback_pending.load") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("!updated") != std::string::npos);
    const std::size_t take_latest_index =
        cpu_worker_source.find("take_latest_cpu_frame");
    const std::size_t idle_gate_index =
        cpu_worker_source.find("now < next_idle_repeat_at");
    VFDUAL_TEST_REQUIRE(take_latest_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(idle_gate_index != std::string::npos);
    VFDUAL_TEST_REQUIRE(take_latest_index < idle_gate_index);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("next_tick += period") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("if (updated)") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        cpu_worker_source.find("advance_absolute_deadline(") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("wait_for_cpu_frame") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shared_worker_source.find("wait_for_worker_signal") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shared_worker_source.find("wait_for_worker_activity") ==
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shared_worker_source.find("CopyResource") == std::string::npos);
    VFDUAL_TEST_REQUIRE(
        shared_worker_source.find("worker_slots[*index].texture.Get()") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        source.find("kMaximumSharedFrameRate") == std::string::npos);
    const std::string encoder_config_source =
        read_source("host/windows/include/vfdual/h264_encoder_config.hpp");
    VFDUAL_TEST_REQUIRE(
        encoder_config_source.find(
            "std::uint32_t kEncoderTimingHintFramesPerSecond") ==
            std::string::npos);
    VFDUAL_TEST_REQUIRE(
        encoder_config_source.find(
            "encoder_timing_hint_for_display_refresh") != std::string::npos);
    VFDUAL_TEST_REQUIRE(
        encoder_config_source.find("kFormalPipelineFramesPerSecond") ==
        std::string::npos);

    const std::string agent_source =
        read_source("host/windows/src/desktop_video_agent.cpp");
    VFDUAL_TEST_REQUIRE(
        agent_source.find(
            "!async_shared_same_adapter_ && repeatable_capture_status") ==
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        agent_source.find("capture_stage_owns_idle_repeat(") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        agent_source.find(
            "capture_timeout_ms = producer_owns_idle_repeat") !=
        std::string::npos);
    const std::string frame_bridge_source =
        read_source("host/windows/src/d3d11_frame_bridge.cpp");
    VFDUAL_TEST_REQUIRE(
        frame_bridge_source.find("InputFrameRate = {60, 1}") ==
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        frame_bridge_source.find(
            "InputFrameRate = {presentation_timing_fps, 1}") !=
        std::string::npos);
    VFDUAL_TEST_REQUIRE(
        frame_bridge_source.find(
            "OutputFrameRate = {presentation_timing_fps, 1}") !=
        std::string::npos);
    return 0;
}
