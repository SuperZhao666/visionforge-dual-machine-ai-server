#include <jni.h>

#include <android/log.h>
#include <android/multinetwork.h>
#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

#include "NativeH264Decoder.hpp"
#include "ReceiverIdleBackoff.hpp"
#include "ReceiverRepeatResyncPolicy.hpp"
#include "ReceiverRecoveryPolicy.hpp"
#include "ReceiverReferenceSyncPolicy.hpp"
#include "ReceiverSourceSession.hpp"
#include "vfdual/access_unit_reassembler.hpp"
#include "vfdual/h264_access_unit.hpp"
#include "vfdual/protocol.hpp"
#include "vfdual/receiver_epoch_session.hpp"

namespace {
constexpr char kTag[] = "VisionForgeMobile";
constexpr std::uint16_t kMinimumPort = 1024;
constexpr std::uint16_t kIdrRequestPort = 5001;
constexpr std::uint16_t kAuthenticatedLoopbackVideoPort = 15000;
constexpr std::uint16_t kCat6ReadyPort = 5003;
constexpr std::uint16_t kCat6ProbePort = 5004;
constexpr std::size_t kCat6ProbeBytes = 1200;
constexpr std::size_t kMaximumCat6ProbeTokenLength = 64;
constexpr std::chrono::milliseconds kCat6ReadyInterval{250};
constexpr std::string_view kCat6ReadyPrefix{"VF_CAT6_READY_V1|"};
constexpr std::string_view kCat6ProbePrefix{"VF_CAT6_PROBE_V1|"};
constexpr std::string_view kCat6ProbeAckPrefix{"VF_CAT6_PROBE_ACK_V1|"};
constexpr std::size_t kMaximumInflightAccessUnits = 4;
constexpr std::uint64_t kAccessUnitReassemblyTtlUs = 50'000;
constexpr std::uint64_t kInitialReceiveTimeoutUs = 100'000;
constexpr std::array<std::byte, 4> kIdrRequest{std::byte{'I'}, std::byte{'D'}, std::byte{'R'}, std::byte{'1'}};

[[nodiscard]] std::uint64_t monotonic_microseconds() noexcept {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] bool set_receive_timeout(int socket, std::uint64_t timeout_us) noexcept {
  timeval receive_timeout{};
  receive_timeout.tv_sec = static_cast<decltype(receive_timeout.tv_sec)>(
      timeout_us / 1'000'000U);
  receive_timeout.tv_usec = static_cast<decltype(receive_timeout.tv_usec)>(
      timeout_us % 1'000'000U);
  return ::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                      sizeof(receive_timeout)) == 0;
}

[[nodiscard]] int normalized_network_bind_error(int bind_result) noexcept {
  if (bind_result > 0) return bind_result;
  if (bind_result < -1) return -bind_result;
  return errno == 0 ? EIO : errno;
}

[[nodiscard]] bool can_fallback_to_local_ipv4_bind(int error) noexcept {
  return error == EPERM || error == EACCES;
}

struct ReceiverMetrics {
  std::atomic_uint64_t accepted_datagrams{};
  std::atomic_uint64_t accepted_bytes{};
  std::atomic_uint64_t rejected_datagrams{};
  std::atomic_uint64_t reassembled_access_units{};
  std::atomic_uint64_t decoder_accepted_access_units{};
  std::atomic_uint64_t completed_access_units{};
  std::atomic_uint64_t fresh_content_access_units{};
  std::atomic_uint64_t non_actionable_completed_access_units{};
  std::atomic_uint64_t repeated_content_access_units{};
  std::atomic_uint64_t resync_rejected_repeats{};
  std::atomic_uint64_t resync_actionable_acceptances{};
  std::atomic_uint64_t dropped_access_units{};
  std::atomic_uint64_t idr_requests{};
  std::atomic_uint64_t receiver_timeouts{};
  std::atomic_uint64_t receive_timeout_us{};
  std::atomic_uint64_t reassembly_expirations{};
  std::atomic_uint64_t reassembly_incomplete_losses{};
  std::atomic_uint64_t reassembly_dependent_flushes{};
  std::atomic_uint64_t reference_resync_drops{};
  std::atomic_uint64_t reference_resync_dependent_flushes{};
  std::atomic_uint64_t sequence_gap_resyncs{};
  std::atomic_uint64_t monotonic_pts_adjustments{};
  std::atomic_uint64_t source_changes{};
  std::atomic_uint64_t source_restart_successes{};
  std::atomic_uint64_t source_restart_failures{};
  std::atomic_uint64_t last_source_restart_us{};
  std::atomic_uint64_t foreign_source_datagrams{};
  std::atomic_uint64_t recovery_idr_requests{};
  std::atomic_uint64_t fatal_socket_errors{};
  std::atomic_int last_socket_errno{};
  std::atomic_uint64_t last_stream_epoch{};
  std::atomic_int64_t last_logical_frame_sequence{-1};
  std::atomic_uint64_t retired_epoch_datagrams{};
  std::atomic_uint64_t candidate_epoch_rejections{};
  std::atomic_uint64_t last_reassembled_access_unit_us{};
  std::atomic_uint64_t last_completed_access_unit_us{};
  std::atomic_uint64_t last_fresh_content_access_unit_us{};

  void reset() noexcept {
    accepted_datagrams = 0;
    accepted_bytes = 0;
    rejected_datagrams = 0;
    reassembled_access_units = 0;
    decoder_accepted_access_units = 0;
    completed_access_units = 0;
    fresh_content_access_units = 0;
    non_actionable_completed_access_units = 0;
    repeated_content_access_units = 0;
    resync_rejected_repeats = 0;
    resync_actionable_acceptances = 0;
    dropped_access_units = 0;
    idr_requests = 0;
    receiver_timeouts = 0;
    receive_timeout_us = kInitialReceiveTimeoutUs;
    reassembly_expirations = 0;
    reassembly_incomplete_losses = 0;
    reassembly_dependent_flushes = 0;
    reference_resync_drops = 0;
    reference_resync_dependent_flushes = 0;
    sequence_gap_resyncs = 0;
    monotonic_pts_adjustments = 0;
    source_changes = 0;
    source_restart_successes = 0;
    source_restart_failures = 0;
    last_source_restart_us = 0;
    foreign_source_datagrams = 0;
    recovery_idr_requests = 0;
    fatal_socket_errors = 0;
    last_socket_errno = 0;
    last_stream_epoch = 0;
    last_logical_frame_sequence = -1;
    retired_epoch_datagrams = 0;
    candidate_epoch_rejections = 0;
    last_reassembled_access_unit_us = 0;
    last_completed_access_unit_us = 0;
    last_fresh_content_access_unit_us = 0;
  }
};

enum class ReceiverStartupStage : int {
  not_started,
  already_running,
  invalid_arguments,
  invalid_local_address,
  invalid_source_address,
  socket_create_failed,
  network_bind_failed,
  receive_timeout_failed,
  local_bind_failed,
  worker_thread_failed,
  running,
  stopped,
};

[[nodiscard]] const char* receiver_startup_stage_name(
    ReceiverStartupStage stage) noexcept {
  switch (stage) {
    case ReceiverStartupStage::not_started: return "not_started";
    case ReceiverStartupStage::already_running: return "already_running";
    case ReceiverStartupStage::invalid_arguments: return "invalid_arguments";
    case ReceiverStartupStage::invalid_local_address: return "invalid_local_address";
    case ReceiverStartupStage::invalid_source_address: return "invalid_source_address";
    case ReceiverStartupStage::socket_create_failed: return "socket_create_failed";
    case ReceiverStartupStage::network_bind_failed: return "network_bind_failed";
    case ReceiverStartupStage::receive_timeout_failed: return "receive_timeout_failed";
    case ReceiverStartupStage::local_bind_failed: return "local_bind_failed";
    case ReceiverStartupStage::worker_thread_failed: return "worker_thread_failed";
    case ReceiverStartupStage::running: return "running";
    case ReceiverStartupStage::stopped: return "stopped";
  }
  return "unknown";
}

class NativeVideoReceiver final {
public:
  bool start(std::string_view local_ipv4, std::string_view expected_source_ipv4,
             std::uint16_t port, net_handle_t network_handle) {
    std::scoped_lock lock(mutex_);
    startup_errno_ = 0;
    if (running_) {
      startup_stage_ = ReceiverStartupStage::already_running;
      return false;
    }
    network_bound_ = false;
    network_handle_bound_ = false;
    local_ipv4_bind_fallback_ = false;
    network_handle_bind_errno_ = 0;
    if (port != kAuthenticatedLoopbackVideoPort ||
        local_ipv4 != "127.0.0.1" || expected_source_ipv4 != "127.0.0.1" ||
        network_handle == NETWORK_UNSPECIFIED) {
      startup_stage_ = ReceiverStartupStage::invalid_arguments;
      startup_errno_ = EINVAL;
      return false;
    }
    if (worker_.joinable()) worker_.join();
    if (socket_ >= 0) {
      ::close(socket_);
      socket_ = -1;
    }
    in_addr local_address{};
    in_addr expected_source_address{};
    const std::string local_ipv4_string(local_ipv4);
    const std::string expected_source_ipv4_string(expected_source_ipv4);
    if (::inet_pton(AF_INET, local_ipv4_string.c_str(), &local_address) != 1) {
      startup_stage_ = ReceiverStartupStage::invalid_local_address;
      startup_errno_ = EINVAL;
      return false;
    }
    if (::inet_pton(
            AF_INET, expected_source_ipv4_string.c_str(),
            &expected_source_address) != 1 ||
        expected_source_address.s_addr == 0U) {
      startup_stage_ = ReceiverStartupStage::invalid_source_address;
      startup_errno_ = EINVAL;
      return false;
    }
    const int socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket < 0) {
      startup_stage_ = ReceiverStartupStage::socket_create_failed;
      startup_errno_ = errno;
      return false;
    }
    const bool authenticated_loopback_relay =
        local_address.s_addr == htonl(INADDR_LOOPBACK) &&
        expected_source_address.s_addr == htonl(INADDR_LOOPBACK);
    const int network_bind_result = authenticated_loopback_relay
        ? 0 : ::android_setsocknetwork(network_handle, socket);
    if (network_bind_result != 0) {
      const int network_bind_error =
          normalized_network_bind_error(network_bind_result);
      if (!can_fallback_to_local_ipv4_bind(network_bind_error)) {
        startup_stage_ = ReceiverStartupStage::network_bind_failed;
        startup_errno_ = network_bind_error;
        ::close(socket);
        return false;
      }
      // Bug #DM-NET-16: selected Android networks can reject the NDK socket
      // mark with EPERM on vendor Android 16 builds. The concrete local IPv4
      // below still pins this socket to that selected interface. Only the two
      // permission-denied results may use this fail-closed route fallback.
      local_ipv4_bind_fallback_ = true;
      network_handle_bind_errno_ = network_bind_error;
    } else if (!authenticated_loopback_relay) {
      network_handle_bound_ = true;
    }
    if (!set_receive_timeout(socket, kInitialReceiveTimeoutUs)) {
      startup_stage_ = ReceiverStartupStage::receive_timeout_failed;
      startup_errno_ = errno;
      network_bound_ = false;
      ::close(socket);
      return false;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr = local_address;
    address.sin_port = htons(port);
    if (::bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      startup_stage_ = ReceiverStartupStage::local_bind_failed;
      startup_errno_ = errno;
      network_bound_ = false;
      ::close(socket);
      return false;
    }
    network_bound_ = true;
    socket_ = socket;
    local_ipv4_ = local_ipv4_string;
    expected_source_ipv4_ = expected_source_ipv4_string;
    idr_destination_ = {};
    idr_destination_ready_ = false;
    source_session_.reset(expected_source_address.s_addr);
    recovery_policy_.reset();
    repeat_resync_policy_.reset();
    reference_sync_policy_.reset();
    last_presentation_time_us_ = 0U;
    next_control_sequence_ = 1U;
    metrics_.reset();
    running_ = true;
    startup_stage_ = ReceiverStartupStage::running;
    try {
      worker_ = std::thread(&NativeVideoReceiver::run, this, socket);
    } catch (const std::system_error& failure) {
      startup_stage_ = ReceiverStartupStage::worker_thread_failed;
      startup_errno_ = failure.code().value() == 0 ? EAGAIN : failure.code().value();
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    } catch (const std::exception&) {
      startup_stage_ = ReceiverStartupStage::worker_thread_failed;
      startup_errno_ = EAGAIN;
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    } catch (...) {
      startup_stage_ = ReceiverStartupStage::worker_thread_failed;
      startup_errno_ = EAGAIN;
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    }
    return true;
  }

  void stop() {
    std::scoped_lock lock(mutex_);
    running_ = false;
    if (socket_ >= 0) {
      ::shutdown(socket_, SHUT_RDWR);
      ::close(socket_);
      socket_ = -1;
    }
    if (worker_.joinable()) worker_.join();
    network_bound_ = false;
    startup_stage_ = ReceiverStartupStage::stopped;
  }

  std::string report() const {
    std::scoped_lock lock(mutex_);
    const std::uint64_t last_reassembled_us = metrics_.last_reassembled_access_unit_us.load();
    const std::uint64_t last_completed_us = metrics_.last_completed_access_unit_us.load();
    const std::uint64_t last_fresh_content_us =
        metrics_.last_fresh_content_access_unit_us.load();
    const std::uint64_t reassembled_age_ms = last_reassembled_us == 0
        ? std::numeric_limits<std::uint64_t>::max()
        : (monotonic_microseconds() - last_reassembled_us) / 1'000U;
    const std::uint64_t age_ms = last_completed_us == 0
        ? std::numeric_limits<std::uint64_t>::max()
        : (monotonic_microseconds() - last_completed_us) / 1'000U;
    const std::uint64_t fresh_content_age_ms = last_fresh_content_us == 0
        ? std::numeric_limits<std::uint64_t>::max()
        : (monotonic_microseconds() - last_fresh_content_us) / 1'000U;
    std::ostringstream result;
    result << "UDP receiver running=" << running_
           << " bind_ipv4=" << local_ipv4_
           << " expected_source_ipv4=" << expected_source_ipv4_
           << " ethernet_network_bound=" << network_bound_
           << " network_handle_bound=" << network_handle_bound_
           << " local_ipv4_bind_fallback=" << local_ipv4_bind_fallback_
           << " network_handle_bind_errno=" << network_handle_bind_errno_
           << " startup_stage="
           << receiver_startup_stage_name(startup_stage_.load())
           << " startup_errno=" << startup_errno_
           << " accepted_datagrams=" << metrics_.accepted_datagrams
           << " accepted_bytes=" << metrics_.accepted_bytes
           << " rejected_datagrams=" << metrics_.rejected_datagrams
           << " reassembled_access_units=" << metrics_.reassembled_access_units
           << " decoder_accepted_access_units=" << metrics_.decoder_accepted_access_units
           << " completed_access_units=" << metrics_.completed_access_units
           << " fresh_content_access_units="
           << metrics_.fresh_content_access_units
           << " non_actionable_completed_access_units="
           << metrics_.non_actionable_completed_access_units
           << " repeated_content_access_units="
           << metrics_.repeated_content_access_units
           << " resync_rejected_repeats="
           << metrics_.resync_rejected_repeats
           << " resync_actionable_acceptances="
           << metrics_.resync_actionable_acceptances
           << " dropped_access_units=" << metrics_.dropped_access_units
           << " idr_requests=" << metrics_.idr_requests
           << " receiver_timeouts=" << metrics_.receiver_timeouts
           << " receive_timeout_us=" << metrics_.receive_timeout_us
           << " reassembly_expirations=" << metrics_.reassembly_expirations
           << " reassembly_incomplete_losses="
           << metrics_.reassembly_incomplete_losses
           << " reassembly_dependent_flushes="
           << metrics_.reassembly_dependent_flushes
           << " reference_resync_drops=" << metrics_.reference_resync_drops
           << " reference_resync_dependent_flushes="
           << metrics_.reference_resync_dependent_flushes
           << " sequence_gap_resyncs=" << metrics_.sequence_gap_resyncs
           << " monotonic_pts_adjustments="
           << metrics_.monotonic_pts_adjustments
           << " source_changes=" << metrics_.source_changes
           << " source_restart_successes=" << metrics_.source_restart_successes
           << " source_restart_failures=" << metrics_.source_restart_failures
           << " last_source_restart_us=" << metrics_.last_source_restart_us
           << " foreign_source_datagrams=" << metrics_.foreign_source_datagrams
           << " recovery_idr_requests=" << metrics_.recovery_idr_requests
           << " fatal_socket_errors=" << metrics_.fatal_socket_errors
           << " last_socket_errno=" << metrics_.last_socket_errno
           << " last_stream_epoch=" << metrics_.last_stream_epoch
           << " retired_epoch_datagrams=" << metrics_.retired_epoch_datagrams
           << " candidate_epoch_rejections=" << metrics_.candidate_epoch_rejections
           << " last_logical_frame_sequence="
           << metrics_.last_logical_frame_sequence
           << " last_reassembled_access_unit_age_ms=";
    if (reassembled_age_ms == std::numeric_limits<std::uint64_t>::max()) result << -1;
    else result << reassembled_age_ms;
    result << " last_completed_access_unit_age_ms=";
    if (age_ms == std::numeric_limits<std::uint64_t>::max()) result << -1;
    else result << age_ms;
    result << " last_fresh_content_access_unit_age_ms=";
    if (fresh_content_age_ms == std::numeric_limits<std::uint64_t>::max()) {
      result << -1;
    } else {
      result << fresh_content_age_ms;
    }
    return result.str();
  }

  ~NativeVideoReceiver() { stop(); }

  [[nodiscard]] bool is_running() const noexcept { return running_; }

private:
  struct CompletedSubmission final {
    bool accepted{};
    bool content_updated{};
    bool fatal{};
  };

  void require_reference_sync() noexcept {
    reference_sync_policy_.require_idr();
    repeat_resync_policy_.require_resync();
  }

  [[nodiscard]] std::uint64_t next_presentation_time_us(
      std::uint64_t now_us) noexcept {
    if (now_us <= last_presentation_time_us_) {
      ++metrics_.monotonic_pts_adjustments;
      now_us = last_presentation_time_us_ + 1U;
    }
    last_presentation_time_us_ = now_us;
    return now_us;
  }

  [[nodiscard]] CompletedSubmission submit_completed_access_unit(
      const vfdual::CompletedAccessUnit& completed, std::uint64_t now_us) {
    ++metrics_.reassembled_access_units;
    metrics_.last_reassembled_access_unit_us.store(now_us);
    const bool repeated_content = completed.repeated_content;
    const std::uint32_t logical_frame_id = completed.identity.frame_sequence;
    metrics_.last_stream_epoch = completed.identity.stream_epoch;
    metrics_.last_logical_frame_sequence =
        static_cast<std::int64_t>(logical_frame_id);
    if (repeated_content) ++metrics_.repeated_content_access_units;

    const bool sync_frame =
        vfdual::h264_access_unit_contains_idr(completed.bytes);
    const auto reference_decision =
        reference_sync_policy_.evaluate(logical_frame_id, sync_frame);
    if (reference_decision !=
        vfdual_android::ReceiverReferenceDecision::admit) {
      if (reference_decision ==
          vfdual_android::ReceiverReferenceDecision::reject_sequence_gap) {
        ++metrics_.sequence_gap_resyncs;
      } else {
        ++metrics_.reference_resync_drops;
      }
      ++metrics_.dropped_access_units;
      require_reference_sync();
      return {};
    }

    // An IDR is a valid new visual baseline even when the desktop pixels were
    // unchanged. It must be allowed to unlock transport recovery.
    const bool repeated_for_admission = repeated_content && !sync_frame;
    const auto admission =
        repeat_resync_policy_.admit(repeated_for_admission);
    if (!admission.submit) {
      ++metrics_.resync_rejected_repeats;
      ++metrics_.dropped_access_units;
      return {};
    }

    const bool accepted = vfdual_android::decoder().submit(
        completed.bytes, next_presentation_time_us(now_us), logical_frame_id,
        next_control_sequence_++, admission.content_updated);
    repeat_resync_policy_.record_submit_result(
        repeated_for_admission, accepted);
    reference_sync_policy_.record_submit(logical_frame_id, accepted);
    if (!accepted) {
      ++metrics_.dropped_access_units;
      require_reference_sync();
      const bool restart_timed_out =
          vfdual_android::decoder().has_stream_restart_timed_out();
      if (restart_timed_out) record_source_restart_timeout();
      return {
          .accepted = false,
          .content_updated = false,
          .fatal = vfdual_android::decoder().has_fatal_decoder_failure() ||
              restart_timed_out,
      };
    }

    ++metrics_.decoder_accepted_access_units;
    ++metrics_.completed_access_units;
    if (admission.content_updated) {
      ++metrics_.fresh_content_access_units;
      metrics_.last_fresh_content_access_unit_us.store(
          monotonic_microseconds());
    } else {
      ++metrics_.non_actionable_completed_access_units;
    }
    if (admission.resync_unlock) ++metrics_.resync_actionable_acceptances;
    metrics_.last_completed_access_unit_us.store(monotonic_microseconds());
    return {
        .accepted = true,
        .content_updated = admission.content_updated,
        .fatal = false,
    };
  }

  [[nodiscard]] bool request_idr(
      int socket, std::uint64_t now_us, bool recovery_request,
      bool idle_request, bool invalidate_active_reference = true) noexcept {
    // Recovery for the active epoch closes its predictive-reference chain.
    // Candidate-epoch preflight may ask the Host for an IDR without destroying
    // a still-healthy active stream.
    if (invalidate_active_reference) require_reference_sync();
    if (socket < 0 || !idr_destination_ready_) return false;
    const auto sent = ::sendto(socket, kIdrRequest.data(), kIdrRequest.size(), MSG_NOSIGNAL,
        reinterpret_cast<const sockaddr*>(&idr_destination_), sizeof(idr_destination_));
    if (sent == static_cast<ssize_t>(kIdrRequest.size())) {
      ++metrics_.idr_requests;
      if (recovery_request) ++metrics_.recovery_idr_requests;
      if (idle_request) recovery_policy_.mark_idle_idr_requested(now_us);
      else recovery_policy_.mark_idr_requested(now_us);
      return true;
    }
    metrics_.last_socket_errno = errno;
    return false;
  }

  void record_source_restart_timeout() noexcept {
    ++metrics_.source_restart_failures;
    metrics_.last_source_restart_us =
        vfdual_android::NativeH264Decoder::kStreamRestartTimeoutUs;
  }

  void run(int socket) {
    vfdual::AccessUnitReassembler active_reassembler(
        kMaximumInflightAccessUnits);
    vfdual::AccessUnitReassembler candidate_reassembler(
        kMaximumInflightAccessUnits);
    vfdual::ReceiverEpochSession epoch_session(8U);
    std::optional<vfdual::CompletedAccessUnit> pending_candidate_idr;
    std::uint64_t candidate_reassembler_epoch{};
    std::array<std::byte, vfdual::kMaxDatagramBytes> datagram{};
    std::uint32_t consecutive_socket_errors{};
    bool source_restart_pending{};
    bool decoder_restart_ready{};
    bool receive_timeout_backoff_available{true};
    std::uint64_t last_accepted_datagram_us = monotonic_microseconds();
    std::uint64_t receive_timeout_us = kInitialReceiveTimeoutUs;

    const auto rebuild_active_reassembler = [
        &](std::optional<std::uint32_t> last_delivered_sequence = std::nullopt) {
      active_reassembler =
          vfdual::AccessUnitReassembler(kMaximumInflightAccessUnits);
      if (const auto active = epoch_session.active_epoch(); active.has_value()) {
        (void)active_reassembler.activate_epoch(
            *active, last_delivered_sequence);
      }
    };
    const auto rebuild_candidate_reassembler = [&](std::uint64_t epoch) {
      candidate_reassembler =
          vfdual::AccessUnitReassembler(kMaximumInflightAccessUnits);
      candidate_reassembler_epoch = epoch;
      (void)candidate_reassembler.activate_epoch(epoch);
    };
    const auto commit_restarted_candidate = [&](std::uint64_t now_us) -> bool {
      if (!decoder_restart_ready || !pending_candidate_idr.has_value()) {
        return true;
      }
      const std::uint64_t epoch =
          pending_candidate_idr->identity.stream_epoch;
      if (!epoch_session.commit_candidate(epoch, true)) {
        ++metrics_.candidate_epoch_rejections;
        pending_candidate_idr.reset();
        return true;
      }
      const std::uint32_t committed_idr_sequence =
          pending_candidate_idr->identity.frame_sequence;
      rebuild_active_reassembler(committed_idr_sequence);
      recovery_policy_.reset();
      require_reference_sync();
      const CompletedSubmission submission =
          submit_completed_access_unit(*pending_candidate_idr, now_us);
      pending_candidate_idr.reset();
      decoder_restart_ready = false;
      source_restart_pending = false;
      if (!submission.accepted) {
        ++metrics_.source_restart_failures;
        return false;
      }
      ++metrics_.source_restart_successes;
      return true;
    };

    while (running_) {
      sockaddr_in sender{};
      socklen_t sender_size = sizeof(sender);
      const ssize_t received = ::recvfrom(
          socket, datagram.data(), datagram.size(), 0,
          reinterpret_cast<sockaddr*>(&sender), &sender_size);
      const auto now_us = monotonic_microseconds();

      if (source_restart_pending) {
        const auto completion =
            vfdual_android::decoder().take_stream_restart_completion();
        if (completion.has_value()) {
          metrics_.last_source_restart_us = completion->elapsed_us;
          if (!completion->succeeded) {
            ++metrics_.source_restart_failures;
            __android_log_print(
                ANDROID_LOG_ERROR, kTag,
                "video epoch decoder restart failed generation=%llu elapsed_us=%llu",
                static_cast<unsigned long long>(completion->generation),
                static_cast<unsigned long long>(completion->elapsed_us));
            running_ = false;
            break;
          }
          // A newer candidate may still be reassembling. Keep the completed
          // decoder restart edge and commit only the latest complete real IDR.
          decoder_restart_ready = true;
          if (!commit_restarted_candidate(now_us)) {
            running_ = false;
            break;
          }
        }
      }

      if (received <= 0) {
        if (!running_) break;
        if (vfdual_android::decoder().has_stream_restart_timed_out()) {
          record_source_restart_timeout();
          __android_log_print(
              ANDROID_LOG_ERROR, kTag,
              "video receiver stopping after bounded stream restart timeout while idle");
          running_ = false;
          break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          consecutive_socket_errors = 0;
          ++metrics_.receiver_timeouts;
          const std::uint64_t idle_us = now_us >= last_accepted_datagram_us
              ? now_us - last_accepted_datagram_us : 0U;
          const std::uint64_t next_timeout_us =
              vfdual_android::ReceiverIdleBackoff::receive_timeout_us(idle_us);
          if (receive_timeout_backoff_available &&
              next_timeout_us != receive_timeout_us) {
            if (set_receive_timeout(socket, next_timeout_us)) {
              receive_timeout_us = next_timeout_us;
              metrics_.receive_timeout_us = next_timeout_us;
            } else {
              receive_timeout_backoff_available = false;
              metrics_.last_socket_errno = errno;
              __android_log_print(
                  ANDROID_LOG_ERROR, kTag,
                  "video receiver idle timeout backoff disabled errno=%d", errno);
            }
          }
          if (!source_restart_pending &&
              recovery_policy_.observe_idle(now_us, idr_destination_ready_)) {
            const auto pending_flushes = static_cast<std::uint64_t>(
                active_reassembler.inflight_frame_count());
            metrics_.reference_resync_dependent_flushes += pending_flushes;
            metrics_.dropped_access_units += pending_flushes;
            rebuild_active_reassembler();
            (void)request_idr(socket, now_us, true, true);
          }
          continue;
        }
        if (errno == EINTR) continue;
        metrics_.last_socket_errno = errno;
        ++metrics_.fatal_socket_errors;
        __android_log_print(
            ANDROID_LOG_ERROR, kTag,
            "video receiver socket error errno=%d consecutive=%u running=%d",
            errno, consecutive_socket_errors + 1U,
            running_.load() ? 1 : 0);
        if (++consecutive_socket_errors < 3U) {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
          continue;
        }
        break;
      }

      consecutive_socket_errors = 0;
      vfdual::VideoFragmentView fragment;
      if (!vfdual::decode_video_packet_view(
              std::span<const std::byte>(
                  datagram.data(), static_cast<std::size_t>(received)),
              fragment)) {
        ++metrics_.rejected_datagrams;
        continue;
      }

      const auto source_decision = source_session_.observe(
          sender.sin_addr.s_addr, sender.sin_port, now_us);
      if (source_decision ==
          vfdual_android::ReceiverSourceDecision::reject_foreign) {
        ++metrics_.foreign_source_datagrams;
        continue;
      }
      const bool source_port_restarted = source_decision ==
          vfdual_android::ReceiverSourceDecision::restart_source_port;
      if (source_port_restarted) ++metrics_.source_changes;

      ++metrics_.accepted_datagrams;
      metrics_.accepted_bytes += static_cast<std::uint64_t>(received);
      last_accepted_datagram_us = now_us;
      if (receive_timeout_backoff_available &&
          receive_timeout_us != kInitialReceiveTimeoutUs) {
        if (set_receive_timeout(socket, kInitialReceiveTimeoutUs)) {
          receive_timeout_us = kInitialReceiveTimeoutUs;
          metrics_.receive_timeout_us = kInitialReceiveTimeoutUs;
        } else {
          receive_timeout_backoff_available = false;
          metrics_.last_socket_errno = errno;
        }
      }
      idr_destination_ = sender;
      idr_destination_.sin_port = htons(kIdrRequestPort);
      idr_destination_ready_ = true;

      const auto epoch_decision =
          epoch_session.observe(fragment.identity.stream_epoch);
      if (epoch_decision == vfdual::ReceiverEpochDecision::invalid) {
        ++metrics_.rejected_datagrams;
        continue;
      }
      if (epoch_decision == vfdual::ReceiverEpochDecision::retired) {
        ++metrics_.retired_epoch_datagrams;
        continue;
      }

      if (epoch_decision == vfdual::ReceiverEpochDecision::candidate) {
        const std::uint64_t candidate_epoch = fragment.identity.stream_epoch;
        if (candidate_reassembler_epoch != candidate_epoch) {
          rebuild_candidate_reassembler(candidate_epoch);
          pending_candidate_idr.reset();
        }
        const std::uint64_t losses_before =
            candidate_reassembler.incomplete_access_unit_losses();
        auto candidate = candidate_reassembler.push_view(fragment, now_us);
        (void)candidate_reassembler.discard_expired(
            now_us, kAccessUnitReassemblyTtlUs);
        const bool candidate_lost =
            candidate_reassembler.incomplete_access_unit_losses() !=
            losses_before;
        if (candidate_lost) {
          ++metrics_.candidate_epoch_rejections;
          rebuild_candidate_reassembler(candidate_epoch);
          (void)request_idr(
              socket, now_us, true, false,
              /*invalidate_active_reference=*/false);
          continue;
        }
        if (!candidate.has_value()) continue;
        const bool complete_real_idr =
            !candidate->repeated_content &&
            vfdual::h264_access_unit_contains_idr(candidate->bytes);
        if (!complete_real_idr) {
          ++metrics_.candidate_epoch_rejections;
          rebuild_candidate_reassembler(candidate_epoch);
          (void)request_idr(
              socket, now_us, true, false,
              /*invalidate_active_reference=*/false);
          continue;
        }

        if (!epoch_session.active_epoch().has_value()) {
          if (!epoch_session.commit_candidate(candidate_epoch, true)) {
            ++metrics_.candidate_epoch_rejections;
            continue;
          }
          rebuild_active_reassembler(candidate->identity.frame_sequence);
          recovery_policy_.reset();
          require_reference_sync();
          const CompletedSubmission submission =
              submit_completed_access_unit(*candidate, now_us);
          if (!submission.accepted) {
            running_ = false;
            break;
          }
          continue;
        }

        pending_candidate_idr = std::move(candidate);
        if (!source_restart_pending) {
          require_reference_sync();
          if (!vfdual_android::decoder().restart_after_stream_discontinuity()) {
            ++metrics_.source_restart_failures;
            running_ = false;
            break;
          }
          source_restart_pending = true;
          decoder_restart_ready = false;
        }
        if (!commit_restarted_candidate(now_us)) {
          running_ = false;
          break;
        }
        continue;
      }

      // Active epoch. During MediaCodec replacement every compressed frame is
      // rejected; only the newest candidate IDR may reopen the pipeline.
      if (source_restart_pending) continue;
      const std::uint64_t reassembly_losses_before =
          active_reassembler.incomplete_access_unit_losses();
      auto completed = active_reassembler.push_view(fragment, now_us);
      const std::size_t expired_access_units =
          active_reassembler.discard_expired(
              now_us, kAccessUnitReassemblyTtlUs);
      const std::uint64_t reassembly_losses =
          active_reassembler.incomplete_access_unit_losses() -
          reassembly_losses_before;
      const bool reassembly_lost = reassembly_losses != 0U;
      if (reassembly_lost) {
        const std::uint64_t dependent_flushes =
            static_cast<std::uint64_t>(
                active_reassembler.inflight_frame_count()) +
            (completed.has_value() ? 1U : 0U);
        metrics_.reassembly_expirations += expired_access_units;
        metrics_.reassembly_incomplete_losses += reassembly_losses;
        metrics_.reassembly_dependent_flushes += dependent_flushes;
        metrics_.dropped_access_units += reassembly_losses + dependent_flushes;
        require_reference_sync();
        completed.reset();
        rebuild_active_reassembler();
      }

      bool fresh_content_accepted = false;
      bool submission_failed = false;
      bool fatal_decoder_failure = false;
      while (completed.has_value()) {
        const CompletedSubmission submission =
            submit_completed_access_unit(*completed, now_us);
        fresh_content_accepted = fresh_content_accepted ||
            (submission.accepted && submission.content_updated);
        submission_failed = submission_failed || !submission.accepted;
        fatal_decoder_failure = fatal_decoder_failure || submission.fatal;
        if (!submission.accepted) break;
        completed = active_reassembler.pop_completed();
      }
      if (fatal_decoder_failure) {
        running_ = false;
        break;
      }
      if (submission_failed) {
        const std::uint64_t dependent_flushes =
            static_cast<std::uint64_t>(
                active_reassembler.inflight_frame_count());
        metrics_.reference_resync_dependent_flushes += dependent_flushes;
        metrics_.dropped_access_units += dependent_flushes;
        rebuild_active_reassembler();
      }
      if (recovery_policy_.observe_fragment(
              now_us, fresh_content_accepted, source_port_restarted,
              reassembly_lost || submission_failed)) {
        const auto pending_flushes = static_cast<std::uint64_t>(
            active_reassembler.inflight_frame_count());
        metrics_.reference_resync_dependent_flushes += pending_flushes;
        metrics_.dropped_access_units += pending_flushes;
        rebuild_active_reassembler();
        (void)request_idr(socket, now_us, true, false);
      }
    }
    running_ = false;
  }

  mutable std::mutex mutex_;
  std::thread worker_;
  std::atomic_bool running_{false};
  std::atomic_bool network_bound_{false};
  std::atomic_bool network_handle_bound_{false};
  std::atomic_bool local_ipv4_bind_fallback_{false};
  std::atomic_int network_handle_bind_errno_{};
  std::atomic<ReceiverStartupStage> startup_stage_{ReceiverStartupStage::not_started};
  std::atomic_int startup_errno_{};
  int socket_{-1};
  sockaddr_in idr_destination_{};
  bool idr_destination_ready_{};
  ReceiverMetrics metrics_;
  vfdual_android::ReceiverRecoveryPolicy recovery_policy_;
  vfdual_android::ReceiverRepeatResyncPolicy repeat_resync_policy_;
  vfdual_android::ReceiverReferenceSyncPolicy reference_sync_policy_;
  vfdual_android::ReceiverSourceSession source_session_{0U};
  std::uint64_t last_presentation_time_us_{};
  // Local monotonic sequence is intentionally independent of the host's
  // frame_id, which restarts after encoder or receiver recovery.
  // This prevents valid post-recovery frames from being suppressed forever by
  // the phone-side non-monotonic-frame safety gate.
  std::uint64_t next_control_sequence_{1};
  std::string local_ipv4_;
  std::string expected_source_ipv4_;
};

[[nodiscard]] bool valid_cat6_probe_token(std::string_view token) noexcept {
  if (token.empty() || token.size() > kMaximumCat6ProbeTokenLength) return false;
  return std::all_of(token.begin(), token.end(), [](char value) {
    return (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z') || value == '_' || value == '-';
  });
}

[[nodiscard]] bool make_cat6_probe_ack(const char* datagram, std::size_t length,
                                       std::array<char, kCat6ProbeBytes>& response) {
  if (datagram == nullptr || length != kCat6ProbeBytes) return false;
  const char* const end = datagram + length;
  const char* const header_end = std::find(datagram, end, '\0');
  if (header_end == end || std::any_of(header_end, end, [](char value) { return value != 0; })) {
    return false;
  }
  const std::string_view header(datagram, static_cast<std::size_t>(header_end - datagram));
  if (!header.starts_with(kCat6ProbePrefix) || !header.ends_with('|')) return false;
  const std::string_view token = header.substr(
      kCat6ProbePrefix.size(), header.size() - kCat6ProbePrefix.size() - 1U);
  if (!valid_cat6_probe_token(token)) return false;
  const std::string ack = std::string(kCat6ProbeAckPrefix) + std::string(token) + "|";
  if (ack.size() > response.size()) return false;
  response.fill(0);
  std::copy(ack.begin(), ack.end(), response.begin());
  return true;
}

[[nodiscard]] std::string requester_ipv4_text(std::uint32_t network_order_ipv4) {
  if (network_order_ipv4 == 0U) return "none";
  in_addr address{};
  address.s_addr = network_order_ipv4;
  char text[INET_ADDRSTRLEN]{};
  if (::inet_ntop(AF_INET, &address, text, sizeof(text)) == nullptr) return "unavailable";
  return text;
}

enum class Cat6ReadyStage : int {
  not_started,
  invalid_arguments,
  invalid_address,
  socket_create_failed,
  network_bind_failed,
  receive_timeout_failed,
  local_bind_failed,
  worker_thread_failed,
  running,
  worker_socket_failed,
  stopped,
};

[[nodiscard]] const char* cat6_ready_stage_name(Cat6ReadyStage stage) noexcept {
  switch (stage) {
    case Cat6ReadyStage::not_started: return "not_started";
    case Cat6ReadyStage::invalid_arguments: return "invalid_arguments";
    case Cat6ReadyStage::invalid_address: return "invalid_address";
    case Cat6ReadyStage::socket_create_failed: return "socket_create_failed";
    case Cat6ReadyStage::network_bind_failed: return "network_bind_failed";
    case Cat6ReadyStage::receive_timeout_failed: return "receive_timeout_failed";
    case Cat6ReadyStage::local_bind_failed: return "local_bind_failed";
    case Cat6ReadyStage::worker_thread_failed: return "worker_thread_failed";
    case Cat6ReadyStage::running: return "running";
    case Cat6ReadyStage::worker_socket_failed: return "worker_socket_failed";
    case Cat6ReadyStage::stopped: return "stopped";
  }
  return "unknown";
}

class Cat6ReadyAgent final {
public:
  bool start(std::string_view local_ipv4, std::string_view host_ipv4,
             std::string_view broadcast_ipv4, net_handle_t network_handle) {
    std::scoped_lock lock(mutex_);
    if (running_) return true;
    startup_errno_ = 0;
    last_socket_errno_ = 0;
    network_bound_ = false;
    network_handle_bound_ = false;
    local_ipv4_bind_fallback_ = false;
    network_handle_bind_errno_ = 0;
    ready_messages_sent_ = 0;
    ready_send_failures_ = 0;
    primary_ready_messages_sent_ = 0;
    primary_ready_send_failures_ = 0;
    broadcast_ready_messages_sent_ = 0;
    broadcast_ready_send_failures_ = 0;
    broadcast_enabled_ = false;
    multicast_interface_configured_ = false;
    multicast_ttl_configured_ = false;
    broadcast_socket_errno_ = 0;
    probes_received_ = 0;
    probe_acks_sent_ = 0;
    probe_ack_failures_ = 0;
    last_requester_ipv4_network_order_.store(0U);
    if (network_handle == NETWORK_UNSPECIFIED) {
      stage_ = Cat6ReadyStage::invalid_arguments;
      startup_errno_ = EINVAL;
      return false;
    }
    if (worker_.joinable()) worker_.join();
    if (socket_ >= 0) {
      ::close(socket_);
      socket_ = -1;
    }

    in_addr local_address{};
    sockaddr_in host{};
    sockaddr_in broadcast{};
    host.sin_family = AF_INET;
    host.sin_port = htons(kCat6ReadyPort);
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(kCat6ReadyPort);
    const std::string local_ipv4_string(local_ipv4);
    const std::string host_ipv4_string(host_ipv4);
    const std::string broadcast_ipv4_string(broadcast_ipv4);
    if (::inet_pton(AF_INET, local_ipv4_string.c_str(), &local_address) != 1 ||
        ::inet_pton(AF_INET, host_ipv4_string.c_str(), &host.sin_addr) != 1 ||
        (!broadcast_ipv4_string.empty() &&
         ::inet_pton(AF_INET, broadcast_ipv4_string.c_str(), &broadcast.sin_addr) != 1)) {
      stage_ = Cat6ReadyStage::invalid_address;
      startup_errno_ = EINVAL;
      return false;
    }

    const int socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket < 0) {
      stage_ = Cat6ReadyStage::socket_create_failed;
      startup_errno_ = errno;
      return false;
    }
    const int network_bind_result =
        ::android_setsocknetwork(network_handle, socket);
    if (network_bind_result != 0) {
      const int network_bind_error =
          normalized_network_bind_error(network_bind_result);
      if (!can_fallback_to_local_ipv4_bind(network_bind_error)) {
        stage_ = Cat6ReadyStage::network_bind_failed;
        startup_errno_ = network_bind_error;
        ::close(socket);
        return false;
      }
      local_ipv4_bind_fallback_ = true;
      network_handle_bind_errno_ = network_bind_error;
    } else {
      network_handle_bound_ = true;
    }
    if (!broadcast_ipv4_string.empty()) {
      int enabled = 1;
      if (::setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) == 0) {
        broadcast_enabled_ = true;
      } else {
        broadcast_socket_errno_ = errno;
      }
    }
    const std::uint32_t host_order = ntohl(host.sin_addr.s_addr);
    if (IN_MULTICAST(host_order)) {
      multicast_interface_configured_ =
          ::setsockopt(socket, IPPROTO_IP, IP_MULTICAST_IF, &local_address,
                       sizeof(local_address)) == 0;
      const unsigned char ttl = 1;
      multicast_ttl_configured_ =
          ::setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == 0;
    }
    timeval receive_timeout{};
    receive_timeout.tv_usec = 25'000;
    if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                     sizeof(receive_timeout)) != 0) {
      stage_ = Cat6ReadyStage::receive_timeout_failed;
      startup_errno_ = errno;
      network_bound_ = false;
      ::close(socket);
      return false;
    }
    int reuse = 1;
    (void)::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in local{};
    local.sin_family = AF_INET;
    // Prefer the Android network handle so the listener survives address
    // repair. Vendor kernels that reject that mark are constrained by the
    // already-selected concrete local IPv4 instead of becoming unreachable.
    local.sin_addr = local_ipv4_bind_fallback_
        ? local_address
        : in_addr{htonl(INADDR_ANY)};
    local.sin_port = htons(kCat6ProbePort);
    if (::bind(socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
      stage_ = Cat6ReadyStage::local_bind_failed;
      startup_errno_ = errno;
      network_bound_ = false;
      ::close(socket);
      return false;
    }
    network_bound_ = true;

    socket_ = socket;
    local_ipv4_ = local_ipv4_string;
    host_ = host;
    broadcast_ = broadcast;
    running_ = true;
    stage_ = Cat6ReadyStage::running;
    try {
      worker_ = std::thread(&Cat6ReadyAgent::run, this, socket);
    } catch (const std::system_error& failure) {
      stage_ = Cat6ReadyStage::worker_thread_failed;
      startup_errno_ = failure.code().value() == 0 ? EAGAIN : failure.code().value();
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    } catch (const std::exception&) {
      stage_ = Cat6ReadyStage::worker_thread_failed;
      startup_errno_ = EAGAIN;
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    } catch (...) {
      stage_ = Cat6ReadyStage::worker_thread_failed;
      startup_errno_ = EAGAIN;
      running_ = false;
      network_bound_ = false;
      ::close(socket_);
      socket_ = -1;
      return false;
    }
    return true;
  }

  void stop() {
    std::scoped_lock lock(mutex_);
    running_ = false;
    if (socket_ >= 0) {
      ::shutdown(socket_, SHUT_RDWR);
      ::close(socket_);
      socket_ = -1;
    }
    if (worker_.joinable()) worker_.join();
    network_bound_ = false;
    stage_ = Cat6ReadyStage::stopped;
  }

  [[nodiscard]] bool running() const noexcept {
    return running_.load();
  }

  [[nodiscard]] std::string report() const {
    std::scoped_lock lock(mutex_);
    std::ostringstream result;
    result << "CAT6 ready agent running=" << running_
           << " stage=" << cat6_ready_stage_name(stage_.load())
           << " startup_errno=" << startup_errno_
           << " last_socket_errno=" << last_socket_errno_
           << " ethernet_network_bound=" << network_bound_
           << " network_handle_bound=" << network_handle_bound_
           << " local_ipv4_bind_fallback=" << local_ipv4_bind_fallback_
           << " network_handle_bind_errno=" << network_handle_bind_errno_
           << " ready_messages_sent=" << ready_messages_sent_
           << " ready_send_failures=" << ready_send_failures_
           << " primary_ready_messages_sent=" << primary_ready_messages_sent_
           << " primary_ready_send_failures=" << primary_ready_send_failures_
           << " broadcast_enabled=" << broadcast_enabled_
           << " broadcast_socket_errno=" << broadcast_socket_errno_
           << " broadcast_ready_messages_sent=" << broadcast_ready_messages_sent_
           << " broadcast_ready_send_failures=" << broadcast_ready_send_failures_
           << " multicast_interface_configured=" << multicast_interface_configured_
           << " multicast_ttl_configured=" << multicast_ttl_configured_
           << " probes_received=" << probes_received_
           << " probe_acks_sent=" << probe_acks_sent_
           << " probe_ack_failures=" << probe_ack_failures_
           << " last_requester_ipv4=" << requester_ipv4_text(
               last_requester_ipv4_network_order_.load());
    return result.str();
  }

  [[nodiscard]] std::string requester_ipv4() const {
    return requester_ipv4_text(last_requester_ipv4_network_order_.load());
  }

  ~Cat6ReadyAgent() { stop(); }

private:
  void run(int socket) {
    std::array<char, kCat6ProbeBytes + 1U> probe{};
    std::array<char, kCat6ProbeBytes> response{};
    std::uint64_t sequence = 0U;
    auto next_ready = std::chrono::steady_clock::now();
    while (running_) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= next_ready) {
        const std::string ready = std::string(kCat6ReadyPrefix) + local_ipv4_ + "|" +
            std::to_string(sequence);
        send_ready_datagram(
            socket, ready, host_, primary_ready_messages_sent_,
            primary_ready_send_failures_);
        if (broadcast_enabled_) {
          send_ready_datagram(
              socket, ready, broadcast_, broadcast_ready_messages_sent_,
              broadcast_ready_send_failures_);
        }
        sequence = (sequence + 1U) & 0xffff'ffffULL;
        next_ready = now + kCat6ReadyInterval;
      }

      sockaddr_in requester{};
      socklen_t requester_size = sizeof(requester);
      const ssize_t received = ::recvfrom(socket, probe.data(), probe.size(), 0,
          reinterpret_cast<sockaddr*>(&requester), &requester_size);
      if (received <= 0) {
        if (!running_) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
        last_socket_errno_ = errno;
        stage_ = Cat6ReadyStage::worker_socket_failed;
        break;
      }
      ++probes_received_;
      last_requester_ipv4_network_order_.store(requester.sin_addr.s_addr);
      if (!make_cat6_probe_ack(probe.data(), static_cast<std::size_t>(received), response)) {
        continue;
      }
      const ssize_t sent = ::sendto(
          socket, response.data(), response.size(), MSG_NOSIGNAL,
          reinterpret_cast<const sockaddr*>(&requester), requester_size);
      if (sent == static_cast<ssize_t>(response.size())) {
        ++probe_acks_sent_;
      } else {
        ++probe_ack_failures_;
        last_socket_errno_ = errno;
      }
    }
    running_ = false;
  }

  void send_ready_datagram(
      int socket, const std::string& ready, const sockaddr_in& destination,
      std::atomic_uint64_t& successful, std::atomic_uint64_t& failed) {
    const ssize_t sent = ::sendto(
        socket, ready.data(), ready.size(), MSG_NOSIGNAL,
        reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
    if (sent == static_cast<ssize_t>(ready.size())) {
      ++successful;
      ++ready_messages_sent_;
      return;
    }
    ++failed;
    ++ready_send_failures_;
    last_socket_errno_ = errno;
  }

  mutable std::mutex mutex_;
  std::thread worker_;
  std::atomic_bool running_{false};
  std::atomic_bool network_bound_{false};
  std::atomic_bool network_handle_bound_{false};
  std::atomic_bool local_ipv4_bind_fallback_{false};
  std::atomic_int network_handle_bind_errno_{};
  std::atomic<Cat6ReadyStage> stage_{Cat6ReadyStage::not_started};
  std::atomic_int startup_errno_{};
  std::atomic_int last_socket_errno_{};
  std::atomic_uint64_t ready_messages_sent_{};
  std::atomic_uint64_t ready_send_failures_{};
  std::atomic_uint64_t primary_ready_messages_sent_{};
  std::atomic_uint64_t primary_ready_send_failures_{};
  std::atomic_uint64_t broadcast_ready_messages_sent_{};
  std::atomic_uint64_t broadcast_ready_send_failures_{};
  std::atomic_bool broadcast_enabled_{false};
  std::atomic_bool multicast_interface_configured_{false};
  std::atomic_bool multicast_ttl_configured_{false};
  std::atomic_int broadcast_socket_errno_{};
  std::atomic_uint64_t probes_received_{};
  std::atomic_uint64_t probe_acks_sent_{};
  std::atomic_uint64_t probe_ack_failures_{};
  int socket_{-1};
  sockaddr_in host_{};
  sockaddr_in broadcast_{};
  std::string local_ipv4_;
  std::atomic<std::uint32_t> last_requester_ipv4_network_order_{};
};

NativeVideoReceiver& receiver() { static NativeVideoReceiver instance; return instance; }
Cat6ReadyAgent& cat6_ready_agent() { static Cat6ReadyAgent instance; return instance; }

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_startNativeVideoReceiver(
    JNIEnv* environment, jclass, jstring local_ipv4, jstring expected_source_ipv4,
    jint port, jlong network_handle) {
  if (local_ipv4 == nullptr || expected_source_ipv4 == nullptr ||
      port != kAuthenticatedLoopbackVideoPort || network_handle <= 0) {
    return JNI_FALSE;
  }
  const char* local_ipv4_chars = environment->GetStringUTFChars(local_ipv4, nullptr);
  if (local_ipv4_chars == nullptr) return JNI_FALSE;
  const char* expected_source_ipv4_chars =
      environment->GetStringUTFChars(expected_source_ipv4, nullptr);
  if (expected_source_ipv4_chars == nullptr) {
    environment->ReleaseStringUTFChars(local_ipv4, local_ipv4_chars);
    return JNI_FALSE;
  }
  const bool started = receiver().start(
      local_ipv4_chars, expected_source_ipv4_chars,
      static_cast<std::uint16_t>(port),
      static_cast<net_handle_t>(network_handle));
  environment->ReleaseStringUTFChars(
      expected_source_ipv4, expected_source_ipv4_chars);
  environment->ReleaseStringUTFChars(local_ipv4, local_ipv4_chars);
  return started ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_stopNativeVideoReceiver(JNIEnv*, jclass) {
  receiver().stop();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_isNativeVideoReceiverRunning(JNIEnv*, jclass) {
  return receiver().is_running() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeVideoReceiverReport(JNIEnv* environment, jclass) {
  const std::string value = receiver().report();
  return environment->NewStringUTF(value.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_startNativeCat6ReadyAgent(
    JNIEnv* environment, jclass, jstring local_ipv4, jstring host_ipv4,
    jstring broadcast_ipv4, jlong network_handle) {
  if (local_ipv4 == nullptr || host_ipv4 == nullptr || broadcast_ipv4 == nullptr ||
      network_handle <= 0) return JNI_FALSE;
  const char* local_ipv4_chars = environment->GetStringUTFChars(local_ipv4, nullptr);
  if (local_ipv4_chars == nullptr) return JNI_FALSE;
  const char* host_ipv4_chars = environment->GetStringUTFChars(host_ipv4, nullptr);
  if (host_ipv4_chars == nullptr) {
    environment->ReleaseStringUTFChars(local_ipv4, local_ipv4_chars);
    return JNI_FALSE;
  }
  const char* broadcast_ipv4_chars =
      environment->GetStringUTFChars(broadcast_ipv4, nullptr);
  if (broadcast_ipv4_chars == nullptr) {
    environment->ReleaseStringUTFChars(host_ipv4, host_ipv4_chars);
    environment->ReleaseStringUTFChars(local_ipv4, local_ipv4_chars);
    return JNI_FALSE;
  }
  const bool started = cat6_ready_agent().start(
      local_ipv4_chars, host_ipv4_chars, broadcast_ipv4_chars,
      static_cast<net_handle_t>(network_handle));
  environment->ReleaseStringUTFChars(broadcast_ipv4, broadcast_ipv4_chars);
  environment->ReleaseStringUTFChars(host_ipv4, host_ipv4_chars);
  environment->ReleaseStringUTFChars(local_ipv4, local_ipv4_chars);
  return started ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_stopNativeCat6ReadyAgent(JNIEnv*, jclass) {
  cat6_ready_agent().stop();
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_isNativeCat6ReadyAgentRunning(
    JNIEnv*, jclass) {
  return cat6_ready_agent().running() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeCat6ReadyAgentReport(
    JNIEnv* environment, jclass) {
  const std::string value = cat6_ready_agent().report();
  return environment->NewStringUTF(value.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_visionforge_inferencebenchmark_QnnHtpBridge_getNativeCat6ReadyAgentRequesterIpv4(
    JNIEnv* environment, jclass) {
  const std::string value = cat6_ready_agent().requester_ipv4();
  return environment->NewStringUTF(value.c_str());
}
