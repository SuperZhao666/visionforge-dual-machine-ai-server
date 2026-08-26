#pragma once

#include "vfdual/authenticated_data_plane_v2.hpp"
#include "vfdual/authenticated_peer_handshake_v1.hpp"
#include "vfdual/udp_socket.hpp"
#include "vfdual/udp_video_publisher.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace vfdual {

struct HostMouseButtonPublisherStats {
  bool running{};
  bool transport_ready{};
  bool authenticated_session_ready{};
  std::uint8_t current_button_mask{};
  std::uint64_t packets_sent{};
  std::uint64_t send_failures{};
  std::uint32_t last_socket_error{};
};

/**
 * Publishes the Windows physical mouse button state on the selected transport.
 *
 * Movement remains phone-owned. This source only supplies the trigger state
 * needed by the Bluetooth HID output route and sends a zero mask on shutdown.
 */
class HostMouseButtonPublisher final {
public:
  HostMouseButtonPublisher() = default;
  ~HostMouseButtonPublisher();
  HostMouseButtonPublisher(const HostMouseButtonPublisher&) = delete;
  HostMouseButtonPublisher& operator=(const HostMouseButtonPublisher&) = delete;

  [[nodiscard]] bool start(
      std::string_view local_ipv4,
      std::string_view mobile_ipv4,
      VideoDataPlanePermitSource permit_source,
      std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
          authenticated_session = {}) noexcept;
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  /** Test-only fixture path. Production accepts only the shared VFA2 owner. */
  [[nodiscard]] bool install_confirmed_session(
      std::uint64_t connection_id,
      PeerHandshakeDataPlaneKeyView mouse_host_to_android) noexcept;
#endif
  void clear_confirmed_session() noexcept;
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  using InstallPreparationHookForTest = void (*)();
  void set_install_preparation_hook_for_test(
      InstallPreparationHookForTest hook) noexcept;
  using PublishPreLockHookForTest = void (*)();
  void set_publish_pre_lock_hook_for_test(
      PublishPreLockHookForTest hook) noexcept;
  using StopRequestedHookForTest = void (*)();
  void set_stop_requested_hook_for_test(
      StopRequestedHookForTest hook) noexcept;
#endif
  void stop() noexcept;
  [[nodiscard]] HostMouseButtonPublisherStats stats() const noexcept;

private:
  void run() noexcept;
  void clear_confirmed_session_locked() noexcept;
  [[nodiscard]] bool open_transport(UdpSocket& socket) noexcept;
  [[nodiscard]] bool publish(
      UdpSocket& socket,
      std::uint8_t button_mask,
      bool shutdown_release = false) noexcept;
  [[nodiscard]] bool authorization_permits_send() const noexcept;

  std::thread worker_;
  mutable std::mutex wait_mutex_;
  mutable std::mutex session_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool running_{};
  std::atomic_bool transport_ready_{};
  std::atomic_bool authenticated_session_ready_{};
  std::atomic_uint64_t session_revision_{};
  std::atomic_uint8_t current_button_mask_{};
  std::atomic_uint64_t packets_sent_{};
  std::atomic_uint64_t send_failures_{};
  std::atomic_uint32_t last_socket_error_{};
  std::string local_ipv4_;
  std::string mobile_ipv4_;
  VideoDataPlanePermitSource permit_source_;
  std::uint64_t active_connection_id_{};
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  std::unique_ptr<Aes256GcmProvider> aes_provider_;
  std::unique_ptr<AuthenticatedPacketSealer> packet_sealer_;
#endif
  std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
      authenticated_data_plane_session_;
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  InstallPreparationHookForTest install_preparation_hook_for_test_{};
  PublishPreLockHookForTest publish_pre_lock_hook_for_test_{};
  StopRequestedHookForTest stop_requested_hook_for_test_{};
#endif
};

}  // namespace vfdual
