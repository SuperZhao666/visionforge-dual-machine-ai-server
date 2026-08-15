#pragma once

#include "vfdual/udp_socket.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace vfdual {

struct HostMouseButtonPublisherStats {
  bool running{};
  bool transport_ready{};
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
      std::string_view mobile_ipv4) noexcept;
  void stop() noexcept;
  [[nodiscard]] HostMouseButtonPublisherStats stats() const noexcept;

private:
  void run() noexcept;
  [[nodiscard]] bool open_transport(UdpSocket& socket) noexcept;
  [[nodiscard]] bool publish(
      UdpSocket& socket, std::uint8_t button_mask) noexcept;

  std::thread worker_;
  mutable std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool running_{};
  std::atomic_bool transport_ready_{};
  std::atomic_uint8_t current_button_mask_{};
  std::atomic_uint64_t packets_sent_{};
  std::atomic_uint64_t send_failures_{};
  std::atomic_uint32_t last_socket_error_{};
  std::uint32_t session_id_{};
  std::uint32_t sequence_{};
  std::string local_ipv4_;
  std::string mobile_ipv4_;
};

}  // namespace vfdual
