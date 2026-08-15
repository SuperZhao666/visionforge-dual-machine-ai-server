#include "vfdual/host_mouse_button_publisher.hpp"

#include "vfdual/mouse_button_protocol.hpp"
#include "vfdual/wired_link_contract.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <chrono>
#include <system_error>

namespace vfdual {
namespace {

constexpr auto kButtonPollInterval = std::chrono::milliseconds(4);
constexpr auto kButtonHeartbeatInterval = std::chrono::milliseconds(50);
constexpr auto kTransportRetryInterval = std::chrono::seconds(1);

std::uint8_t read_physical_button_mask() noexcept {
  std::uint8_t mask{};
  if ((GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0) mask |= 0x01U;
  if ((GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0) mask |= 0x02U;
  if ((GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0) mask |= 0x04U;
  if ((GetAsyncKeyState(VK_XBUTTON1) & 0x8000) != 0) mask |= 0x08U;
  if ((GetAsyncKeyState(VK_XBUTTON2) & 0x8000) != 0) mask |= 0x10U;
  return mask;
}

std::uint32_t create_session_id() noexcept {
  LARGE_INTEGER counter{};
  QueryPerformanceCounter(&counter);
  const std::uint64_t mixed =
      static_cast<std::uint64_t>(counter.QuadPart) ^
      (GetTickCount64() << 17U) ^
      (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32U);
  const std::uint32_t folded = static_cast<std::uint32_t>(mixed) ^
      static_cast<std::uint32_t>(mixed >> 32U);
  return folded == 0U ? 1U : folded;
}

}  // namespace

HostMouseButtonPublisher::~HostMouseButtonPublisher() { stop(); }

bool HostMouseButtonPublisher::start(
    std::string_view local_ipv4,
    std::string_view mobile_ipv4) noexcept {
  stop();
  if (local_ipv4.empty() || mobile_ipv4.empty()) return false;
  try {
    local_ipv4_ = local_ipv4;
    mobile_ipv4_ = mobile_ipv4;
  } catch (...) {
    local_ipv4_.clear();
    mobile_ipv4_.clear();
    return false;
  }
  stop_requested_.store(false, std::memory_order_release);
  running_.store(true, std::memory_order_release);
  transport_ready_.store(false, std::memory_order_release);
  current_button_mask_.store(0U, std::memory_order_release);
  packets_sent_.store(0U, std::memory_order_release);
  send_failures_.store(0U, std::memory_order_release);
  last_socket_error_.store(0U, std::memory_order_release);
  session_id_ = create_session_id();
  sequence_ = 0U;
  try {
    worker_ = std::thread(&HostMouseButtonPublisher::run, this);
  } catch (const std::system_error& error) {
    running_.store(false, std::memory_order_release);
    last_socket_error_.store(
        static_cast<std::uint32_t>(error.code().value()),
        std::memory_order_release);
    return false;
  } catch (...) {
    running_.store(false, std::memory_order_release);
    last_socket_error_.store(ERROR_NOT_ENOUGH_MEMORY, std::memory_order_release);
    return false;
  }
  return true;
}

void HostMouseButtonPublisher::stop() noexcept {
  stop_requested_.store(true, std::memory_order_release);
  wait_condition_.notify_all();
  if (worker_.joinable()) worker_.join();
  running_.store(false, std::memory_order_release);
  transport_ready_.store(false, std::memory_order_release);
  current_button_mask_.store(0U, std::memory_order_release);
  local_ipv4_.clear();
  mobile_ipv4_.clear();
}

HostMouseButtonPublisherStats HostMouseButtonPublisher::stats() const noexcept {
  return HostMouseButtonPublisherStats{
      running_.load(std::memory_order_acquire),
      transport_ready_.load(std::memory_order_acquire),
      current_button_mask_.load(std::memory_order_acquire),
      packets_sent_.load(std::memory_order_acquire),
      send_failures_.load(std::memory_order_acquire),
      last_socket_error_.load(std::memory_order_acquire),
  };
}

void HostMouseButtonPublisher::run() noexcept {
  UdpSocket socket;
  std::uint8_t last_published_mask = 0xffU;
  auto last_publish = std::chrono::steady_clock::time_point::min();
  while (!stop_requested_.load(std::memory_order_acquire)) {
    if (!transport_ready_.load(std::memory_order_acquire)) {
      if (!open_transport(socket)) {
        std::unique_lock lock(wait_mutex_);
        wait_condition_.wait_for(lock, kTransportRetryInterval, [this] {
          return stop_requested_.load(std::memory_order_acquire);
        });
        continue;
      }
      last_published_mask = 0xffU;
      last_publish = std::chrono::steady_clock::time_point::min();
    }

    const std::uint8_t current_mask = read_physical_button_mask();
    current_button_mask_.store(current_mask, std::memory_order_release);
    const auto now = std::chrono::steady_clock::now();
    if (current_mask != last_published_mask ||
        now - last_publish >= kButtonHeartbeatInterval) {
      if (!publish(socket, current_mask)) {
        transport_ready_.store(false, std::memory_order_release);
        socket.close();
        continue;
      }
      last_published_mask = current_mask;
      last_publish = now;
    }

    std::unique_lock lock(wait_mutex_);
    wait_condition_.wait_for(lock, kButtonPollInterval, [this] {
      return stop_requested_.load(std::memory_order_acquire);
    });
  }

  if (transport_ready_.load(std::memory_order_acquire)) {
    (void)publish(socket, 0U);
    (void)publish(socket, 0U);
  }
  socket.close();
  transport_ready_.store(false, std::memory_order_release);
}

bool HostMouseButtonPublisher::open_transport(UdpSocket& socket) noexcept {
  socket.close();
  if (!socket.open() ||
      !socket.bind_exclusive_to(local_ipv4_, kWiredMouseButtonPort) ||
      !socket.connect_to(mobile_ipv4_, kWiredMouseButtonPort)) {
    last_socket_error_.store(socket.last_error(), std::memory_order_release);
    socket.close();
    return false;
  }
  last_socket_error_.store(0U, std::memory_order_release);
  transport_ready_.store(true, std::memory_order_release);
  return true;
}

bool HostMouseButtonPublisher::publish(
    UdpSocket& socket,
    std::uint8_t button_mask) noexcept {
  std::array<std::byte, kMouseButtonPacketBytes> datagram{};
  const MouseButtonStatePacket packet{
      button_mask,
      session_id_,
      ++sequence_,
  };
  if (encode_mouse_button_state_packet(packet, datagram) != datagram.size() ||
      !socket.send(datagram)) {
    send_failures_.fetch_add(1U, std::memory_order_relaxed);
    last_socket_error_.store(socket.last_error(), std::memory_order_release);
    return false;
  }
  packets_sent_.fetch_add(1U, std::memory_order_relaxed);
  return true;
}

}  // namespace vfdual
