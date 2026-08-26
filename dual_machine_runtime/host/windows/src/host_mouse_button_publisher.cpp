#include "vfdual/host_mouse_button_publisher.hpp"

#include "vfdual/authenticated_mouse_button_v2.hpp"
#include "vfdual/wired_link_contract.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <system_error>
#include <utility>

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

}  // namespace

HostMouseButtonPublisher::~HostMouseButtonPublisher() { stop(); }

#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
void HostMouseButtonPublisher::set_install_preparation_hook_for_test(
    const InstallPreparationHookForTest hook) noexcept {
  std::lock_guard lock(session_mutex_);
  install_preparation_hook_for_test_ = hook;
}

void HostMouseButtonPublisher::set_publish_pre_lock_hook_for_test(
    const PublishPreLockHookForTest hook) noexcept {
  std::lock_guard lock(session_mutex_);
  publish_pre_lock_hook_for_test_ = hook;
}

void HostMouseButtonPublisher::set_stop_requested_hook_for_test(
    const StopRequestedHookForTest hook) noexcept {
  std::lock_guard lock(session_mutex_);
  stop_requested_hook_for_test_ = hook;
}
#endif

bool HostMouseButtonPublisher::start(
    std::string_view local_ipv4,
    std::string_view mobile_ipv4,
    VideoDataPlanePermitSource permit_source,
    std::shared_ptr<HostAuthenticatedDataPlaneSessionV2>
        authenticated_session) noexcept {
  stop();
  if (local_ipv4.empty() || mobile_ipv4.empty() || !permit_source) return false;
  try {
    local_ipv4_ = local_ipv4;
    mobile_ipv4_ = mobile_ipv4;
    permit_source_ = std::move(permit_source);
  } catch (...) {
    local_ipv4_.clear();
    mobile_ipv4_.clear();
    permit_source_ = {};
    return false;
  }
  stop_requested_.store(false, std::memory_order_release);
  running_.store(true, std::memory_order_release);
  transport_ready_.store(false, std::memory_order_release);
  authenticated_session_ready_.store(false, std::memory_order_release);
  session_revision_.store(0U, std::memory_order_release);
  current_button_mask_.store(0U, std::memory_order_release);
  packets_sent_.store(0U, std::memory_order_release);
  send_failures_.store(0U, std::memory_order_release);
  last_socket_error_.store(0U, std::memory_order_release);
  if (authenticated_session) {
    std::lock_guard lock(session_mutex_);
    active_connection_id_ = authenticated_session->connection_id();
    authenticated_data_plane_session_ = std::move(authenticated_session);
    authenticated_session_ready_.store(true, std::memory_order_release);
  }
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

#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
bool HostMouseButtonPublisher::install_confirmed_session(
    const std::uint64_t connection_id,
    const PeerHandshakeDataPlaneKeyView mouse_host_to_android) noexcept {
  if (!running_.load(std::memory_order_acquire) ||
      stop_requested_.load(std::memory_order_acquire)) {
    return false;
  }
  try {
    std::unique_lock session_lock(session_mutex_);
    if (!running_.load(std::memory_order_acquire) ||
        stop_requested_.load(std::memory_order_acquire)) {
      return false;
    }
    if (connection_id == 0U) {
      clear_confirmed_session_locked();
      session_lock.unlock();
      transport_ready_.store(false, std::memory_order_release);
      current_button_mask_.store(0U, std::memory_order_release);
      wait_condition_.notify_all();
      return false;
    }
    authenticated_data_plane_session_.reset();
    if (authenticated_session_ready_.load(std::memory_order_acquire) &&
        packet_sealer_ && active_connection_id_ == connection_id) {
      // A lifecycle retry for the same confirmed connection must preserve
      // the one counter owner. Rebuilding it would reuse AES-GCM nonces.
      return true;
    }
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
    if (install_preparation_hook_for_test_) {
      install_preparation_hook_for_test_();
    }
#endif
    auto provider = make_platform_aes_256_gcm_provider();
    if (!provider) {
      clear_confirmed_session_locked();
      session_lock.unlock();
      transport_ready_.store(false, std::memory_order_release);
      current_button_mask_.store(0U, std::memory_order_release);
      wait_condition_.notify_all();
      return false;
    }
    AuthenticatedTrafficKey traffic_key;
    traffic_key.tuple =
        make_authenticated_mouse_button_host_to_android_tuple(connection_id);
    std::copy(
        mouse_host_to_android.aes_256_key.begin(),
        mouse_host_to_android.aes_256_key.end(),
        traffic_key.aes_256_key.begin());
    std::copy(
        mouse_host_to_android.nonce_prefix.begin(),
        mouse_host_to_android.nonce_prefix.end(),
        traffic_key.nonce_prefix.begin());
    auto sealer = std::make_unique<AuthenticatedPacketSealer>(
        std::move(traffic_key), *provider);
    if (!running_.load(std::memory_order_acquire) ||
        stop_requested_.load(std::memory_order_acquire)) {
      return false;
    }
    packet_sealer_.reset();
    aes_provider_.reset();
    aes_provider_ = std::move(provider);
    packet_sealer_ = std::move(sealer);
    active_connection_id_ = connection_id;
    authenticated_session_ready_.store(true, std::memory_order_release);
    session_revision_.fetch_add(1U, std::memory_order_acq_rel);
    session_lock.unlock();
    transport_ready_.store(false, std::memory_order_release);
    wait_condition_.notify_all();
    return true;
  } catch (...) {
    {
      std::lock_guard lock(session_mutex_);
      if (stop_requested_.load(std::memory_order_acquire)) return false;
      clear_confirmed_session_locked();
    }
    transport_ready_.store(false, std::memory_order_release);
    current_button_mask_.store(0U, std::memory_order_release);
    wait_condition_.notify_all();
    return false;
  }
}
#endif

void HostMouseButtonPublisher::clear_confirmed_session() noexcept {
  {
    std::lock_guard lock(session_mutex_);
    clear_confirmed_session_locked();
  }
  transport_ready_.store(false, std::memory_order_release);
  current_button_mask_.store(0U, std::memory_order_release);
  wait_condition_.notify_all();
}

void HostMouseButtonPublisher::clear_confirmed_session_locked() noexcept {
  authenticated_session_ready_.store(false, std::memory_order_release);
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  packet_sealer_.reset();
  aes_provider_.reset();
#endif
  authenticated_data_plane_session_.reset();
  active_connection_id_ = 0U;
  session_revision_.fetch_add(1U, std::memory_order_acq_rel);
}

void HostMouseButtonPublisher::stop() noexcept {
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  StopRequestedHookForTest stop_requested_hook{};
#endif
  {
    std::lock_guard lock(session_mutex_);
    stop_requested_.store(true, std::memory_order_release);
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
    stop_requested_hook = stop_requested_hook_for_test_;
#endif
  }
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  if (stop_requested_hook) stop_requested_hook();
#endif
  wait_condition_.notify_all();
  if (worker_.joinable()) worker_.join();
  clear_confirmed_session();
  running_.store(false, std::memory_order_release);
  transport_ready_.store(false, std::memory_order_release);
  current_button_mask_.store(0U, std::memory_order_release);
  local_ipv4_.clear();
  mobile_ipv4_.clear();
  permit_source_ = {};
}

HostMouseButtonPublisherStats HostMouseButtonPublisher::stats() const noexcept {
  return HostMouseButtonPublisherStats{
      running_.load(std::memory_order_acquire),
      transport_ready_.load(std::memory_order_acquire),
      authenticated_session_ready_.load(std::memory_order_acquire),
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
  std::uint64_t active_session_revision =
      session_revision_.load(std::memory_order_acquire);
  while (!stop_requested_.load(std::memory_order_acquire)) {
    const std::uint64_t current_session_revision =
        session_revision_.load(std::memory_order_acquire);
    if (current_session_revision != active_session_revision) {
      active_session_revision = current_session_revision;
      transport_ready_.store(false, std::memory_order_release);
      socket.close();
      last_published_mask = 0xffU;
      last_publish = std::chrono::steady_clock::time_point::min();
    }
    if (!authorization_permits_send()) {
      current_button_mask_.store(0U, std::memory_order_release);
      transport_ready_.store(false, std::memory_order_release);
      socket.close();
      std::unique_lock lock(wait_mutex_);
      wait_condition_.wait_for(lock, kButtonPollInterval, [this] {
        return stop_requested_.load(std::memory_order_acquire);
      });
      continue;
    }
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
        if (stop_requested_.load(std::memory_order_acquire)) break;
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

  if (transport_ready_.load(std::memory_order_acquire) &&
      authorization_permits_send()) {
    (void)publish(socket, 0U, true);
    (void)publish(socket, 0U, true);
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
    std::uint8_t button_mask,
    const bool shutdown_release) noexcept {
  if (!authorization_permits_send()) return false;
  std::array<std::byte, kAuthenticatedMouseButtonPayloadBytes> payload{};
  if (!encode_authenticated_mouse_button_payload(button_mask, payload)) {
    send_failures_.fetch_add(1U, std::memory_order_relaxed);
    return false;
  }
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  PublishPreLockHookForTest publish_pre_lock_hook{};
  {
    std::lock_guard hook_lock(session_mutex_);
    publish_pre_lock_hook = publish_pre_lock_hook_for_test_;
  }
  if (publish_pre_lock_hook) publish_pre_lock_hook();
#endif
  std::lock_guard lock(session_mutex_);
  if ((!shutdown_release &&
      stop_requested_.load(std::memory_order_acquire)) ||
      !authenticated_session_ready_.load(std::memory_order_acquire) ||
      !authenticated_data_plane_session_
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
      && !packet_sealer_
#endif
      ||
      !authorization_permits_send()) {
    return false;
  }
  PacketSealResult sealed{};
  if (authenticated_data_plane_session_) {
    sealed = authenticated_data_plane_session_->seal_mouse_button(payload);
  }
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
  else if (packet_sealer_) {
    sealed = packet_sealer_->seal(payload);
  }
#endif
  if (sealed.status != PacketSealStatus::sealed) {
    send_failures_.fetch_add(1U, std::memory_order_relaxed);
    if (sealed.status == PacketSealStatus::counter_exhausted ||
        sealed.status == PacketSealStatus::invalid_configuration) {
      authenticated_session_ready_.store(false, std::memory_order_release);
#if defined(VFDUAL_HOST_MOUSE_BUTTON_PUBLISHER_TESTING)
      packet_sealer_.reset();
      aes_provider_.reset();
#endif
      authenticated_data_plane_session_.reset();
      active_connection_id_ = 0U;
      session_revision_.fetch_add(1U, std::memory_order_acq_rel);
    }
    return false;
  }
  // The live lease may be revoked while this publisher waits for the session
  // lock or while the provider seals. Burn the attempted counter, but never
  // cross the UDP boundary after the send-boundary authorization recheck.
  if (!authorization_permits_send()) return false;
  if (!socket.send(sealed.datagram)) {
    send_failures_.fetch_add(1U, std::memory_order_relaxed);
    last_socket_error_.store(socket.last_error(), std::memory_order_release);
    return false;
  }
  packets_sent_.fetch_add(1U, std::memory_order_relaxed);
  return true;
}

bool HostMouseButtonPublisher::authorization_permits_send() const noexcept {
  if (!authenticated_session_ready_.load(std::memory_order_acquire) ||
      !permit_source_) {
    return false;
  }
  try {
    return permit_source_();
  } catch (...) {
    return false;
  }
}

}  // namespace vfdual
