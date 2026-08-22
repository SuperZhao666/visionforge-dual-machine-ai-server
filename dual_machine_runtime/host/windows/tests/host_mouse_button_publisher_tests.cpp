#include "vfdual/authenticated_data_plane_v2.hpp"
#include "vfdual/authenticated_mouse_button_v2.hpp"
#include "vfdual/authenticated_peer_handshake_v1.hpp"
#include "vfdual/host_mouse_button_publisher.hpp"
#include "vfdual/udp_socket.hpp"
#include "vfdual/wired_link_contract.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <span>
#include <thread>
#include <utility>

namespace {

std::mutex install_gate_mutex;
std::condition_variable install_gate_condition;
bool install_gate_entered{};
bool release_install_gate{};

std::mutex publish_gate_mutex;
std::condition_variable publish_gate_condition;
bool publish_gate_entered{};
bool release_publish_gate{};

std::mutex stop_gate_mutex;
std::condition_variable stop_gate_condition;
bool stop_gate_entered{};
bool release_stop_gate{};

void reset_install_gate() {
    std::lock_guard lock(install_gate_mutex);
    install_gate_entered = false;
    release_install_gate = false;
}

void block_install_preparation() {
    std::unique_lock lock(install_gate_mutex);
    install_gate_entered = true;
    install_gate_condition.notify_all();
    install_gate_condition.wait(lock, [] { return release_install_gate; });
}

void reset_publish_gate() {
    std::lock_guard lock(publish_gate_mutex);
    publish_gate_entered = false;
    release_publish_gate = false;
}

void block_before_publish_session_lock() {
    std::unique_lock lock(publish_gate_mutex);
    publish_gate_entered = true;
    publish_gate_condition.notify_all();
    publish_gate_condition.wait(lock, [] { return release_publish_gate; });
}

void reset_stop_gate() {
    std::lock_guard lock(stop_gate_mutex);
    stop_gate_entered = false;
    release_stop_gate = false;
}

void block_after_stop_requested() {
    std::unique_lock lock(stop_gate_mutex);
    stop_gate_entered = true;
    stop_gate_condition.notify_all();
    stop_gate_condition.wait(lock, [] { return release_stop_gate; });
}

void require(bool condition, const char* expression, const char* file, int line) {
    if (condition) return;
    std::cerr << file << ':' << line << ": CHECK failed: "
              << expression << '\n';
    std::exit(EXIT_FAILURE);
}

}  // namespace

#define CHECK(expression) \
    require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    constexpr std::uint64_t connection_id = 0x0123'4567'89ab'cdefULL;
    std::array<std::byte, 36U> material{};
    std::array<std::byte, 36U> replacement_material{};
    for (std::size_t index{}; index < material.size(); ++index) {
        material[index] = std::byte{static_cast<std::uint8_t>(0x20U + index)};
        replacement_material[index] =
            std::byte{static_cast<std::uint8_t>(0x60U + index)};
    }
    const vfdual::PeerHandshakeDataPlaneKeyView key_view{
        std::span<const std::byte, 32U>{material.data(), 32U},
        std::span<const std::byte, 4U>{material.data() + 32U, 4U},
    };
    const vfdual::PeerHandshakeDataPlaneKeyView replacement_key_view{
        std::span<const std::byte, 32U>{replacement_material.data(), 32U},
        std::span<const std::byte, 4U>{replacement_material.data() + 32U, 4U},
    };

    vfdual::UdpSocket receiver;
    CHECK(receiver.bind_exclusive_to(
        "127.0.0.2", vfdual::kWiredMouseButtonPort));

    vfdual::HostMouseButtonPublisher publisher;
    CHECK(!publisher.install_confirmed_session(connection_id, key_view));
    std::atomic_bool permit_send{};
    CHECK(publisher.start(
        "127.0.0.1", "127.0.0.2",
        [&permit_send] { return permit_send.load(std::memory_order_acquire); }));

    std::array<std::byte, 64U> datagram{};
    CHECK(receiver.receive(datagram, 120U) == 0U);
    CHECK(!publisher.stats().authenticated_session_ready);
    CHECK(!publisher.install_confirmed_session(0U, key_view));

    // An install that started first must hold the lifecycle boundary until its
    // commit. A later clear cannot return early and then be overtaken by the
    // in-flight install.
    reset_install_gate();
    publisher.set_install_preparation_hook_for_test(block_install_preparation);
    std::atomic_bool install_result{};
    std::thread installer([&] {
        install_result.store(
            publisher.install_confirmed_session(connection_id, key_view),
            std::memory_order_release);
    });
    {
        std::unique_lock lock(install_gate_mutex);
        CHECK(install_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return install_gate_entered; }));
    }
    std::atomic_bool clear_started{};
    std::atomic_bool clear_finished{};
    std::thread clearer([&] {
        clear_started.store(true, std::memory_order_release);
        publisher.clear_confirmed_session();
        clear_finished.store(true, std::memory_order_release);
    });
    while (!clear_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    CHECK(!clear_finished.load(std::memory_order_acquire));
    {
        std::lock_guard lock(install_gate_mutex);
        release_install_gate = true;
    }
    install_gate_condition.notify_all();
    installer.join();
    clearer.join();
    CHECK(install_result.load(std::memory_order_acquire));
    CHECK(clear_finished.load(std::memory_order_acquire));
    CHECK(!publisher.stats().authenticated_session_ready);
    publisher.set_install_preparation_hook_for_test(nullptr);

    // Stop uses the same session mutex as install. Once an install owns that
    // boundary, stop cannot publish its request between the installer's final
    // lifecycle check and commit.
    reset_install_gate();
    reset_stop_gate();
    publisher.set_install_preparation_hook_for_test(block_install_preparation);
    publisher.set_stop_requested_hook_for_test(block_after_stop_requested);
    std::atomic_bool stop_race_install_result{};
    std::thread stop_race_installer([&] {
        stop_race_install_result.store(
            publisher.install_confirmed_session(connection_id, key_view),
            std::memory_order_release);
    });
    {
        std::unique_lock lock(install_gate_mutex);
        CHECK(install_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return install_gate_entered; }));
    }
    std::thread install_race_stopper([&] { publisher.stop(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    {
        std::lock_guard lock(stop_gate_mutex);
        CHECK(!stop_gate_entered);
    }
    {
        std::lock_guard lock(install_gate_mutex);
        release_install_gate = true;
    }
    install_gate_condition.notify_all();
    stop_race_installer.join();
    {
        std::unique_lock lock(stop_gate_mutex);
        CHECK(stop_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return stop_gate_entered; }));
    }
    CHECK(stop_race_install_result.load(std::memory_order_acquire));
    CHECK(publisher.stats().authenticated_session_ready);
    {
        std::lock_guard lock(stop_gate_mutex);
        release_stop_gate = true;
    }
    stop_gate_condition.notify_all();
    install_race_stopper.join();
    CHECK(!publisher.stats().running);
    CHECK(!publisher.stats().authenticated_session_ready);
    publisher.set_install_preparation_hook_for_test(nullptr);
    publisher.set_stop_requested_hook_for_test(nullptr);
    CHECK(publisher.start(
        "127.0.0.1", "127.0.0.2",
        [&permit_send] { return permit_send.load(std::memory_order_acquire); }));

    // Authorization is live, not a one-time loop admission. If it is revoked
    // after publish starts but before the session lock is acquired, no packet
    // may cross the UDP boundary.
    reset_publish_gate();
    publisher.set_publish_pre_lock_hook_for_test(
        block_before_publish_session_lock);
    permit_send.store(true, std::memory_order_release);
    CHECK(publisher.install_confirmed_session(connection_id, key_view));
    CHECK(publisher.stats().authenticated_session_ready);
    {
        std::unique_lock lock(publish_gate_mutex);
        CHECK(publish_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return publish_gate_entered; }));
    }
    permit_send.store(false, std::memory_order_release);
    {
        std::lock_guard lock(publish_gate_mutex);
        release_publish_gate = true;
    }
    publish_gate_condition.notify_all();
    CHECK(receiver.receive(datagram, 200U) == 0U);
    publisher.set_publish_pre_lock_hook_for_test(nullptr);
    publisher.clear_confirmed_session();

    permit_send.store(true, std::memory_order_release);
    CHECK(publisher.install_confirmed_session(connection_id, key_view));
    CHECK(publisher.stats().authenticated_session_ready);

    const std::size_t received = receiver.receive(datagram, 1500U);
    CHECK(received == 49U);
    auto opener_key =
        vfdual::make_authenticated_mouse_button_host_to_android_key(
            connection_id, material);
    auto provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(provider != nullptr);
    vfdual::AuthenticatedPacketOpener opener(
        std::move(opener_key), *provider);
    const auto opened = opener.open(
        std::span<const std::byte>{datagram.data(), received});
    CHECK(opened.status == vfdual::PacketOpenStatus::opened);
    std::uint8_t button_mask{0xffU};
    CHECK(vfdual::decode_authenticated_mouse_button_payload(
        opened.plaintext, button_mask));
    CHECK((button_mask & ~vfdual::kAuthenticatedMouseButtonValidMask) == 0U);

    // A lifecycle retry for the same connection must keep the original
    // counter owner. Resetting it would make the opener reject a reused nonce.
    CHECK(publisher.install_confirmed_session(connection_id, key_view));
    const std::size_t duplicate_install_received =
        receiver.receive(datagram, 1500U);
    CHECK(duplicate_install_received == 49U);
    const auto after_duplicate_install = opener.open(
        std::span<const std::byte>{
            datagram.data(), duplicate_install_received});
    CHECK(after_duplicate_install.status == vfdual::PacketOpenStatus::opened);

    // Any invalid replacement fails closed instead of leaving the old key live.
    CHECK(!publisher.install_confirmed_session(0U, key_view));
    CHECK(!publisher.stats().authenticated_session_ready);
    while (receiver.receive(datagram, 10U) != 0U) {
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(receiver.receive(datagram, 80U) == 0U);

    constexpr std::uint64_t replacement_connection_id = connection_id + 1U;
    CHECK(publisher.install_confirmed_session(
        replacement_connection_id, replacement_key_view));
    const std::size_t replacement_received = receiver.receive(datagram, 1500U);
    CHECK(replacement_received == 49U);
    auto replacement_opener_key =
        vfdual::make_authenticated_mouse_button_host_to_android_key(
            replacement_connection_id, replacement_material);
    auto replacement_provider = vfdual::make_platform_aes_256_gcm_provider();
    CHECK(replacement_provider != nullptr);
    vfdual::AuthenticatedPacketOpener replacement_opener(
        std::move(replacement_opener_key), *replacement_provider);
    const auto replacement_opened = replacement_opener.open(
        std::span<const std::byte>{datagram.data(), replacement_received});
    CHECK(replacement_opened.status == vfdual::PacketOpenStatus::opened);

    // Freeze a normal publish immediately before its session lock, then begin
    // stop. Stop must own that same lifecycle lock before setting its flag:
    // the in-flight normal publish is rejected, a later install cannot clear
    // the active sealer, and the worker can still emit exactly two authenticated
    // zero-mask release packets before teardown.
    while (receiver.receive(datagram, 10U) != 0U) {
    }
    reset_publish_gate();
    reset_stop_gate();
    publisher.set_publish_pre_lock_hook_for_test(
        block_before_publish_session_lock);
    publisher.set_stop_requested_hook_for_test(block_after_stop_requested);
    {
        std::unique_lock lock(publish_gate_mutex);
        CHECK(publish_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return publish_gate_entered; }));
    }
    std::thread stopper([&] { publisher.stop(); });
    {
        std::unique_lock lock(stop_gate_mutex);
        CHECK(stop_gate_condition.wait_for(
            lock, std::chrono::seconds(2), [] { return stop_gate_entered; }));
    }
    CHECK(!publisher.install_confirmed_session(connection_id, key_view));
    CHECK(publisher.stats().authenticated_session_ready);
    {
        std::lock_guard lock(publish_gate_mutex);
        release_publish_gate = true;
    }
    publish_gate_condition.notify_all();
    {
        std::lock_guard lock(stop_gate_mutex);
        release_stop_gate = true;
    }
    stop_gate_condition.notify_all();
    stopper.join();
    publisher.set_publish_pre_lock_hook_for_test(nullptr);
    publisher.set_stop_requested_hook_for_test(nullptr);

    for (int release_index = 0; release_index < 2; ++release_index) {
        const std::size_t release_received = receiver.receive(datagram, 1500U);
        CHECK(release_received == 49U);
        const auto release_opened = replacement_opener.open(
            std::span<const std::byte>{datagram.data(), release_received});
        CHECK(release_opened.status == vfdual::PacketOpenStatus::opened);
        std::uint8_t release_mask{0xffU};
        CHECK(vfdual::decode_authenticated_mouse_button_payload(
            release_opened.plaintext, release_mask));
        CHECK(release_mask == 0U);
    }
    CHECK(receiver.receive(datagram, 100U) == 0U);
    CHECK(!publisher.stats().running);
    CHECK(!publisher.stats().authenticated_session_ready);
    return EXIT_SUCCESS;
}
