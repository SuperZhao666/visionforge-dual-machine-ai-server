#include "vfdual/host_authenticated_control_service_v1.hpp"

#include "vfdual/wired_link_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

namespace vfdual {
namespace {

inline constexpr std::uint32_t kAcceptPollMilliseconds = 500U;
inline constexpr std::uint32_t kHandshakeIoMilliseconds = 60'000U;

[[nodiscard]] HostAuthenticatedControlTimeV1 now() noexcept {
    const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto monotonic = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (epoch <= 0 || monotonic <= 0 ||
        static_cast<std::uint64_t>(monotonic) >
            (std::numeric_limits<std::uint64_t>::max)()) {
        return {};
    }
    return {
        .epoch_seconds = epoch,
        .monotonic_milliseconds = static_cast<std::uint64_t>(monotonic),
    };
}

[[nodiscard]] bool ipv4_bytes(
    const std::string_view input,
    std::array<std::byte, 4U>& output) noexcept {
    output = {};
    std::size_t start{};
    for (std::size_t index{}; index < output.size(); ++index) {
        const std::size_t separator = input.find('.', start);
        const std::size_t end = index + 1U == output.size()
            ? input.size() : separator;
        if (end == std::string_view::npos || end <= start ||
            end - start > 3U ||
            (index + 1U != output.size() &&
             separator == std::string_view::npos)) {
            return false;
        }
        unsigned value{};
        for (std::size_t cursor = start; cursor < end; ++cursor) {
            const char digit = input[cursor];
            if (digit < '0' || digit > '9') return false;
            value = value * 10U + static_cast<unsigned>(digit - '0');
            if (value > 255U) return false;
        }
        output[index] = std::byte{static_cast<std::uint8_t>(value)};
        start = end + 1U;
    }
    return start == input.size() + 1U;
}

[[nodiscard]] bool private_ipv4(
    const std::array<std::byte, 4U>& address) noexcept {
    const auto octet = [&address](const std::size_t index) {
        return std::to_integer<std::uint8_t>(address[index]);
    };
    return octet(0U) == 10U ||
        (octet(0U) == 172U && octet(1U) >= 16U && octet(1U) <= 31U) ||
        (octet(0U) == 192U && octet(1U) == 168U);
}

[[nodiscard]] bool write_host(
    AuthenticatedControlTcpConnectionV1& connection,
    const std::span<const std::byte> record) noexcept {
    return connection.write_bootstrap_record(
        record, ControlBootstrapDirectionV1::host_to_android,
        kHandshakeIoMilliseconds).succeeded();
}

[[nodiscard]] std::optional<std::vector<std::byte>> read_android(
    AuthenticatedControlTcpConnectionV1& connection) noexcept {
    auto read = connection.read_bootstrap_record(
        ControlBootstrapDirectionV1::android_to_host,
        kHandshakeIoMilliseconds);
    if (!read.succeeded()) return std::nullopt;
    return std::move(read.encoded_record);
}

}  // namespace

HostAuthenticatedControlServiceV1::~HostAuthenticatedControlServiceV1() {
    stop();
}

bool HostAuthenticatedControlServiceV1::start(
    HostDeviceIdentityRuntime& identity_runtime,
    HostAuthenticatedControlPairBindingV1 pair_binding,
    std::string bind_ipv4,
    std::string host_runtime_version,
    GenerationCommit generation_commit,
    SessionCommit session_commit,
    std::string& error) {
    stop();
    error.clear();
    if (bind_ipv4.empty() || host_runtime_version.empty() ||
        !generation_commit || !session_commit) {
        error = "bound control listener configuration is invalid";
        return false;
    }
    const auto started = listener_.start(
        bind_ipv4, kWiredAuthenticatedControlPort);
    if (!started.succeeded()) {
        error = "bound control TCP listener failed with status=" +
            std::to_string(static_cast<unsigned>(started.status)) +
            " native=" + std::to_string(started.native_error);
        return false;
    }
    {
        std::lock_guard lock(state_mutex_);
        identity_runtime_ = &identity_runtime;
        pair_binding_ = std::move(pair_binding);
        host_runtime_version_ = std::move(host_runtime_version);
        generation_commit_ = std::move(generation_commit);
        session_commit_ = std::move(session_commit);
        last_error_.clear();
    }
    stopping_.store(false);
    running_.store(true);
    try {
        worker_ = std::thread([this] { run(); });
    } catch (...) {
        running_.store(false);
        listener_.close();
        std::lock_guard lock(state_mutex_);
        identity_runtime_ = nullptr;
        generation_commit_ = {};
        session_commit_ = {};
        error = "bound control worker could not start";
        return false;
    }
    return true;
}

void HostAuthenticatedControlServiceV1::stop() noexcept {
    stopping_.store(true);
    listener_.close();
    {
        std::lock_guard lock(connection_mutex_);
        if (active_connection_ != nullptr) active_connection_->close();
    }
    if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
    }
    running_.store(false);
    std::lock_guard lock(state_mutex_);
    identity_runtime_ = nullptr;
    generation_commit_ = {};
    session_commit_ = {};
}

bool HostAuthenticatedControlServiceV1::is_running() const noexcept {
    return running_.load();
}

std::string HostAuthenticatedControlServiceV1::last_error() const {
    std::lock_guard lock(state_mutex_);
    return last_error_;
}

void HostAuthenticatedControlServiceV1::run() noexcept {
    while (!stopping_.load()) {
        auto accepted = listener_.accept_bound_pair_candidate(
            kAcceptPollMilliseconds);
        if (!accepted.succeeded()) {
            if (accepted.error.status ==
                    AuthenticatedControlTcpStatusV1::timed_out) {
                continue;
            }
            if (!stopping_.load()) {
                set_error("bound control accept failed with status=" +
                    std::to_string(static_cast<unsigned>(
                        accepted.error.status)));
            }
            break;
        }
        {
            std::lock_guard lock(connection_mutex_);
            active_connection_ = accepted.connection.get();
        }
        (void)process_candidate(accepted.connection);
        if (accepted.connection != nullptr) accepted.connection->close();
        {
            std::lock_guard lock(connection_mutex_);
            active_connection_ = nullptr;
        }
        // A completed handshake transfers this connection to the runtime
        // authorization coordinator, but the bound-pair listener must remain
        // available.  Android package replacement, process death, Wi-Fi
        // roaming, or an ordinary control-channel loss all require a fresh
        // generation-authenticated handshake without restarting the Host.
        // Every successor still proves the exact persisted pair and consumes
        // a server-authorized generation before it can replace the old
        // channel, so continuing to accept cannot reopen the data plane by
        // itself.
        if (stopping_.load()) break;
    }
    listener_.close();
    running_.store(false);
}

bool HostAuthenticatedControlServiceV1::process_candidate(
    std::unique_ptr<AuthenticatedControlTcpConnectionV1>& connection)
    noexcept {
    try {
        HostDeviceIdentityRuntime* identity{};
        HostAuthenticatedControlPairBindingV1 pair;
        std::string runtime_version;
        GenerationCommit generation_commit;
        SessionCommit session_commit;
        {
            std::lock_guard lock(state_mutex_);
            identity = identity_runtime_;
            pair = pair_binding_;
            runtime_version = host_runtime_version_;
            generation_commit = generation_commit_;
            session_commit = session_commit_;
        }
        HostAuthenticatedControlRouteV1 route;
        if (identity == nullptr || connection == nullptr ||
            !generation_commit || !session_commit ||
            !ipv4_bytes(connection->local_ipv4(), route.host_ipv4) ||
            !ipv4_bytes(connection->peer_ipv4(), route.android_ipv4) ||
            !private_ipv4(route.host_ipv4) ||
            !private_ipv4(route.android_ipv4) ||
            route.host_ipv4 == route.android_ipv4) {
            set_error("bound control socket route is invalid");
            return false;
        }
        route.transport_kind =
            connection->local_ipv4() == kWiredHostIpv4 &&
                    connection->peer_ipv4() == kWiredMobileIpv4
                ? PeerHandshakeTransportKind::cat6
                : PeerHandshakeTransportKind::wlan;
        route.video_port = kWiredVideoPort;
        route.control_port = kWiredAuthenticatedControlPort;
        route.host_runtime_version = std::move(runtime_version);

        auto created = HostAuthenticatedControlCoordinatorV1::create(
            *identity, pair, route, now());
        if (!created.succeeded()) {
            set_error(
                "bound control coordinator creation failed: reason=" +
                std::string{host_authenticated_control_error_code_name_v1(
                    created.error.code)});
            return false;
        }
        auto host_hello = created.coordinator->start(now());
        if (!host_hello.succeeded() ||
            !write_host(*connection, host_hello.outbound_record)) {
            set_error("bound control Host hello failed");
            return false;
        }

        auto android_challenge = read_android(*connection);
        if (!android_challenge.has_value()) {
            set_error("bound control Android challenge was not received");
            return false;
        }
        auto host_challenge =
            created.coordinator->accept_android_challenge_request(
                *android_challenge, now());
        if (!host_challenge.succeeded() ||
            !write_host(*connection, host_challenge.outbound_record)) {
            set_error("bound control Host challenge proof failed");
            return false;
        }

        auto server_challenge = read_android(*connection);
        if (!server_challenge.has_value()) {
            set_error("bound control server challenge was not received");
            return false;
        }
        auto host_final = created.coordinator->accept_server_challenge(
            *server_challenge, now());
        if (!host_final.succeeded() ||
            !write_host(*connection, host_final.outbound_record)) {
            set_error("bound control Host final proof failed");
            return false;
        }

        auto generation_credential = read_android(*connection);
        if (!generation_credential.has_value()) {
            set_error("bound control generation credential was not received");
            return false;
        }
        auto host_signature =
            created.coordinator->accept_pair_generation_credential(
                *generation_credential, now());
        if (!host_signature.succeeded() ||
            !write_host(*connection, host_signature.outbound_record)) {
            set_error("bound control Host handshake signature failed");
            return false;
        }

        auto android_confirmation = read_android(*connection);
        if (!android_confirmation.has_value()) {
            set_error("bound control Android confirmation was not received");
            return false;
        }
        auto completed =
            created.coordinator->accept_android_handshake_confirmation(
                *android_confirmation, now());
        if (!completed.succeeded()) {
            set_error("bound control peer confirmation failed");
            return false;
        }

        // Burn the server-authorized generation durably before revealing Host
        // Finished. A crash or delivery loss may waste one generation but can
        // never permit generation reuse or rollback.
        if (!generation_commit(pair, completed.session_generation)) {
            set_error("bound control generation persistence failed");
            return false;
        }
        if (!write_host(*connection, completed.host_finished_record)) {
            set_error("bound control Host Finished delivery failed");
            return false;
        }
        if (!session_commit(
                pair,
                completed.session_generation,
                std::move(completed.confirmed_session),
                std::move(connection))) {
            set_error("bound control session installation failed");
            return false;
        }
        {
            std::lock_guard lock(state_mutex_);
            pair_binding_.generation_high_watermark =
                completed.session_generation;
            last_error_.clear();
        }
        return true;
    } catch (...) {
        set_error("bound control candidate failed closed");
        return false;
    }
}

void HostAuthenticatedControlServiceV1::set_error(
    std::string value) noexcept {
    try {
        std::lock_guard lock(state_mutex_);
        last_error_ = std::move(value);
    } catch (...) {
        // Sanitized diagnostics cannot weaken fail-closed handling.
    }
}

}  // namespace vfdual
