#include "vfdual/host_first_pairing_service_v1.hpp"

#include "vfdual/wired_link_contract.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>

namespace vfdual {
namespace {

inline constexpr std::uint32_t kAcceptPollMilliseconds = 500U;
inline constexpr std::uint32_t kAttemptIoMilliseconds = 300'000U;

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
        if (end == std::string_view::npos || end <= start || end - start > 3U ||
            (index + 1U != output.size() && separator == std::string_view::npos)) {
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

[[nodiscard]] bool local_scope_ipv4(
    const std::array<std::byte, 4U>& address) noexcept {
    const auto octet = [&address](const std::size_t index) {
        return std::to_integer<std::uint8_t>(address[index]);
    };
    return octet(0U) == 10U ||
        octet(0U) == 127U ||
        (octet(0U) == 169U && octet(1U) == 254U) ||
        (octet(0U) == 172U && octet(1U) >= 16U && octet(1U) <= 31U) ||
        (octet(0U) == 192U && octet(1U) == 168U);
}

[[nodiscard]] bool write_host(
    AuthenticatedControlTcpConnectionV1& connection,
    const std::span<const std::byte> record) noexcept {
    return connection.write_bootstrap_record(
        record, ControlBootstrapDirectionV1::host_to_android,
        kAttemptIoMilliseconds).succeeded();
}

[[nodiscard]] std::optional<std::vector<std::byte>> read_android(
    AuthenticatedControlTcpConnectionV1& connection) noexcept {
    auto read = connection.read_bootstrap_record(
        ControlBootstrapDirectionV1::android_to_host,
        kAttemptIoMilliseconds);
    if (!read.succeeded()) return std::nullopt;
    return std::move(read.encoded_record);
}

}  // namespace

HostFirstPairingServiceV1::~HostFirstPairingServiceV1() { stop(); }

bool HostFirstPairingServiceV1::start(
    HostDeviceIdentityRuntime& identity_runtime,
    std::string bind_ipv4,
    std::string host_runtime_version,
    std::string host_client_version,
    LocalConfirmation local_confirmation,
    PairBindingCommit pair_binding_commit,
    std::string& error) {
    stop();
    error.clear();
    if (bind_ipv4.empty() || host_runtime_version.empty() ||
        host_client_version.empty() || !local_confirmation ||
        !pair_binding_commit) {
        error = "fresh-pair listener configuration is invalid";
        return false;
    }
    const auto started = listener_.start(
        bind_ipv4, kWiredAuthenticatedControlPort);
    if (!started.succeeded()) {
        error = "fresh-pair TCP listener failed with status=" +
            std::to_string(static_cast<unsigned>(started.status)) +
            " native=" + std::to_string(started.native_error);
        return false;
    }
    {
        std::lock_guard lock(state_mutex_);
        identity_runtime_ = &identity_runtime;
        host_runtime_version_ = std::move(host_runtime_version);
        host_client_version_ = std::move(host_client_version);
        local_confirmation_ = std::move(local_confirmation);
        pair_binding_commit_ = std::move(pair_binding_commit);
        last_error_.clear();
        provisional_pair_binding_.reset();
    }
    stopping_.store(false);
    running_.store(true);
    try {
        worker_ = std::thread([this] { run(); });
    } catch (...) {
        running_.store(false);
        listener_.close();
        {
            std::lock_guard lock(state_mutex_);
            identity_runtime_ = nullptr;
            local_confirmation_ = {};
            pair_binding_commit_ = {};
        }
        error = "fresh-pair worker could not start";
        return false;
    }
    return true;
}

void HostFirstPairingServiceV1::stop() noexcept {
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
    local_confirmation_ = {};
    pair_binding_commit_ = {};
}

bool HostFirstPairingServiceV1::is_running() const noexcept {
    return running_.load();
}

std::string HostFirstPairingServiceV1::last_error() const {
    std::lock_guard lock(state_mutex_);
    return last_error_;
}

std::optional<HostAuthenticatedControlPairBindingV1>
HostFirstPairingServiceV1::provisional_pair_binding() const {
    std::lock_guard lock(state_mutex_);
    return provisional_pair_binding_;
}

void HostFirstPairingServiceV1::run() noexcept {
    while (!stopping_.load()) {
        auto accepted = listener_.accept_untrusted_first_pair(
            kAcceptPollMilliseconds);
        if (!accepted.succeeded()) {
            if (accepted.error.status ==
                    AuthenticatedControlTcpStatusV1::timed_out) {
                continue;
            }
            if (!stopping_.load()) {
                set_error("fresh-pair accept failed with status=" +
                    std::to_string(static_cast<unsigned>(
                        accepted.error.status)));
            }
            break;
        }
        {
            std::lock_guard lock(connection_mutex_);
            active_connection_ = accepted.connection.get();
        }
        const bool completed = process_candidate(*accepted.connection);
        accepted.connection->close();
        {
            std::lock_guard lock(connection_mutex_);
            active_connection_ = nullptr;
        }
        if (completed || stopping_.load()) break;
    }
    listener_.close();
    running_.store(false);
}

bool HostFirstPairingServiceV1::process_candidate(
    AuthenticatedControlTcpConnectionV1& connection) noexcept {
    try {
        HostDeviceIdentityRuntime* identity{};
        std::string runtime_version;
        std::string client_version;
        LocalConfirmation confirmation;
        PairBindingCommit binding_commit;
        {
            std::lock_guard lock(state_mutex_);
            identity = identity_runtime_;
            runtime_version = host_runtime_version_;
            client_version = host_client_version_;
            confirmation = local_confirmation_;
            binding_commit = pair_binding_commit_;
        }
        HostFirstPairingRouteV1 route;
        if (identity == nullptr || !confirmation || !binding_commit ||
            !ipv4_bytes(connection.local_ipv4(), route.host_ipv4) ||
            !ipv4_bytes(connection.peer_ipv4(), route.android_ipv4) ||
            !local_scope_ipv4(route.host_ipv4) ||
            !local_scope_ipv4(route.android_ipv4)) {
            set_error("fresh-pair socket route is invalid");
            return false;
        }
        route.video_port = kWiredVideoPort;
        route.control_port = kWiredAuthenticatedControlPort;
        auto created = HostFirstPairingCoordinatorV1::create(
            *identity, route, std::move(runtime_version),
            std::move(client_version),
            FirstPairingConfirmationMethodV1::decimal_sas, now());
        if (!created.succeeded() ||
            !write_host(connection, created.host_offer_record)) {
            set_error("fresh-pair Host offer failed");
            return false;
        }
        const auto android_offer = read_android(connection);
        if (!android_offer.has_value()) {
            set_error("fresh-pair Android offer was not received");
            return false;
        }
        const auto accepted = created.coordinator->accept_android_offer(
            *android_offer, now());
        if (!accepted.succeeded()) {
            set_error("fresh-pair Android offer was rejected");
            return false;
        }
        if (!confirmation(accepted.decimal_sas, connection.peer_ipv4())) {
            created.coordinator->close();
            set_error("fresh-pair was rejected by the Host user");
            return false;
        }
        const auto local = created.coordinator->confirm_local_user(now());
        if (!local.succeeded() || !write_host(connection, local.outbound_record)) {
            set_error("fresh-pair Host confirmation failed");
            return false;
        }
        const auto android_confirmation = read_android(connection);
        if (!android_confirmation.has_value() ||
            created.coordinator->accept_android_user_confirmation(
                *android_confirmation, now()).has_error()) {
            set_error("fresh-pair Android confirmation failed");
            return false;
        }
        const auto activation_request = read_android(connection);
        if (!activation_request.has_value()) {
            set_error("fresh-pair activation request was not received");
            return false;
        }
        const auto activation_signature =
            created.coordinator->accept_activation_proof_request(
                *activation_request, now());
        if (!activation_signature.succeeded() ||
            !write_host(connection, activation_signature.outbound_record)) {
            set_error("fresh-pair Host activation signature failed");
            return false;
        }
        const auto activation_result = read_android(connection);
        if (!activation_result.has_value()) {
            set_error("fresh-pair activation result was not received");
            return false;
        }
        auto completed = created.coordinator->accept_activation_result(
            *activation_result, now());
        if (!completed.succeeded()) {
            set_error("fresh-pair completion failed");
            return false;
        }
        if (!binding_commit(completed.provisional_pair_binding)) {
            set_error("fresh-pair binding persistence failed");
            return false;
        }
        if (!write_host(connection, completed.complete_record)) {
            set_error("fresh-pair completion delivery failed");
            return false;
        }
        {
            std::lock_guard lock(state_mutex_);
            provisional_pair_binding_ =
                std::move(completed.provisional_pair_binding);
            last_error_.clear();
        }
        return true;
    } catch (...) {
        set_error("fresh-pair candidate failed closed");
        return false;
    }
}

void HostFirstPairingServiceV1::set_error(std::string value) noexcept {
    try {
        std::lock_guard lock(state_mutex_);
        last_error_ = std::move(value);
    } catch (...) {
        // Error reporting cannot weaken fail-closed transport handling.
    }
}

}  // namespace vfdual
