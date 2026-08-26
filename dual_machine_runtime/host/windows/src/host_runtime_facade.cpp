#include "vfdual/host/application/host_runtime_facade.hpp"

#include "vfdual/host_device_identity_runtime.hpp"
#include "vfdual/host_cat6_session.hpp"
#include "vfdual/host_authenticated_control_service_v1.hpp"
#include "vfdual/host_direct_link_provisioner.hpp"
#include "vfdual/host_first_pairing_service_v1.hpp"
#include "vfdual/host_pair_binding_store_v1.hpp"
#include "vfdual/host_release_version.hpp"
#include "vfdual/host_runtime_service.hpp"
#include "vfdual/host_runtime_authorization_coordinator.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace vfdual::host::application {
namespace {

[[nodiscard]] std::filesystem::path pair_binding_state_path() noexcept {
    char* local_app_data{};
    std::size_t length{};
    if (_dupenv_s(
            &local_app_data, &length, "LOCALAPPDATA") != 0 ||
        local_app_data == nullptr || length <= 1U) {
        std::free(local_app_data);
        return {};
    }
    const std::filesystem::path root{local_app_data};
    std::free(local_app_data);
    return root / "VisionForge" / "DualMachine" /
        "host-pair-binding-v1.state";
}

}  // namespace

struct HostRuntimeFacade::State final {
    explicit State(vfdual::IsolatedDhcpServer* owner)
        : runtime(owner),
          authorization(runtime),
          device_identity(
              vfdual::HostDeviceIdentityRuntime::open_for_current_build(
                  identity_error)) {
        const auto path = pair_binding_state_path();
        if (path.empty()) {
            pair_store_error = "Host pair-binding path is unavailable.";
            return;
        }
        try {
            pair_store =
                std::make_unique<vfdual::HostPairBindingStoreV1>(path);
        } catch (const std::exception& failure) {
            pair_store_error = failure.what();
        }
    }
    vfdual::HostRuntimeService runtime;
    vfdual::HostRuntimeAuthorizationCoordinator authorization;
    vfdual::HostIdentityError identity_error;
    std::unique_ptr<vfdual::HostDeviceIdentityRuntime> device_identity;
    std::unique_ptr<vfdual::HostPairBindingStoreV1> pair_store;
    std::string pair_store_error;
    vfdual::HostFirstPairingServiceV1 first_pairing;
    vfdual::HostAuthenticatedControlServiceV1 authenticated_control;
};

HostRuntimeFacade::HostRuntimeFacade(vfdual::IsolatedDhcpServer* owner)
    : state_(std::make_unique<State>(owner)) {}
HostRuntimeFacade::~HostRuntimeFacade() = default;

bool HostRuntimeFacade::start(const HostStartRequest& request, std::string& error) {
    if (state_->device_identity == nullptr) {
        error = "Host device identity initialization failed: " +
            vfdual::format_host_identity_error(state_->identity_error);
        return false;
    }
    if (!request.capture_region.has_value()) {
        error = "Host capture region is invalid.";
        return false;
    }
    if (state_->pair_store == nullptr) {
        error = state_->pair_store_error.empty()
            ? "Host pair-binding store is unavailable."
            : state_->pair_store_error;
        return false;
    }
    std::string pair_load_error;
    const auto persisted_pair = state_->pair_store->load(pair_load_error);
    if (!pair_load_error.empty()) {
        error = "Host pair-binding state is invalid: " + pair_load_error;
        return false;
    }
    if (persisted_pair.has_value() &&
        persisted_pair->host_identity_spki_sha256 !=
            state_->device_identity->public_identity()
                .public_key_sha256_hex) {
        error = "Host pair-binding does not match the current device identity.";
        return false;
    }
    // Firewall ownership is part of the activation-only listener boundary.
    // Provision the exact TCP 5006 rules before accepting an untrusted peer;
    // never depend on a broad Windows application exception.
    const auto pairing_firewall =
        vfdual::ensure_host_firewall_rules_automatically();
    if (!vfdual::host_firewall_is_ready(pairing_firewall.status)) {
        error = "Host first-pairing firewall is not ready: " +
            pairing_firewall.detail;
        return false;
    }
    // Fresh pairing is the prerequisite for Host authorization, so its
    // activation-only listener must exist before the authenticated video data
    // plane is allowed to start.  Keeping these phases ordered the other way
    // around creates a deadlock: an unpaired Host cannot pass the data-plane
    // gate, while Android has no listener through which it can establish the
    // first pair.  A completed provisional binding is deliberately not
    // restarted here; it still grants no data-plane authority.
    const auto provisional_pair =
        state_->first_pairing.provisional_pair_binding();
    if (!state_->first_pairing.is_running() &&
        !persisted_pair.has_value() && !provisional_pair.has_value()) {
        const auto confirm_pairing = [](
            const std::string_view decimal_sas,
            const std::string_view android_ipv4) {
            const std::wstring sas(decimal_sas.begin(), decimal_sas.end());
            const std::wstring peer(android_ipv4.begin(), android_ipv4.end());
            const std::wstring message =
                L"请确认手机上显示相同的 6 位配对码：\n\n" + sas +
                L"\n\n手机地址：" + peer +
                L"\n\n只有两端号码完全一致时才点击“是”。";
            return MessageBoxW(
                nullptr, message.c_str(), L"VisionForge 双机首次配对",
                MB_YESNO | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND) ==
                IDYES;
        };
        const auto commit_pair_binding = [this](
            const vfdual::HostAuthenticatedControlPairBindingV1& binding) {
            std::string commit_error;
            const bool committed =
                state_->pair_store->commit_initial_binding(
                    binding, commit_error);
            if (!committed) state_->pair_store_error = commit_error;
            return committed;
        };
        if (!state_->first_pairing.start(
                *state_->device_identity,
                "0.0.0.0",
                std::string(vfdual::kHostReleaseVersionAscii),
                std::string(vfdual::kHostClientProtocolVersion),
                confirm_pairing,
                commit_pair_binding,
                error)) {
            return false;
        }
    }
    if (persisted_pair.has_value() &&
        !state_->authorization.has_authenticated_channel() &&
        !state_->authenticated_control.is_running()) {
        const auto commit_generation = [this](
            const vfdual::HostAuthenticatedControlPairBindingV1& binding,
            const std::uint64_t generation) {
            std::string commit_error;
            const bool committed = state_->pair_store->commit_generation(
                binding, generation, commit_error);
            if (!committed) state_->pair_store_error = commit_error;
            return committed;
        };
        const auto commit_session = [this](
            const vfdual::HostAuthenticatedControlPairBindingV1& binding,
            const std::uint64_t generation,
            std::unique_ptr<vfdual::ConfirmedPeerHandshakeSessionV1> session,
            std::unique_ptr<vfdual::AuthenticatedControlTcpConnectionV1>
                connection) {
            return state_->authorization.install_authenticated_channel(
                *state_->device_identity,
                binding, generation, std::move(session),
                std::move(connection));
        };
        if (!state_->authenticated_control.start(
                *state_->device_identity,
                *persisted_pair,
                "0.0.0.0",
                std::string(vfdual::kHostReleaseVersionAscii),
                commit_generation,
                commit_session,
                error)) {
            return false;
        }
    }
    if (persisted_pair.has_value() ||
        !state_->first_pairing.provisional_pair_binding().has_value()) {
        // Endpoint discovery is process-local on Android.  Advertise the Host
        // again after every app or Host restart, including when a persisted
        // pair already exists, so the phone can reach the bound-control
        // listener and re-authenticate.  Suppress only while a provisional
        // first-pairing exchange is already in progress.  The probe remains
        // untrusted and cannot open the protected runtime by itself.
        (void)vfdual::discover_wireless_lan_mobile_session(
            std::chrono::milliseconds{1'500});
    }
    vfdual::HostStreamSettings settings{};
    settings.local_host = request.local_host;
    settings.phone_host = request.phone_host;
    settings.transport = request.transport;
    settings.adapter_index = request.adapter_index;
    settings.output_index = request.output_index;
    settings.width = request.width;
    settings.height = request.height;
    settings.capture_region = vfdual::DesktopCaptureRegion{
        request.capture_region->left(), request.capture_region->top(),
        request.capture_region->width(), request.capture_region->height()};
    settings.display_id = request.display_id;
    settings.display_left = request.display_left;
    settings.display_top = request.display_top;
    settings.display_right = request.display_right;
    settings.display_bottom = request.display_bottom;
    settings.roi_left = request.roi_left;
    settings.roi_top = request.roi_top;
    settings.roi_right = request.roi_right;
    settings.roi_bottom = request.roi_bottom;
    settings.source_width = request.source_width;
    settings.source_height = request.source_height;
    settings.fallback_reason = request.fallback_reason;
    settings.display_selection_reason = request.display_selection_reason;
    settings.encoder_timing_fps = request.encoder_timing_fps;
    if (!state_->runtime.start(settings, error)) {
        // Preserve the authenticated data-plane gate error, but also surface
        // the activation-only protocol stage from a preceding candidate.  The
        // service stores only fixed sanitized stage text; no record, key,
        // signature, card secret or SAS is exposed here.
        const std::string pairing_error = state_->first_pairing.last_error();
        if (!pairing_error.empty()) {
            error += " first_pairing={" + pairing_error + '}';
        }
        const std::string authenticated_error =
            state_->authenticated_control.last_error();
        if (!authenticated_error.empty()) {
            error += " authenticated_control={" + authenticated_error + '}';
        }
        return false;
    }
    return true;
}

void HostRuntimeFacade::request_stop() noexcept {
    state_->first_pairing.stop();
    state_->authenticated_control.stop();
    state_->authorization.close();
    state_->runtime.request_stop();
}
void HostRuntimeFacade::stop() noexcept {
    state_->first_pairing.stop();
    state_->authenticated_control.stop();
    state_->authorization.close();
    state_->runtime.stop();
}
void HostRuntimeFacade::restore_direct_link_on_clean_shutdown() noexcept {
    state_->runtime.restore_direct_link_on_clean_shutdown();
}
bool HostRuntimeFacade::is_running() const noexcept { return state_->runtime.is_running(); }
std::string HostRuntimeFacade::last_error() const { return state_->runtime.last_error(); }

void HostRuntimeFacade::revoke_data_plane_authorization() noexcept {
    state_->runtime.revoke_data_plane_authorization();
}

HostAuthorizationReadModel HostRuntimeFacade::authorization_read_model() noexcept {
    const auto snapshot = state_->runtime.authorization_snapshot();
    HostAuthorizationReadModel result{};
    result.permits_data_plane = snapshot.permits_data_plane;
    result.sequence = snapshot.sequence;
    result.expires_at_epoch = snapshot.expires_at_epoch;
    if (snapshot.monotonic_clock_rollback) {
        result.status = HostAuthorizationStatus::trusted_time_invalid;
    } else if (!snapshot.peer_confirmed) {
        result.status = HostAuthorizationStatus::peer_unconfirmed;
    } else {
        switch (snapshot.lease_state) {
        case vfdual::UsageLeaseGateState::active:
            result.status = snapshot.permits_data_plane
                ? HostAuthorizationStatus::authorized
                : HostAuthorizationStatus::lease_expired;
            break;
        case vfdual::UsageLeaseGateState::expired:
            result.status = HostAuthorizationStatus::lease_expired;
            break;
        case vfdual::UsageLeaseGateState::stopped:
        case vfdual::UsageLeaseGateState::revoked:
            result.status = HostAuthorizationStatus::lease_revoked;
            break;
        case vfdual::UsageLeaseGateState::empty:
        case vfdual::UsageLeaseGateState::invalid_binding:
        case vfdual::UsageLeaseGateState::trusted_time_rollback:
            result.status = vfdual::UsageLeaseGateState::trusted_time_rollback ==
                    snapshot.lease_state
                ? HostAuthorizationStatus::trusted_time_invalid
                : HostAuthorizationStatus::lease_missing;
            break;
        }
    }
    return result;
}

std::optional<HostRuntimeReadModel> HostRuntimeFacade::snapshot() const {
    const auto source = state_->runtime.last_metrics();
    if (!source.has_value()) return std::nullopt;
    HostRuntimeReadModel result{};
    result.stream_epoch = source->stream_epoch;
    result.source_sequence = source->source_sequence;
    result.frame_sequence = source->frame_id;
    result.capture_us = source->capture_us;
    result.readback_wait_us = source->readback_wait_us;
    result.readback_copy_us = source->readback_copy_us;
    result.bridge_us = source->bridge_us;
    result.upload_us = source->upload_us;
    result.encode_us = source->encode_us;
    result.publish_us = source->publish_us;
    result.capture_to_publish_us = source->capture_to_publish_us;
    result.published_frames = source->published_frames;
    result.encoder_backend = source->encoder_backend;
    result.encoder_vendor = source->encoder_vendor;
    result.encoder_same_adapter = source->encoder_same_adapter;
    result.recovery_count = source->recovery_count;
    result.display_id = source->display_id;
    result.transport = source->transport;
    result.mobile_ipv4 = source->mobile_ipv4;
    result.mobile_reachable = source->mobile_reachable;
    result.mobile_last_success_age_ms = source->mobile_last_success_age_ms;
    result.rtt_ms = source->rtt_ms;
    result.throughput_mbps = source->throughput_mbps;
    return result;
}

}  // namespace vfdual::host::application
