#include "vfdual/host/application/host_runtime_facade.hpp"

#include "vfdual/host_device_identity_runtime.hpp"
#include "vfdual/host_runtime_service.hpp"

#include <utility>

namespace vfdual::host::application {

struct HostRuntimeFacade::State final {
    explicit State(vfdual::IsolatedDhcpServer* owner)
        : runtime(owner),
          device_identity(
              vfdual::HostDeviceIdentityRuntime::open_for_current_build(
                  identity_error)) {}
    vfdual::HostRuntimeService runtime;
    vfdual::HostIdentityError identity_error;
    std::unique_ptr<vfdual::HostDeviceIdentityRuntime> device_identity;
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
    return state_->runtime.start(settings, error);
}

void HostRuntimeFacade::request_stop() noexcept { state_->runtime.request_stop(); }
void HostRuntimeFacade::stop() noexcept { state_->runtime.stop(); }
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
