#pragma once

namespace vfdual {

enum class HostUiPhase {
    idle,
    discovering,
    streaming,
    mobile_stale,
    recovering,
    failed,
};

[[nodiscard]] constexpr bool host_ui_phase_requires_polling(HostUiPhase phase) noexcept {
    return phase == HostUiPhase::streaming ||
           phase == HostUiPhase::mobile_stale ||
           phase == HostUiPhase::recovering;
}

}  // namespace vfdual
