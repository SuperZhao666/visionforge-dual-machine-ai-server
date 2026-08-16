#include "ControlBlockerState.hpp"

#include <cassert>
#include <string_view>

int main() {
  vfdual_android::ControlBlockerState state;
  auto snapshot = state.snapshot();
  assert(snapshot.reason ==
         vfdual_android::ControlBlockerReason::initializing);
  assert(snapshot.transition_id == 0U);

  state.update(vfdual_android::ControlBlockerReason::runnable, 100U);
  snapshot = state.snapshot();
  assert(snapshot.reason == vfdual_android::ControlBlockerReason::runnable);
  assert(snapshot.since_us == 100U);
  assert(snapshot.transition_id == 1U);

  state.update(vfdual_android::ControlBlockerReason::runnable, 200U);
  auto unchanged = state.snapshot();
  assert(unchanged.since_us == 100U);
  assert(unchanged.transition_id == 1U);

  state.update(
      vfdual_android::ControlBlockerReason::post_ack_visibility, 300U);
  snapshot = state.snapshot();
  assert(snapshot.since_us == 300U);
  assert(snapshot.transition_id == 2U);
  assert(std::string_view(vfdual_android::control_blocker_reason_name(
             snapshot.reason)) == "post_ack_visibility");
  return 0;
}
