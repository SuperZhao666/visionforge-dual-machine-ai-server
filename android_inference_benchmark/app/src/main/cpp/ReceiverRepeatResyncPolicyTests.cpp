#include "ReceiverRepeatResyncPolicy.hpp"
#include "ReceiverRecoveryPolicy.hpp"

#include <cassert>

namespace {

void android_restart_requires_a_real_seed() {
  vfdual_android::ReceiverRepeatResyncPolicy policy;
  int actionable_frames = 0;
  const auto startup_repeat = policy.admit(true);
  assert(!startup_repeat.submit);
  assert(!startup_repeat.content_updated);
  assert(!startup_repeat.resync_unlock);

  const auto first_real = policy.admit(false);
  assert(first_real.submit);
  assert(first_real.content_updated);
  assert(first_real.resync_unlock);
  if (first_real.content_updated) ++actionable_frames;
  policy.record_submit_result(false, true);
  assert(policy.real_frame_accepted());

  const auto later_repeat = policy.admit(true);
  assert(later_repeat.submit);
  assert(!later_repeat.content_updated);
  assert(!later_repeat.resync_unlock);
  if (later_repeat.content_updated) ++actionable_frames;
  assert(!policy.admit(true).content_updated);
  assert(!policy.admit(true).content_updated);
  assert(actionable_frames == 1);
  const auto later_real = policy.admit(false);
  assert(later_real.submit);
  assert(later_real.content_updated);
  assert(!later_real.resync_unlock);

  policy.reset();
  assert(!policy.real_frame_accepted());
  assert(!policy.admit(true).submit);
}

void rejected_first_vfrg_keeps_repeats_locked() {
  vfdual_android::ReceiverRepeatResyncPolicy policy;
  const auto rejected_vfrg = policy.admit(false);
  assert(rejected_vfrg.submit);
  assert(rejected_vfrg.content_updated);
  assert(rejected_vfrg.resync_unlock);
  policy.record_submit_result(false, false);
  assert(!policy.real_frame_accepted());
  assert(!policy.admit(true).submit);
}

void lost_first_vfrg_requests_idr_and_does_not_unlock_repeat() {
  vfdual_android::ReceiverRepeatResyncPolicy policy;
  vfdual_android::ReceiverRecoveryPolicy recovery;

  // The first VFRG never reaches the receiver. The following completed VFRR
  // is rejected as a resync boundary and immediately drives the existing
  // bounded IDR request policy.
  assert(!policy.admit(true).submit);
  assert(recovery.observe_fragment(1'000U, false, false, true));
  recovery.mark_idr_requested(1'000U);
  assert(!recovery.observe_fragment(1'001U, false, false, true));

  const auto recovery_vfrg = policy.admit(false);
  assert(recovery_vfrg.submit);
  assert(recovery_vfrg.content_updated);
  assert(recovery_vfrg.resync_unlock);
  policy.record_submit_result(false, true);
  assert(policy.real_frame_accepted());
}

void rejected_repeat_closes_session_until_new_vfrg_is_accepted() {
  vfdual_android::ReceiverRepeatResyncPolicy policy;
  policy.record_submit_result(false, true);
  assert(policy.real_frame_accepted());

  const auto repeat = policy.admit(true);
  assert(repeat.submit);
  assert(!repeat.resync_unlock);
  policy.record_submit_result(true, false);
  assert(!policy.real_frame_accepted());
  assert(!policy.admit(true).submit);

  const auto recovery_vfrg = policy.admit(false);
  assert(recovery_vfrg.submit);
  assert(recovery_vfrg.content_updated);
  assert(recovery_vfrg.resync_unlock);
  policy.record_submit_result(false, true);
  assert(policy.real_frame_accepted());
  assert(policy.admit(true).submit);
}

}  // namespace

int main() {
  android_restart_requires_a_real_seed();
  rejected_first_vfrg_keeps_repeats_locked();
  lost_first_vfrg_requests_idr_and_does_not_unlock_repeat();
  rejected_repeat_closes_session_until_new_vfrg_is_accepted();
  return 0;
}
