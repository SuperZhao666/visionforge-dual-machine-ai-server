#include "ReceiverRecoveryPolicy.hpp"

#include <cassert>

int main() {
  vfdual_android::ReceiverRecoveryPolicy policy;
  assert(!policy.observe_fragment(1'000, false, false, false));
  assert(policy.observe_fragment(2'000, false, true, false));
  policy.mark_idr_requested(2'000);
  assert(!policy.observe_fragment(100'000, false, false, true));
  assert(!policy.observe_fragment(499'999, false, false, true));
  assert(policy.observe_fragment(502'000, false, false, true));
  policy.mark_idr_requested(502'000);
  assert(!policy.observe_fragment(1'501'999, false, false, true));
  assert(policy.observe_fragment(1'502'000, false, false, true));

  policy.reset();
  assert(!policy.observe_fragment(1'000'000, false, false, false));
  assert(!policy.observe_fragment(1'149'999, false, false, false));
  assert(policy.observe_fragment(1'150'000, false, false, false));

  policy.reset();
  assert(!policy.observe_fragment(2'000'000, true, false, false));
  assert(!policy.observe_idle(2'299'999, true));
  assert(policy.observe_idle(2'300'000, true));
  policy.mark_idle_idr_requested(2'300'000);
  assert(!policy.observe_idle(2'400'000, true));
  assert(!policy.observe_idle(2'799'999, true));
  assert(policy.observe_idle(2'800'000, true));
  assert(!policy.observe_idle(3'000'000, false));

  policy.mark_idle_idr_requested(2'800'000);
  assert(policy.observe_idle(3'800'000, true));
  policy.mark_idle_idr_requested(3'800'000);
  assert(policy.observe_idle(5'800'000, true));
  policy.mark_idle_idr_requested(5'800'000);
  assert(!policy.observe_idle(10'800'000, true));

  // Any returning fragment immediately re-arms recovery without manual action.
  assert(policy.observe_fragment(20'000'000, false, false, false));
  policy.mark_idr_requested(20'000'000);
  assert(!policy.observe_fragment(20'001'000, true, false, false));
  assert(!policy.observe_idle(20'300'999, true));
  assert(policy.observe_idle(20'301'000, true));
  return 0;
}
