#include "ReceiverReferenceSyncPolicy.hpp"

#include <cassert>

int main() {
  using vfdual_android::ReceiverReferenceDecision;
  using vfdual_android::ReceiverReferenceSyncPolicy;

  ReceiverReferenceSyncPolicy policy;
  assert(policy.awaiting_idr());
  assert(policy.evaluate(10U, false) ==
      ReceiverReferenceDecision::reject_awaiting_idr);
  assert(policy.evaluate(10U, true) == ReceiverReferenceDecision::admit);

  policy.record_submit(10U, true);
  assert(!policy.awaiting_idr());
  assert(policy.evaluate(11U, false) == ReceiverReferenceDecision::admit);
  assert(policy.evaluate(12U, false) ==
      ReceiverReferenceDecision::reject_sequence_gap);
  assert(policy.evaluate(1'000U, true) == ReceiverReferenceDecision::admit);

  policy.record_submit(11U, false);
  assert(policy.awaiting_idr());
  assert(policy.evaluate(12U, false) ==
      ReceiverReferenceDecision::reject_awaiting_idr);

  policy.record_submit(vfdual::kVideoFrameSequenceMask, true);
  assert(policy.evaluate(0U, false) == ReceiverReferenceDecision::admit);

  policy.require_idr();
  assert(policy.awaiting_idr());
  return 0;
}
