#include "vfdual/receiver_epoch_session.hpp"

#include <cassert>

int main() {
  vfdual::ReceiverEpochSession session(2U);
  assert(session.observe(11U) == vfdual::ReceiverEpochDecision::candidate);
  assert(!session.commit_candidate(11U, false));
  assert(session.commit_candidate(11U, true));
  assert(session.observe(11U) == vfdual::ReceiverEpochDecision::active);

  assert(session.observe(22U) == vfdual::ReceiverEpochDecision::candidate);
  assert(session.commit_candidate(22U, true));
  assert(session.is_retired(11U));
  assert(session.observe(11U) == vfdual::ReceiverEpochDecision::retired);

  assert(session.observe(33U) == vfdual::ReceiverEpochDecision::candidate);
  session.reject_candidate(33U);
  assert(!session.candidate_epoch().has_value());
  assert(session.is_retired(33U));

  // A bounded retirement ring used to forget epoch 11 after enough rotations.
  // Exercise far more rotations than any historic capacity and prove that the
  // earliest Host session can never reclaim the receiver.
  for (std::uint64_t epoch = 34U; epoch <= 4'096U; ++epoch) {
    assert(session.observe(epoch) == vfdual::ReceiverEpochDecision::candidate);
    assert(session.commit_candidate(epoch, true));
  }
  assert(session.retired_through().has_value());
  assert(*session.retired_through() == 4'095U);
  assert(session.observe(11U) == vfdual::ReceiverEpochDecision::retired);
  assert(session.observe(4'094U) == vfdual::ReceiverEpochDecision::retired);

  // A lower out-of-order candidate cannot replace the newest pending epoch.
  assert(session.observe(5'000U) == vfdual::ReceiverEpochDecision::candidate);
  assert(session.observe(4'999U) == vfdual::ReceiverEpochDecision::retired);
  assert(session.candidate_epoch() == 5'000U);
  assert(!session.commit_candidate(4'999U, true));
  assert(session.commit_candidate(5'000U, true));
  assert(session.observe(0U) == vfdual::ReceiverEpochDecision::invalid);
  return 0;
}
