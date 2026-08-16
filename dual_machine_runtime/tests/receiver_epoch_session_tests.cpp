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
  assert(session.observe(0U) == vfdual::ReceiverEpochDecision::invalid);
  return 0;
}
