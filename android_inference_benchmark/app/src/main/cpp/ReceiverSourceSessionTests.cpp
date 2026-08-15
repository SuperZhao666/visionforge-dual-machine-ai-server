#include "ReceiverSourceSession.hpp"

#include <cassert>

int main() {
  using vfdual_android::ReceiverSourceDecision;
  vfdual_android::ReceiverSourceSession session(1U);
  assert(session.observe(2U, 100U, 500U) == ReceiverSourceDecision::reject_foreign);
  assert(session.observe(1U, 100U, 1'000U) == ReceiverSourceDecision::accept);
  assert(session.observe(1U, 100U, 2'000U) == ReceiverSourceDecision::accept);
  assert(session.observe(1U, 200U, 301'999U) == ReceiverSourceDecision::reject_foreign);
  assert(session.observe(1U, 200U, 302'000U) == ReceiverSourceDecision::restart_source_port);
  assert(session.observe(1U, 100U, 400'000U) == ReceiverSourceDecision::reject_foreign);
  assert(session.observe(2U, 300U, 5'000'000U) == ReceiverSourceDecision::reject_foreign);
  assert(session.observe(1U, 300U, 5'000'001U) == ReceiverSourceDecision::restart_source_port);
  session.reset(2U);
  assert(session.observe(1U, 300U, 1U) == ReceiverSourceDecision::reject_foreign);
  assert(session.observe(2U, 300U, 2U) == ReceiverSourceDecision::accept);
  vfdual_android::ReceiverSourceSession stable_source(3U);
  assert(stable_source.observe(3U, 5002U, 1U) == ReceiverSourceDecision::accept);
  assert(stable_source.observe(3U, 5002U, 10'000'000U) == ReceiverSourceDecision::accept);
  vfdual_android::ReceiverSourceSession fail_closed_source(0U);
  assert(fail_closed_source.observe(3U, 5002U, 1U) ==
         ReceiverSourceDecision::reject_foreign);
  return 0;
}
