#include "ReceiverIdleBackoff.hpp"

#include <cassert>

int main() {
  using vfdual_android::ReceiverIdleBackoff;

  assert(ReceiverIdleBackoff::receive_timeout_us(0U) == 100'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(999'999U) == 100'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(1'000'000U) == 500'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(4'999'999U) == 500'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(5'000'000U) == 1'000'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(14'999'999U) == 1'000'000U);
  assert(ReceiverIdleBackoff::receive_timeout_us(15'000'000U) == 5'000'000U);
  return 0;
}
