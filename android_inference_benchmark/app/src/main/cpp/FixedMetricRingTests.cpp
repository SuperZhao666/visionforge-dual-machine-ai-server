#include "FixedMetricRing.hpp"

#include <cassert>

int main() {
  vfdual_android::FixedMetricRing<int, 3U> ring;
  assert(ring.empty());
  assert(!ring.push(1));
  assert(!ring.push(2));
  assert(!ring.push(3));
  assert(ring.size() == 3U);
  assert(ring.oldest_at(0U) == 1);
  assert(ring.oldest_at(2U) == 3);

  assert(ring.push(4));
  assert(ring.size() == 3U);
  assert(ring.oldest_at(0U) == 2);
  assert(ring.oldest_at(1U) == 3);
  assert(ring.oldest_at(2U) == 4);

  ring.clear();
  assert(ring.empty());
  assert(!ring.push(5));
  assert(ring.size() == 1U && ring.oldest_at(0U) == 5);
  return 0;
}
