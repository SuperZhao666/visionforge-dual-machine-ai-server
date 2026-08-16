#include "DecodedFrameMetadataLedger.hpp"

#include <cassert>

int main() {
  vfdual_android::DecodedFrameMetadataLedger ledger(2U);
  ledger.begin_generation(4U);
  assert(!ledger.record({{10U, 1U}, 3U, 100U, true}));
  assert(ledger.record({{10U, 1U}, 4U, 100U, false}));
  assert(!ledger.latest_real().has_value());
  assert(ledger.record({{10U, 2U}, 4U, 120U, true}));
  assert(ledger.visible_after({10U, 2U}, 110U));
  assert(!ledger.visible_after({10U, 2U}, 130U));
  assert(!ledger.record({{10U, 2U}, 4U, 140U, true}));
  ledger.begin_generation(5U);
  assert(ledger.size() == 0U);
  assert(!ledger.visible_after({10U, 2U}, 0U));
  return 0;
}
