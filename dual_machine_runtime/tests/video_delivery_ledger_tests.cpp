#include "vfdual/video_delivery_ledger.hpp"

#include <cassert>

int main() {
  vfdual::VideoDeliveryLedger ledger;
  ledger.request_idr(7U);
  assert(ledger.recovery_required());

  const vfdual::VideoFrameIdentity frame{101U, 33U};
  auto partial = ledger.record({
      frame, 3U, 2U, true, false,
      vfdual::VideoPublicationStage::socket_send}, 7U);
  assert(!partial.publication_complete);
  assert(!partial.idr_request_consumed);
  assert(partial.recovery_still_required);
  assert(!ledger.last_complete_idr().has_value());

  auto repeated = ledger.record({
      frame, 3U, 3U, true, true,
      vfdual::VideoPublicationStage::complete}, 7U);
  assert(repeated.publication_complete);
  assert(!repeated.reference_chain_established);
  assert(!repeated.idr_request_consumed);
  assert(repeated.recovery_still_required);

  const vfdual::VideoFrameIdentity idr{101U, 34U};
  auto complete = ledger.record({
      idr, 3U, 3U, true, false,
      vfdual::VideoPublicationStage::complete}, 7U);
  assert(complete.publication_complete);
  assert(complete.reference_chain_established);
  assert(complete.idr_request_consumed);
  assert(!complete.recovery_still_required);
  assert(ledger.last_complete_idr() == idr);

  ledger.request_idr(8U);
  auto stale_generation = ledger.record({
      {101U, 35U}, 1U, 1U, true, false,
      vfdual::VideoPublicationStage::complete}, 7U);
  assert(!stale_generation.idr_request_consumed);
  assert(stale_generation.recovery_still_required);
  return 0;
}
