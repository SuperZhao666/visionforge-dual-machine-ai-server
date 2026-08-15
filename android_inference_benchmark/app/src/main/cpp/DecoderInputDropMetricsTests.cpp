#include "DecoderInputDropMetrics.hpp"

#include <cassert>

int main() {
  vfdual_android::DecoderInputDropMetrics metrics;
  metrics.record_offer(vfdual_android::JavaAccessUnitOfferResult::queue_capacity);
  metrics.record_offer(vfdual_android::JavaAccessUnitOfferResult::restarting);
  metrics.record_offer(vfdual_android::JavaAccessUnitOfferResult::reference_recovery);
  metrics.record_offer(vfdual_android::JavaAccessUnitOfferResult::bridge_failure);
  metrics.record_async("input_no_buffer_stall");
  metrics.record_async("input_stale_before_codec");
  metrics.record_async("input_buffer_capacity");
  metrics.record_async("input_codec_exception");
  metrics.record_async("input_state_exception");
  metrics.record_async("input_fatal_flush");
  metrics.record_async("input_restart_flush");
  metrics.record_async("input_recovery_flush");
  metrics.record_async("input_stop_flush");
  assert(metrics.queue_capacity == 1);
  assert(metrics.reference_recovery == 1);
  assert(metrics.bridge_failure == 1);
  assert(metrics.no_input_buffer == 1);
  assert(metrics.stale_before_codec == 1);
  assert(metrics.buffer_capacity == 1);
  assert(metrics.codec_exception == 1);
  assert(metrics.state_exception == 1);
  assert(metrics.fatal_flush == 1);
  assert(metrics.recovery_flush == 1);
  assert(metrics.stop_flush == 1);
  assert(metrics.restart == 2);
  assert(metrics.total() == 13);
  metrics.reset();
  assert(metrics.total() == 0);
  return 0;
}
