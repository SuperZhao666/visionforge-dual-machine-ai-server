#include "vfdual/video_pipeline_status.hpp"

#include <cassert>

int main() {
  vfdual::VideoPipelineStateMachine machine;
  assert(!machine.status().control_may_open());
  machine.transition(
      vfdual::VideoPipelinePhase::waiting_for_idr,
      vfdual::VideoPipelineBlocker::decoder, 10U);
  assert(machine.status().transition_id == 1U);
  machine.record_complete_frame({77U, 4U});
  machine.record_decoded_frame({77U, 3U});
  machine.transition(
      vfdual::VideoPipelinePhase::streaming,
      vfdual::VideoPipelineBlocker::none, 20U);
  assert(!machine.status().control_may_open());
  machine.record_decoded_frame({77U, 4U});
  assert(machine.status().control_may_open());
  machine.transition(
      vfdual::VideoPipelinePhase::recovering,
      vfdual::VideoPipelineBlocker::transport, 30U);
  assert(!machine.status().control_may_open());
  assert(machine.status().transition_id == 3U);
  return 0;
}
