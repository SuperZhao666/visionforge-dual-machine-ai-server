#include "InferenceGenerationPolicy.hpp"

#include <cassert>
#include <cstdint>

int main() {
  using vfdual_android::inference_result_can_commit;

  assert(inference_result_can_commit(7U, 7U, false, false));
  assert(!inference_result_can_commit(6U, 7U, false, false));
  assert(!inference_result_can_commit(8U, 7U, false, false));
  assert(!inference_result_can_commit(7U, 7U, true, false));
  assert(!inference_result_can_commit(7U, 7U, false, true));
  assert(!inference_result_can_commit(7U, 7U, true, true));
  assert(!inference_result_can_commit(0U, 0U, false, false));

  return 0;
}
