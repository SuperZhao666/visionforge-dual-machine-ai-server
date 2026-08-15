#include "PortableInferenceFailurePolicy.hpp"

#include <array>
#include <cstdlib>
#include <string_view>

namespace {

using vfdual_android::PortableInitializationFailureKind;
using vfdual_android::PortableExecutionFailureKind;

void require(bool condition) {
  if (!condition) std::abort();
}

void verify_immutable_failures_are_permanent() {
  constexpr std::array kinds{
      PortableInitializationFailureKind::model_selection_invalid,
      PortableInitializationFailureKind::backend_invalid,
      PortableInitializationFailureKind::model_path_missing,
      PortableInitializationFailureKind::model_contract_invalid,
      PortableInitializationFailureKind::probe_non_finite_output,
      PortableInitializationFailureKind::
          onnxruntime_model_or_configuration_invalid};
  for (const auto kind : kinds) {
    const auto decision =
        vfdual_android::classify_portable_initialization_failure(kind);
    require(!decision.retryable);
    require(!decision.failure_code.empty());
  }
}

void verify_runtime_and_unknown_failures_remain_retryable() {
  const auto runtime = vfdual_android::classify_portable_initialization_failure(
      PortableInitializationFailureKind::onnxruntime_initialization_failed);
  require(runtime.retryable);
  require(runtime.failure_code == "onnxruntime_initialization_failed");

  const auto unexpected =
      vfdual_android::classify_portable_initialization_failure(
          PortableInitializationFailureKind::unexpected_initialization_failed);
  require(unexpected.retryable);
  require(unexpected.failure_code == "portable_initialization_failed");
}

void verify_stable_failure_codes() {
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::model_selection_invalid)
              .failure_code == "portable_model_selection_invalid");
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::backend_invalid)
              .failure_code == "portable_backend_invalid");
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::model_path_missing)
              .failure_code == "portable_model_path_missing");
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::model_contract_invalid)
              .failure_code == "portable_model_contract_invalid");
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::probe_non_finite_output)
              .failure_code == "portable_probe_non_finite_output");
  require(vfdual_android::classify_portable_initialization_failure(
              PortableInitializationFailureKind::
                  onnxruntime_model_or_configuration_invalid)
              .failure_code
          == "onnxruntime_model_or_configuration_invalid");
}

void verify_live_frame_failures_do_not_poison_proven_session() {
  constexpr std::array kinds{
      PortableExecutionFailureKind::non_finite_output,
      PortableExecutionFailureKind::onnxruntime_run_failed};
  for (const auto kind : kinds) {
    const auto decision =
        vfdual_android::classify_portable_execution_failure(kind);
    require(decision.retryable);
    require(!decision.retire_session);
    require(!decision.failure_code.empty());
  }
}

void verify_stable_execution_failure_codes() {
  require(vfdual_android::classify_portable_execution_failure(
              PortableExecutionFailureKind::non_finite_output)
              .failure_code == "portable_non_finite_output");
  require(vfdual_android::classify_portable_execution_failure(
              PortableExecutionFailureKind::onnxruntime_run_failed)
              .failure_code == "onnxruntime_execute_failed");
}

}  // namespace

int main() {
  verify_immutable_failures_are_permanent();
  verify_runtime_and_unknown_failures_remain_retryable();
  verify_stable_failure_codes();
  verify_live_frame_failures_do_not_poison_proven_session();
  verify_stable_execution_failure_codes();
  return EXIT_SUCCESS;
}
