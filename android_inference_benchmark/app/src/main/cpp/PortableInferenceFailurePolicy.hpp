#pragma once

#include <string_view>

namespace vfdual_android {

/** Stable preparation failures emitted by the portable ONNX Runtime path. */
enum class PortableInitializationFailureKind {
  model_selection_invalid,
  backend_invalid,
  model_path_missing,
  model_contract_invalid,
  probe_non_finite_output,
  onnxruntime_model_or_configuration_invalid,
  onnxruntime_initialization_failed,
  unexpected_initialization_failed,
};

/** Failures produced by one live frame after a session became ready. */
enum class PortableExecutionFailureKind {
  non_finite_output,
  onnxruntime_run_failed,
};

struct PortableInitializationFailureDecision final {
  std::string_view failure_code;
  bool retryable;
};

struct PortableExecutionFailureDecision final {
  std::string_view failure_code;
  bool retryable;
  bool retire_session;
};

/**
 * Classifies failures relative to an immutable APK/model/backend candidate.
 * A permanent failure is local to that candidate; the Java policy may still
 * try the next candidate (for example NNAPI -> CPU).
 */
[[nodiscard]] constexpr PortableInitializationFailureDecision
classify_portable_initialization_failure(
    PortableInitializationFailureKind kind) noexcept {
  switch (kind) {
    case PortableInitializationFailureKind::model_selection_invalid:
      return {"portable_model_selection_invalid", false};
    case PortableInitializationFailureKind::backend_invalid:
      return {"portable_backend_invalid", false};
    case PortableInitializationFailureKind::model_path_missing:
      return {"portable_model_path_missing", false};
    case PortableInitializationFailureKind::model_contract_invalid:
      return {"portable_model_contract_invalid", false};
    case PortableInitializationFailureKind::probe_non_finite_output:
      return {"portable_probe_non_finite_output", false};
    case PortableInitializationFailureKind::
        onnxruntime_model_or_configuration_invalid:
      return {"onnxruntime_model_or_configuration_invalid", false};
    case PortableInitializationFailureKind::onnxruntime_initialization_failed:
      return {"onnxruntime_initialization_failed", true};
    case PortableInitializationFailureKind::unexpected_initialization_failed:
    default:
      return {"portable_initialization_failed", true};
  }
}

/**
 * A failed live frame closes control through the decoder health contract, but
 * does not poison an already-proven ORT session.  The next incoming frame may
 * therefore recover exactly like the QNN backend.  Sustained failures remain
 * bounded by the existing no-progress formal-stop policy.
 */
[[nodiscard]] constexpr PortableExecutionFailureDecision
classify_portable_execution_failure(
    PortableExecutionFailureKind kind) noexcept {
  switch (kind) {
    case PortableExecutionFailureKind::non_finite_output:
      return {"portable_non_finite_output", true, false};
    case PortableExecutionFailureKind::onnxruntime_run_failed:
    default:
      return {"onnxruntime_execute_failed", true, false};
  }
}

}  // namespace vfdual_android
