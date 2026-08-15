if(NOT DEFINED VFDUAL_CONTROL_TRACE_EVALUATOR
        OR NOT DEFINED VFDUAL_CONTROL_TRACE_SOURCE_DIR
        OR NOT DEFINED VFDUAL_CONTROL_TRACE_CASE)
    message(FATAL_ERROR "The control trace test contract is incomplete")
endif()

set(vfdual_trace_file
    "${VFDUAL_CONTROL_TRACE_SOURCE_DIR}/tests/data/dataset_evaluation/trace.csv")
set(vfdual_common_arguments
    --trace "${vfdual_trace_file}"
    --fps 10
    --require-complete)

if(VFDUAL_CONTROL_TRACE_CASE STREQUAL "normal")
    set(vfdual_expected_exit_code 0)
    set(vfdual_arguments
        ${vfdual_common_arguments}
        --max-frames 2
        --gain 0.08
        --deadzone-pixels 1.5
        --maximum-axis-delta 96)
    set(vfdual_expected_output
        "event=control_trace_evaluation_result expected_frames=2 traced_frames=2 coverage=1\\.000000.*physical_output=disabled driver_calls=0.*nonzero_move_frames=1")
elseif(VFDUAL_CONTROL_TRACE_CASE STREQUAL "stale")
    set(vfdual_expected_exit_code 0)
    set(vfdual_arguments
        ${vfdual_common_arguments}
        --max-frames 2
        --processing-age-us 200000)
    set(vfdual_expected_output
        "event=control_trace_evaluation_result expected_frames=2 traced_frames=2 coverage=1\\.000000.*freshness_rejects=2.*nonzero_move_frames=0")
elseif(VFDUAL_CONTROL_TRACE_CASE STREQUAL "incomplete")
    set(vfdual_expected_exit_code 5)
    set(vfdual_arguments
        ${vfdual_common_arguments}
        --max-frames 3)
    set(vfdual_expected_output
        "event=control_trace_evaluation_result expected_frames=3 traced_frames=2 coverage=0\\.666667")
    set(vfdual_expected_failure
        "event=control_trace_evaluation_failed reason=incomplete_trace_coverage")
elseif(VFDUAL_CONTROL_TRACE_CASE STREQUAL "reacquisition")
    set(vfdual_trace_file
        "${VFDUAL_CONTROL_TRACE_SOURCE_DIR}/tests/data/control_reacquisition/ow2_far_reacquisition.csv")
    set(vfdual_expected_exit_code 0)
    set(vfdual_arguments
        --trace "${vfdual_trace_file}"
        --model overwatch2-head
        --fps 100
        --switch-confirmation-ms 45
        --max-frames 16
        --require-complete)
    set(vfdual_expected_output
        "event=control_trace_evaluation_result expected_frames=16 traced_frames=16 coverage=1\\.000000 model=overwatch2-head.*switch_confirmation_ms=45.*physical_output=disabled driver_calls=0.*switched_frames=1.*reacquisition_pending_frames=6 reacquisition_confirmations=1")
elseif(VFDUAL_CONTROL_TRACE_CASE STREQUAL "high_fps_reacquisition")
    set(vfdual_trace_file
        "${VFDUAL_CONTROL_TRACE_SOURCE_DIR}/tests/data/control_reacquisition/ow2_far_reacquisition_1000fps.csv")
    set(vfdual_expected_exit_code 0)
    set(vfdual_arguments
        --trace "${vfdual_trace_file}"
        --model overwatch2-head
        --fps 1000
        --switch-confirmation-ms 45
        --max-frames 120
        --require-complete)
    set(vfdual_expected_output
        "event=control_trace_evaluation_result expected_frames=120 traced_frames=120 coverage=1\\.000000 model=overwatch2-head fps=1000.*switch_confirmation_ms=45.*physical_output=disabled driver_calls=0.*switched_frames=1.*reacquisition_pending_frames=45 reacquisition_confirmations=1.*saturated_frames=0")
else()
    message(FATAL_ERROR
        "Unknown control trace test case: ${VFDUAL_CONTROL_TRACE_CASE}")
endif()

execute_process(
    COMMAND "${VFDUAL_CONTROL_TRACE_EVALUATOR}" ${vfdual_arguments}
    RESULT_VARIABLE vfdual_result
    OUTPUT_VARIABLE vfdual_stdout
    ERROR_VARIABLE vfdual_stderr)
set(vfdual_output "${vfdual_stdout}\n${vfdual_stderr}")

if(NOT "${vfdual_result}" STREQUAL "${vfdual_expected_exit_code}")
    message(FATAL_ERROR
        "${VFDUAL_CONTROL_TRACE_CASE} returned ${vfdual_result}, expected ${vfdual_expected_exit_code}\n${vfdual_output}")
endif()
if(NOT vfdual_output MATCHES "${vfdual_expected_output}")
    message(FATAL_ERROR
        "${VFDUAL_CONTROL_TRACE_CASE} did not report its expected result\n${vfdual_output}")
endif()
if(DEFINED vfdual_expected_failure)
    if(NOT vfdual_output MATCHES "${vfdual_expected_failure}")
        message(FATAL_ERROR
            "${VFDUAL_CONTROL_TRACE_CASE} did not report its expected failure reason\n${vfdual_output}")
    endif()
elseif(vfdual_output MATCHES "event=control_trace_evaluation_failed")
    message(FATAL_ERROR
        "${VFDUAL_CONTROL_TRACE_CASE} reported an unexpected failure\n${vfdual_output}")
endif()

message(STATUS
    "control trace case=${VFDUAL_CONTROL_TRACE_CASE} exit=${vfdual_result} contract=verified")
