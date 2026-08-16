# Android NDK supplies CMake 3.22. The runtime only uses CMake language
# features available there, so keeping this floor lets the Windows host build
# reproducibly on the same workstation without a second CMake installation.
cmake_minimum_required(VERSION 3.22)

if(WIN32)
    # The repository root is intentionally descriptive and therefore deep.
    # Hash long object-path prefixes so Ninja can create every generated
    # directory on Windows without changing the source layout.
    set(CMAKE_OBJECT_PATH_MAX 128 CACHE STRING
        "Maximum object path length for Windows native builds")
endif()

set(VFDUAL_RELEASE_VERSION_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/release_version.txt")
if(NOT EXISTS "${VFDUAL_RELEASE_VERSION_FILE}")
    message(FATAL_ERROR
        "Dual-machine release version is missing: ${VFDUAL_RELEASE_VERSION_FILE}")
endif()
file(READ "${VFDUAL_RELEASE_VERSION_FILE}" VFDUAL_RELEASE_VERSION)
string(STRIP "${VFDUAL_RELEASE_VERSION}" VFDUAL_RELEASE_VERSION)
if(NOT VFDUAL_RELEASE_VERSION MATCHES
        "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "Dual-machine release version must be stable SemVer: ${VFDUAL_RELEASE_VERSION}")
endif()
set(VFDUAL_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(VFDUAL_VERSION_MINOR "${CMAKE_MATCH_2}")
set(VFDUAL_VERSION_PATCH "${CMAKE_MATCH_3}")
set(VFDUAL_WINDOWS_FILE_VERSION "${VFDUAL_RELEASE_VERSION}.0")

project(VisionForgeDualMachine VERSION "${VFDUAL_RELEASE_VERSION}" LANGUAGES CXX)

option(VFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS
    "Generate and privately archive VisionForgeHost symbols without shipping them" ON)
option(VFDUAL_FORMAL_SECURE_DATA_PLANE_ONLY
    "Build only the authenticated formal v2 data plane without plaintext fallback" OFF)
include("${CMAKE_CURRENT_SOURCE_DIR}/formal_security_loader.cmake")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Ninja and Makefile generators are single-config. Reusing one build tree for
# Debug and Release can leave MSVC STL/CRT objects with incompatible ABI flags
# even after CMake regenerates, producing misleading test crashes. Require a
# fresh build directory instead of silently accepting a configuration switch.
if(NOT CMAKE_CONFIGURATION_TYPES AND CMAKE_BUILD_TYPE)
    if(DEFINED VFDUAL_SINGLE_CONFIG_BUILD_TYPE AND
            NOT VFDUAL_SINGLE_CONFIG_BUILD_TYPE STREQUAL CMAKE_BUILD_TYPE)
        message(FATAL_ERROR
            "Single-config build directory was initialized for "
            "${VFDUAL_SINGLE_CONFIG_BUILD_TYPE}, not ${CMAKE_BUILD_TYPE}; "
            "use a fresh build directory")
    endif()
    set(VFDUAL_SINGLE_CONFIG_BUILD_TYPE "${CMAKE_BUILD_TYPE}"
        CACHE INTERNAL "Immutable build type for a single-config tree")
endif()

if(MSVC)
    # The Host is distributed as one EXE. Keep the MSVC/UCRT runtime inside
    # every Windows binary produced by this standalone runtime project.
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    # CMake 3.22 emits a directory-only /Fd argument for some source files
    # whose object directory is hashed. MSVC 19.44 rejects that form with
    # C1083 and an empty generated-file path. Give every target an explicit,
    # short compiler-PDB directory; linker PDB locations remain target-owned.
    set(CMAKE_COMPILE_PDB_OUTPUT_DIRECTORY
        "${CMAKE_CURRENT_BINARY_DIR}/pdb")
    # Build the host runtime as UTF-8 regardless of the Windows system code
    # page. Chinese Windows defaults to CP936, which can misparse UTF-8 source
    # comments/strings and make release builds non-reproducible across systems.
    add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:/utf-8>")
endif()

add_library(vfdual_protocol STATIC
    shared/src/access_unit_fragmenter.cpp
    shared/src/access_unit_reassembler.cpp
    shared/src/authenticated_data_plane_v2.cpp
    shared/src/h264_annex_b_access_units.cpp
    shared/src/image_preprocessor.cpp
    shared/src/mouse_button_protocol.cpp
    shared/src/protocol.cpp
    shared/src/usage_authorization_contract.cpp
    shared/src/usage_lease_gate.cpp
    shared/src/video_transport_contract.cpp
)
target_include_directories(vfdual_protocol PUBLIC shared/include)
target_compile_definitions(vfdual_protocol PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
    target_compile_options(vfdual_protocol PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(vfdual_protocol PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
if(WIN32)
    target_link_libraries(vfdual_protocol PRIVATE bcrypt)
endif()

# Platform-neutral App/Host domain model used as an executable architecture
# specification.  The production adapters above keep their native APIs, while
# this library compiles the protocol, epoch, bounded-reassembly, complete-IDR
# delivery and control-ticket invariants on every CI worker.
find_package(Threads REQUIRED)
add_library(vfdual_e2e_domain_core STATIC
    e2e_core/src/wire_protocol.cpp
    e2e_core/src/video_transport_contract.cpp
    e2e_core/src/reassembly.cpp
    e2e_core/src/recovery.cpp
    e2e_core/src/host_pipeline.cpp
    e2e_core/src/host/domain/decoded_frame_metadata_ledger.cpp
    e2e_core/src/host/domain/stream_identity_generator.cpp
    e2e_core/src/host/domain/virtual_desktop_mapper.cpp
    e2e_core/src/host/domain/video_pipeline_status.cpp
    e2e_core/src/host/application/video_delivery_ledger.cpp
    e2e_core/src/host/application/control_command_coordinator.cpp
    e2e_core/src/host/application/host_streaming_orchestrator.cpp
    e2e_core/src/host/infrastructure/datagram_fragmenter.cpp
    e2e_core/src/host/infrastructure/file_epoch_reservation_store.cpp
    e2e_core/src/host/interfaces/host_runtime_facade.cpp
    e2e_core/src/host/interfaces/host_runtime_composition_root.cpp
)
target_include_directories(vfdual_e2e_domain_core PUBLIC e2e_core/include)
target_link_libraries(vfdual_e2e_domain_core PUBLIC Threads::Threads)
if(MSVC)
    target_compile_options(vfdual_e2e_domain_core PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(vfdual_e2e_domain_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

# Cryptographic foundation only.  Do not link this target into VisionForgeHost
# until pairing identity signatures, persistent generation allocation, the
# authenticated control record, and the three-step raw-lease install are wired.
add_library(vfdual_authenticated_peer_handshake_v1 STATIC
    shared/src/authenticated_peer_handshake_v1.cpp
)
target_include_directories(vfdual_authenticated_peer_handshake_v1 PUBLIC
    shared/include
)
target_compile_definitions(vfdual_authenticated_peer_handshake_v1 PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
if(WIN32)
    target_link_libraries(vfdual_authenticated_peer_handshake_v1 PRIVATE
        bcrypt
    )
endif()

# Pre-generation transcript proposal foundation only.  This target canonicalizes
# the two peers' proposed identity/session fields and can insert only a later
# positive signed-64 server generation into the existing final transcript.  It
# remains deliberately unlinked from VisionForgeHost and every runtime service.
add_library(vfdual_pair_generation_proposal_v1 STATIC
    shared/src/pair_generation_proposal_v1.cpp
)
target_include_directories(vfdual_pair_generation_proposal_v1 PUBLIC
    shared/include
)
target_compile_definitions(vfdual_pair_generation_proposal_v1 PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(vfdual_pair_generation_proposal_v1 PUBLIC
    vfdual_authenticated_peer_handshake_v1
)
if(WIN32)
    target_link_libraries(vfdual_pair_generation_proposal_v1 PRIVATE
        bcrypt
    )
endif()

if(WIN32)
    add_library(vfdual_host_cng_device_identity STATIC
        host/windows/security/src/host_cng_device_identity.cpp
    )
    target_include_directories(vfdual_host_cng_device_identity PUBLIC
        host/windows/security/include
    )
    target_compile_definitions(vfdual_host_cng_device_identity PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    target_link_libraries(vfdual_host_cng_device_identity PUBLIC
        bcrypt
        ncrypt
    )

    # Strict RS256 pair-generation credential verifier foundation only. Its
    # production factory accepts no runtime key source and currently fails
    # closed because formal build-pinned public material is not yet composed.
    # Keep it unlinked from VisionForgeHost until both peer consumers and the
    # authenticated generation coordinator are complete.
    add_library(vfdual_host_pair_generation_credential_verifier_v1 STATIC
        host/windows/security/src/host_pair_generation_credential_verifier_v1.cpp
    )
    target_include_directories(
        vfdual_host_pair_generation_credential_verifier_v1 PUBLIC
        host/windows/security/include
    )
    target_compile_definitions(
        vfdual_host_pair_generation_credential_verifier_v1 PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    target_link_libraries(
        vfdual_host_pair_generation_credential_verifier_v1 PRIVATE
        bcrypt
        crypt32
    )

    # Restricted typed-transcript signing foundation only.  It owns the Host
    # ephemeral key across signature and one-shot derivation, and deliberately
    # remains unlinked from VisionForgeHost until trusted pair records and the
    # complete authenticated control-plane state machine exist.
    add_library(vfdual_host_peer_handshake_transcript_signer_v1 STATIC
        host/windows/security/src/host_peer_handshake_transcript_signer_v1.cpp
    )
    target_include_directories(
        vfdual_host_peer_handshake_transcript_signer_v1 PUBLIC
        host/windows/security/include
    )
    target_compile_definitions(
        vfdual_host_peer_handshake_transcript_signer_v1 PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
    target_link_libraries(
        vfdual_host_peer_handshake_transcript_signer_v1 PUBLIC
        vfdual_host_cng_device_identity
        vfdual_authenticated_peer_handshake_v1
    )

    set(VFDUAL_GENERATED_RESOURCE_DIRECTORY
        "${CMAKE_CURRENT_BINARY_DIR}/generated/host")
    file(MAKE_DIRECTORY "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}")
    file(MAKE_DIRECTORY "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}/vfdual")
    configure_file(
        host/windows/include/vfdual/host_release_version.hpp.in
        "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}/vfdual/host_release_version.hpp"
        @ONLY)
    set(VFDUAL_HOST_MANIFEST_PATH
        "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}/VisionForgeHost.manifest")
    configure_file(
        host/windows/VisionForgeHost.manifest
        "${VFDUAL_HOST_MANIFEST_PATH}"
        @ONLY)
    set(VFDUAL_HOST_ASSET_ROOT
        "${CMAKE_CURRENT_SOURCE_DIR}/host/windows/assets/ui")
    set(VFDUAL_HOST_RESOURCE_FILE
        "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}/streamer_ui.rc")
    configure_file(
        host/windows/streamer_ui.rc
        "${VFDUAL_HOST_RESOURCE_FILE}"
        @ONLY)

    add_executable(VisionForgeHost WIN32
        "${VFDUAL_HOST_RESOURCE_FILE}"
        host/windows/src/streamer_desktop_main.cpp
        host/windows/src/host_crash_diagnostics.cpp
        host/windows/src/streamer_desktop_app.cpp
        host/windows/src/host_window_layout.cpp
        host/windows/src/host_display_catalog.cpp
        host/windows/src/host_cat6_protocol.cpp
        host/windows/src/host_cat6_session.cpp
        host/windows/src/host_cat6_bootstrap.cpp
        host/windows/src/host_cat6_bootstrap_wait.cpp
        host/windows/src/host_direct_link_provisioner.cpp
        host/windows/src/host_firewall_provisioner.cpp
        host/windows/src/isolated_dhcp_protocol.cpp
        host/windows/src/isolated_dhcp_server.cpp
        host/windows/src/host_cat6_monitor.cpp
        host/windows/src/host_runtime_service.cpp
        e2e_core/src/host/infrastructure/file_epoch_reservation_store.cpp
        host/windows/src/host_runtime_facade.cpp
        host/windows/src/host_endpoint_discovery_facade.cpp
        host/windows/src/host_ui_telemetry.cpp
        host/windows/src/host_outbound_rate_tracker.cpp
        host/windows/src/host_application.cpp
        host/windows/src/host_mouse_button_publisher.cpp
        host/windows/src/host_runtime_config.cpp
        host/windows/src/idr_request_listener.cpp
        host/windows/src/streamer_metrics_csv.cpp
        host/windows/src/desktop_video_agent.cpp
        host/windows/src/hybrid_gpu_video_pipeline.cpp
        host/windows/src/d3d11_frame_bridge.cpp
        host/windows/src/dxgi_desktop_capture.cpp
        host/windows/src/media_foundation_h264_encoder.cpp
        host/windows/src/nvenc_h264_encoder.cpp
        host/windows/src/nvenc_runtime_probe.cpp
        host/windows/src/nvenc_session_probe.cpp
        host/windows/src/udp_socket.cpp
        host/windows/src/udp_video_publisher.cpp
    )
    set_target_properties(VisionForgeHost PROPERTIES OUTPUT_NAME VFHost)
    # CMake 3.22's MSVC link wrapper tries to run mt.exe after every
    # WIN32_EXECUTABLE link.  Because the Host supplies its own repository
    # manifest as an RC resource, that wrapper has no generated manifest input
    # and fails with mt.exe C10100A7.  Keep the GUI subsystem explicit while
    # letting the resource compiler embed the authoritative manifest.
    set_target_properties(VisionForgeHost PROPERTIES WIN32_EXECUTABLE FALSE)
    if(MSVC)
        # Keep the latency-sensitive Host native and fully optimized while
        # making the Windows exploit mitigations explicit.  These switches do
        # not schedule, sleep or cap the capture/publish loop.
        target_compile_options(VisionForgeHost PRIVATE
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:/GS>"
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:/sdl>"
            "$<$<AND:$<CONFIG:Release>,$<COMPILE_LANGUAGE:CXX>>:/guard:cf>")
        target_link_options(VisionForgeHost PRIVATE
            "$<$<CONFIG:Release>:/DYNAMICBASE>"
            "$<$<CONFIG:Release>:/HIGHENTROPYVA>"
            "$<$<CONFIG:Release>:/NXCOMPAT>"
            "$<$<CONFIG:Release>:/guard:cf>"
            "$<$<CONFIG:Release>:/CETCOMPAT>"
            "/SUBSYSTEM:WINDOWS")
        include(CheckIPOSupported)
        check_ipo_supported(RESULT vfdual_host_ipo_supported
                            OUTPUT vfdual_host_ipo_error)
        if(vfdual_host_ipo_supported)
            set_property(TARGET VisionForgeHost PROPERTY
                INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        else()
            message(FATAL_ERROR
                "Release Host requires MSVC IPO/LTCG: ${vfdual_host_ipo_error}")
        endif()
    endif()
    target_include_directories(VisionForgeHost PRIVATE
        "${VFDUAL_GENERATED_RESOURCE_DIRECTORY}"
        e2e_core/include
        host/windows
        host/windows/include
        third_party/nv-codec-headers/include)
    target_link_libraries(VisionForgeHost PRIVATE vfdual_protocol vfdual_e2e_domain_core ws2_32 iphlpapi uuid advapi32 bcrypt crypt32 ncrypt tbs d3d11 dxgi
        mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32 user32 gdi32 shell32 dwmapi dbghelp)
    if(MSVC AND VFDUAL_ENABLE_PRIVATE_HOST_SYMBOLS)
        target_compile_options(VisionForgeHost PRIVATE /Zi /FS)
        target_link_options(VisionForgeHost PRIVATE
            /DEBUG:FULL /OPT:REF /OPT:ICF /PDBALTPATH:VisionForgeHost.pdb)
        find_program(VFDUAL_POWERSHELL_EXECUTABLE NAMES powershell REQUIRED)
        add_custom_command(TARGET VisionForgeHost POST_BUILD
            COMMAND "${VFDUAL_POWERSHELL_EXECUTABLE}"
                -NoProfile
                -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/host/windows/archive_host_symbols.ps1"
                -ExePath "$<TARGET_FILE:VisionForgeHost>"
                -PdbPath "$<TARGET_PDB_FILE:VisionForgeHost>"
                -ArchiveDirectory "${CMAKE_CURRENT_BINARY_DIR}/private_symbols"
            COMMENT "Archiving private VisionForgeHost symbols by executable SHA-256"
            VERBATIM)
    endif()

    # Deterministic, repository-owned 144 Hz visual source used by physical
    # capture acceptance. It is not shipped with the production Host binary.
    add_executable(VisionForgeCaptureStimulus WIN32
        host/windows/tests/capture_stimulus_main.cpp
    )
    target_link_libraries(VisionForgeCaptureStimulus PRIVATE vfdual_protocol d3d11 dxgi user32 shell32)

    add_executable(VisionForgeDatasetReplay
        host/windows/src/dataset_h264_replayer.cpp
        host/windows/src/udp_socket.cpp
        host/windows/src/udp_video_publisher.cpp
    )
    target_include_directories(VisionForgeDatasetReplay PRIVATE host/windows/include)
    target_link_libraries(VisionForgeDatasetReplay PRIVATE vfdual_protocol ws2_32)

    add_executable(VisionForgeDatasetEvaluate
        host/windows/src/dataset_detection_evaluator.cpp
    )
    target_link_libraries(VisionForgeDatasetEvaluate PRIVATE vfdual_protocol)
    add_test(NAME vfdual_dataset_evaluator_tests COMMAND VisionForgeDatasetEvaluate
        --labels tests/data/dataset_evaluation/labels
        --trace tests/data/dataset_evaluation/trace.csv
        --max-frames 2
        --require-complete
    )
    set_tests_properties(vfdual_dataset_evaluator_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    add_executable(VisionForgeControlTraceEvaluate
        host/windows/src/mobile_control_trace_evaluator.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.cpp
    )
    target_include_directories(VisionForgeControlTraceEvaluate PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/include)
    set(vfdual_control_trace_contract_script
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_control_trace_evaluator.cmake)
    add_test(NAME vfdual_control_trace_evaluator_tests
        COMMAND ${CMAKE_COMMAND}
            "-DVFDUAL_CONTROL_TRACE_EVALUATOR=$<TARGET_FILE:VisionForgeControlTraceEvaluate>"
            "-DVFDUAL_CONTROL_TRACE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -DVFDUAL_CONTROL_TRACE_CASE=normal
            -P "${vfdual_control_trace_contract_script}")

    add_test(NAME vfdual_control_trace_evaluator_stale_guard_tests
        COMMAND ${CMAKE_COMMAND}
            "-DVFDUAL_CONTROL_TRACE_EVALUATOR=$<TARGET_FILE:VisionForgeControlTraceEvaluate>"
            "-DVFDUAL_CONTROL_TRACE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -DVFDUAL_CONTROL_TRACE_CASE=stale
            -P "${vfdual_control_trace_contract_script}")

    add_test(NAME vfdual_control_trace_evaluator_incomplete_guard_tests
        COMMAND ${CMAKE_COMMAND}
            "-DVFDUAL_CONTROL_TRACE_EVALUATOR=$<TARGET_FILE:VisionForgeControlTraceEvaluate>"
            "-DVFDUAL_CONTROL_TRACE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -DVFDUAL_CONTROL_TRACE_CASE=incomplete
            -P "${vfdual_control_trace_contract_script}")

    add_test(NAME vfdual_control_trace_evaluator_reacquisition_tests
        COMMAND ${CMAKE_COMMAND}
            "-DVFDUAL_CONTROL_TRACE_EVALUATOR=$<TARGET_FILE:VisionForgeControlTraceEvaluate>"
            "-DVFDUAL_CONTROL_TRACE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -DVFDUAL_CONTROL_TRACE_CASE=reacquisition
            -P "${vfdual_control_trace_contract_script}")

    add_test(NAME vfdual_control_trace_evaluator_high_fps_reacquisition_tests
        COMMAND ${CMAKE_COMMAND}
            "-DVFDUAL_CONTROL_TRACE_EVALUATOR=$<TARGET_FILE:VisionForgeControlTraceEvaluate>"
            "-DVFDUAL_CONTROL_TRACE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -DVFDUAL_CONTROL_TRACE_CASE=high_fps_reacquisition
            -P "${vfdual_control_trace_contract_script}")

    add_executable(vfdual_mobile_target_tracker_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileTargetTrackerTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.cpp
    )
    target_include_directories(vfdual_mobile_target_tracker_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_mobile_target_tracker_tests COMMAND vfdual_mobile_target_tracker_tests)

    add_executable(vfdual_mobile_control_core_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileControlCoreTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileControlCore.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileMotionPlanner.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MobileTargetTracker.cpp
    )
    target_include_directories(vfdual_mobile_control_core_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/include)
    add_test(NAME vfdual_mobile_control_core_tests COMMAND vfdual_mobile_control_core_tests)

    add_executable(vfdual_receiver_recovery_policy_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverRecoveryPolicyTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverRecoveryPolicy.cpp
    )
    target_include_directories(vfdual_receiver_recovery_policy_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_receiver_recovery_policy_tests COMMAND vfdual_receiver_recovery_policy_tests)

    add_executable(vfdual_receiver_repeat_resync_policy_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverRepeatResyncPolicyTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverRecoveryPolicy.cpp
    )
    target_include_directories(vfdual_receiver_repeat_resync_policy_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_receiver_repeat_resync_policy_tests
        COMMAND vfdual_receiver_repeat_resync_policy_tests)

    add_executable(vfdual_receiver_reference_sync_policy_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverReferenceSyncPolicyTests.cpp
    )
    target_include_directories(vfdual_receiver_reference_sync_policy_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/include)
    add_test(NAME vfdual_receiver_reference_sync_policy_tests
        COMMAND vfdual_receiver_reference_sync_policy_tests)

    add_executable(vfdual_receiver_idle_backoff_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverIdleBackoffTests.cpp
    )
    target_include_directories(vfdual_receiver_idle_backoff_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_receiver_idle_backoff_tests COMMAND vfdual_receiver_idle_backoff_tests)

    add_executable(vfdual_receiver_source_session_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverSourceSessionTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ReceiverSourceSession.cpp
    )
    target_include_directories(vfdual_receiver_source_session_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_receiver_source_session_tests COMMAND vfdual_receiver_source_session_tests)

    add_executable(vfdual_makcu_output_gate_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MakcuOutputGateTests.cpp
    )
    target_include_directories(vfdual_makcu_output_gate_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_makcu_output_gate_tests COMMAND vfdual_makcu_output_gate_tests)

    add_executable(vfdual_control_blocker_state_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/ControlBlockerStateTests.cpp
    )
    target_include_directories(vfdual_control_blocker_state_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_control_blocker_state_tests
        COMMAND vfdual_control_blocker_state_tests)

    add_executable(vfdual_yolo_postprocessor_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/YoloPostprocessorTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/YoloPostprocessor.cpp
    )
    target_include_directories(vfdual_yolo_postprocessor_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/shared/include)
    add_test(NAME vfdual_yolo_postprocessor_tests COMMAND vfdual_yolo_postprocessor_tests)

    add_executable(vfdual_decoder_input_drop_metrics_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/DecoderInputDropMetricsTests.cpp
    )
    target_include_directories(vfdual_decoder_input_drop_metrics_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    add_test(NAME vfdual_decoder_input_drop_metrics_tests
        COMMAND vfdual_decoder_input_drop_metrics_tests)

endif()

enable_testing()
add_executable(vfdual_protocol_tests tests/protocol_tests.cpp)
target_link_libraries(vfdual_protocol_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_protocol_tests COMMAND vfdual_protocol_tests)

# Non-gating microbenchmark: reports the production zero-copy decoder against
# the former per-datagram owning path. Correctness is mandatory; wall-clock
# ratios are evidence only and are never used as a flaky CI pass threshold.
add_executable(vfdual_video_packet_decode_benchmark
    tests/video_packet_decode_benchmark.cpp)
target_link_libraries(vfdual_video_packet_decode_benchmark PRIVATE vfdual_protocol)
if(MSVC)
    target_compile_options(vfdual_video_packet_decode_benchmark PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(vfdual_video_packet_decode_benchmark PRIVATE
        -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(vfdual_video_transport_contract_tests
    tests/video_transport_contract_tests.cpp)
target_link_libraries(vfdual_video_transport_contract_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_video_transport_contract_tests
    COMMAND vfdual_video_transport_contract_tests)

add_executable(vfdual_video_transport_simulation_tests
    tests/video_transport_simulation_tests.cpp)
target_link_libraries(vfdual_video_transport_simulation_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_video_transport_simulation_tests
    COMMAND vfdual_video_transport_simulation_tests)

add_executable(vfdual_video_delivery_ledger_tests
    tests/video_delivery_ledger_tests.cpp)
target_include_directories(vfdual_video_delivery_ledger_tests PRIVATE shared/include)
add_test(NAME vfdual_video_delivery_ledger_tests
    COMMAND vfdual_video_delivery_ledger_tests)

add_executable(vfdual_video_pipeline_status_tests
    tests/video_pipeline_status_tests.cpp)
target_include_directories(vfdual_video_pipeline_status_tests PRIVATE shared/include)
add_test(NAME vfdual_video_pipeline_status_tests
    COMMAND vfdual_video_pipeline_status_tests)

add_executable(vfdual_receiver_epoch_session_tests
    tests/receiver_epoch_session_tests.cpp)
target_include_directories(vfdual_receiver_epoch_session_tests PRIVATE shared/include)
add_test(NAME vfdual_receiver_epoch_session_tests
    COMMAND vfdual_receiver_epoch_session_tests)

add_executable(vfdual_host_capture_region_tests
    host/windows/tests/host_capture_region_tests.cpp)
target_include_directories(vfdual_host_capture_region_tests PRIVATE
    host/windows/include)
add_test(NAME vfdual_host_capture_region_tests
    COMMAND vfdual_host_capture_region_tests)

add_executable(vfdual_decoded_frame_metadata_ledger_tests
    ../android_inference_benchmark/app/src/main/cpp/DecodedFrameMetadataLedgerTests.cpp)
target_include_directories(vfdual_decoded_frame_metadata_ledger_tests PRIVATE
    ../android_inference_benchmark/app/src/main/cpp
    shared/include)
add_test(NAME vfdual_decoded_frame_metadata_ledger_tests
    COMMAND vfdual_decoded_frame_metadata_ledger_tests)

add_executable(vfdual_usage_authorization_contract_tests
    tests/usage_authorization_contract_tests.cpp)
target_link_libraries(
    vfdual_usage_authorization_contract_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_usage_authorization_contract_tests
    COMMAND vfdual_usage_authorization_contract_tests)

add_executable(vfdual_usage_lease_gate_tests
    tests/usage_lease_gate_tests.cpp)
target_link_libraries(vfdual_usage_lease_gate_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_usage_lease_gate_tests
    COMMAND vfdual_usage_lease_gate_tests)

add_executable(vfdual_authenticated_data_plane_v2_tests
    tests/authenticated_data_plane_v2_tests.cpp)
target_link_libraries(
    vfdual_authenticated_data_plane_v2_tests PRIVATE vfdual_protocol)
add_test(NAME vfdual_authenticated_data_plane_v2_tests
    COMMAND vfdual_authenticated_data_plane_v2_tests)

# Compile the implementation again for this executable so the private test
# access macro is confined to both test translation units.  Never link this
# target to the macro-free production library: doing so would violate ODR and
# could leak deterministic test crypto seams into a production object.
add_executable(vfdual_authenticated_peer_handshake_v1_tests
    tests/authenticated_peer_handshake_v1_tests.cpp
    shared/src/authenticated_peer_handshake_v1.cpp
)
target_include_directories(
    vfdual_authenticated_peer_handshake_v1_tests PRIVATE
    shared/include
)
target_compile_definitions(
    vfdual_authenticated_peer_handshake_v1_tests PRIVATE
    VFDUAL_ENABLE_AUTHENTICATED_PEER_HANDSHAKE_TEST_ACCESS=1
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
if(WIN32)
    target_link_libraries(
        vfdual_authenticated_peer_handshake_v1_tests PRIVATE
        bcrypt
    )
endif()
add_test(
    NAME vfdual_authenticated_peer_handshake_v1_tests
    COMMAND vfdual_authenticated_peer_handshake_v1_tests
)

add_executable(vfdual_pair_generation_proposal_v1_tests
    tests/pair_generation_proposal_v1_tests.cpp
)
target_compile_definitions(
    vfdual_pair_generation_proposal_v1_tests PRIVATE
    VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(
    vfdual_pair_generation_proposal_v1_tests PRIVATE
    vfdual_pair_generation_proposal_v1
)
add_test(
    NAME vfdual_pair_generation_proposal_v1_tests
    COMMAND vfdual_pair_generation_proposal_v1_tests
)

if(WIN32)
    add_executable(vfdual_host_cng_device_identity_tests
        host/windows/security/tests/host_cng_device_identity_tests.cpp
    )
    target_link_libraries(vfdual_host_cng_device_identity_tests PRIVATE
        vfdual_host_cng_device_identity
    )
    add_test(NAME vfdual_host_cng_device_identity_tests
        COMMAND vfdual_host_cng_device_identity_tests)

    # The executable's build target is intentionally shorter than the CTest
    # name so MSVC's per-target /Fd path remains below MAX_PATH even when the
    # repository itself lives under a long directory name.
    add_executable(vfdual_host_peer_signer_v1_tests
        host/windows/security/tests/host_peer_handshake_transcript_signer_v1_tests.cpp
    )
    add_executable(
        vfdual_host_peer_handshake_transcript_signer_v1_tests ALIAS
        vfdual_host_peer_signer_v1_tests)
    target_compile_definitions(
        vfdual_host_peer_signer_v1_tests PRIVATE
        VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_link_libraries(
        vfdual_host_peer_signer_v1_tests PRIVATE
        vfdual_host_peer_handshake_transcript_signer_v1
    )
    add_test(
        NAME vfdual_host_peer_handshake_transcript_signer_v1_tests
        COMMAND vfdual_host_peer_signer_v1_tests)

    # Compile a separate object with the fixture-only keyring API. The macro
    # must never reach the production library or the Host executable. This
    # source is optional in the current checkout, so do not make all other
    # native targets unconfigurable when the fixture is absent.
    set(VFDUAL_HOST_PAIR_CREDENTIAL_TEST_SOURCE
        "${CMAKE_CURRENT_SOURCE_DIR}/host/windows/security/tests/host_pair_generation_credential_verifier_v1_tests.cpp")
    if(EXISTS "${VFDUAL_HOST_PAIR_CREDENTIAL_TEST_SOURCE}")
        add_executable(vfdual_host_pair_credential_v1_tests
            "${VFDUAL_HOST_PAIR_CREDENTIAL_TEST_SOURCE}"
            host/windows/security/src/host_pair_generation_credential_verifier_v1.cpp
        )
        add_executable(
            vfdual_host_pair_generation_credential_verifier_v1_tests ALIAS
            vfdual_host_pair_credential_v1_tests)
        target_include_directories(
            vfdual_host_pair_credential_v1_tests PRIVATE
            host/windows/security/include
        )
        target_compile_definitions(
            vfdual_host_pair_credential_v1_tests PRIVATE
            VFDUAL_ENABLE_HOST_PAIR_CREDENTIAL_TEST_ACCESS=1
            VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
            WIN32_LEAN_AND_MEAN
            NOMINMAX
        )
        target_link_libraries(vfdual_host_pair_credential_v1_tests PRIVATE
            bcrypt
            crypt32
        )
        add_test(
            NAME vfdual_host_pair_generation_credential_verifier_v1_tests
            COMMAND vfdual_host_pair_credential_v1_tests)
    else()
        message(WARNING
            "Skipping vfdual_host_pair_generation_credential_verifier_v1_tests: "
            "missing ${VFDUAL_HOST_PAIR_CREDENTIAL_TEST_SOURCE}")
    endif()

    add_executable(vfdual_dxgi_capture_tests
        host/windows/tests/dxgi_desktop_capture_tests.cpp
        host/windows/src/dxgi_desktop_capture.cpp
        host/windows/src/host_display_catalog.cpp
    )
    target_include_directories(vfdual_dxgi_capture_tests PRIVATE
        host/windows/include shared/include)
    target_link_libraries(vfdual_dxgi_capture_tests PRIVATE d3d11 dxgi user32 dwmapi)
    add_test(NAME vfdual_dxgi_capture_tests COMMAND vfdual_dxgi_capture_tests)
    set_tests_properties(vfdual_dxgi_capture_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(vfdual_dxgi_frame_semantics_tests
        host/windows/tests/dxgi_frame_semantics_tests.cpp
    )
    target_include_directories(vfdual_dxgi_frame_semantics_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_dxgi_frame_semantics_tests COMMAND vfdual_dxgi_frame_semantics_tests)

    add_executable(vfdual_host_encoder_policy_tests
        host/windows/tests/host_encoder_policy_tests.cpp
    )
    target_include_directories(vfdual_host_encoder_policy_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_encoder_policy_tests
        COMMAND vfdual_host_encoder_policy_tests)

    add_executable(vfdual_hybrid_gpu_pipeline_policy_tests
        host/windows/tests/hybrid_gpu_video_pipeline_policy_tests.cpp
    )
    target_include_directories(vfdual_hybrid_gpu_pipeline_policy_tests PRIVATE
        host/windows/include shared/include)
    target_compile_definitions(vfdual_hybrid_gpu_pipeline_policy_tests
        PRIVATE VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME vfdual_hybrid_gpu_pipeline_policy_tests
        COMMAND vfdual_hybrid_gpu_pipeline_policy_tests)

    add_executable(vfdual_nvenc_runtime_probe_tests
        host/windows/tests/nvenc_runtime_probe_tests.cpp
        host/windows/src/nvenc_runtime_probe.cpp
    )
    target_include_directories(vfdual_nvenc_runtime_probe_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_nvenc_runtime_probe_tests COMMAND vfdual_nvenc_runtime_probe_tests)
    set_tests_properties(vfdual_nvenc_runtime_probe_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(vfdual_nvenc_session_probe_tests
        host/windows/tests/nvenc_session_probe_tests.cpp
        host/windows/src/nvenc_session_probe.cpp
        host/windows/src/nvenc_h264_encoder.cpp
    )
    target_include_directories(vfdual_nvenc_session_probe_tests PRIVATE host/windows/include third_party/nv-codec-headers/include)
    target_link_libraries(vfdual_nvenc_session_probe_tests PRIVATE d3d11 dxgi)
    add_test(NAME vfdual_nvenc_session_probe_tests COMMAND vfdual_nvenc_session_probe_tests)
    set_tests_properties(vfdual_nvenc_session_probe_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(vfdual_desktop_video_agent_tests
        host/windows/tests/desktop_video_agent_tests.cpp
        host/windows/src/desktop_video_agent.cpp
        host/windows/src/hybrid_gpu_video_pipeline.cpp
        host/windows/src/d3d11_frame_bridge.cpp
        host/windows/src/dxgi_desktop_capture.cpp
        host/windows/src/host_display_catalog.cpp
        host/windows/src/media_foundation_h264_encoder.cpp
        host/windows/src/nvenc_h264_encoder.cpp
        host/windows/src/udp_socket.cpp
        host/windows/src/udp_video_publisher.cpp
    )
    target_include_directories(vfdual_desktop_video_agent_tests PRIVATE
        host/windows/include shared/include third_party/nv-codec-headers/include)
    target_link_libraries(vfdual_desktop_video_agent_tests PRIVATE vfdual_protocol ws2_32 d3d11 dxgi
        mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32 user32 dwmapi)
    add_test(NAME vfdual_desktop_video_agent_tests COMMAND vfdual_desktop_video_agent_tests)
    set_tests_properties(vfdual_desktop_video_agent_tests PROPERTIES SKIP_RETURN_CODE 77)

    add_executable(vfdual_media_foundation_encoder_tests
        host/windows/tests/media_foundation_h264_encoder_tests.cpp
        host/windows/src/media_foundation_h264_encoder.cpp
    )
    target_include_directories(vfdual_media_foundation_encoder_tests PRIVATE host/windows/include)
    target_link_libraries(vfdual_media_foundation_encoder_tests PRIVATE d3d11 dxgi
        mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32)
    add_test(NAME vfdual_media_foundation_encoder_tests COMMAND vfdual_media_foundation_encoder_tests)

    add_executable(vfdual_isolated_dhcp_protocol_tests
        host/windows/tests/isolated_dhcp_protocol_tests.cpp
        host/windows/src/isolated_dhcp_protocol.cpp
        host/windows/src/isolated_dhcp_server.cpp
    )
    target_include_directories(vfdual_isolated_dhcp_protocol_tests PRIVATE host/windows/include)
    target_compile_definitions(vfdual_isolated_dhcp_protocol_tests
        PRIVATE VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(vfdual_isolated_dhcp_protocol_tests PRIVATE ws2_32 iphlpapi)
    add_test(NAME vfdual_isolated_dhcp_protocol_tests COMMAND vfdual_isolated_dhcp_protocol_tests)

    add_executable(vfdual_host_cat6_protocol_tests
        host/windows/tests/host_cat6_protocol_tests.cpp
        host/windows/src/host_cat6_protocol.cpp
    )
    target_include_directories(vfdual_host_cat6_protocol_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_cat6_protocol_tests COMMAND vfdual_host_cat6_protocol_tests)

    add_executable(vfdual_host_cat6_bootstrap_wait_tests
        host/windows/tests/host_cat6_bootstrap_wait_tests.cpp
        host/windows/src/host_cat6_bootstrap_wait.cpp
    )
    target_include_directories(vfdual_host_cat6_bootstrap_wait_tests PRIVATE host/windows/include)
    target_compile_definitions(vfdual_host_cat6_bootstrap_wait_tests
        PRIVATE VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME vfdual_host_cat6_bootstrap_wait_tests COMMAND vfdual_host_cat6_bootstrap_wait_tests)

    add_executable(vfdual_host_cat6_monitor_policy_tests
        host/windows/tests/host_cat6_monitor_policy_tests.cpp
        host/windows/src/host_cat6_monitor.cpp
        host/windows/src/host_cat6_session.cpp
        host/windows/src/host_cat6_protocol.cpp
    )
    target_include_directories(vfdual_host_cat6_monitor_policy_tests PRIVATE host/windows/include)
    target_compile_definitions(vfdual_host_cat6_monitor_policy_tests
        PRIVATE VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(vfdual_host_cat6_monitor_policy_tests PRIVATE ws2_32 iphlpapi)
    add_test(NAME vfdual_host_cat6_monitor_policy_tests
        COMMAND vfdual_host_cat6_monitor_policy_tests)

    add_executable(vfdual_host_direct_link_policy_tests
        host/windows/tests/host_direct_link_policy_tests.cpp
        host/windows/src/host_direct_link_provisioner.cpp
        host/windows/src/host_firewall_provisioner.cpp
    )
    target_include_directories(vfdual_host_direct_link_policy_tests PRIVATE host/windows/include)
    target_link_libraries(vfdual_host_direct_link_policy_tests PRIVATE ws2_32 iphlpapi uuid advapi32 ole32 oleaut32)
    add_test(NAME vfdual_host_direct_link_policy_tests COMMAND vfdual_host_direct_link_policy_tests)

    add_executable(vfdual_host_firewall_policy_tests
        host/windows/tests/host_firewall_policy_tests.cpp
        host/windows/src/host_firewall_provisioner.cpp
    )
    target_include_directories(vfdual_host_firewall_policy_tests PRIVATE host/windows/include)
    target_link_libraries(vfdual_host_firewall_policy_tests PRIVATE uuid advapi32 ole32 oleaut32)
    add_test(NAME vfdual_host_firewall_policy_tests COMMAND vfdual_host_firewall_policy_tests)

    add_executable(vfdual_host_display_catalog_tests
        host/windows/tests/host_display_catalog_tests.cpp
        host/windows/src/host_display_catalog.cpp
    )
    target_include_directories(vfdual_host_display_catalog_tests PRIVATE
        host/windows/include shared/include)
    target_link_libraries(vfdual_host_display_catalog_tests PRIVATE dxgi user32 dwmapi)
    add_test(NAME vfdual_host_display_catalog_tests COMMAND vfdual_host_display_catalog_tests)

    add_executable(vfdual_host_outbound_rate_tracker_tests
        host/windows/tests/host_outbound_rate_tracker_tests.cpp
        host/windows/src/host_outbound_rate_tracker.cpp
    )
    target_include_directories(vfdual_host_outbound_rate_tracker_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_outbound_rate_tracker_tests COMMAND vfdual_host_outbound_rate_tracker_tests)

    add_executable(vfdual_host_ui_telemetry_tests
        host/windows/tests/host_ui_telemetry_tests.cpp
        host/windows/src/host_ui_telemetry.cpp
        host/windows/src/host_outbound_rate_tracker.cpp
    )
    target_include_directories(vfdual_host_ui_telemetry_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_ui_telemetry_tests COMMAND vfdual_host_ui_telemetry_tests)

    add_executable(vfdual_host_ui_lifecycle_contract_tests
        host/windows/tests/host_ui_lifecycle_contract_tests.cpp
    )
    target_compile_definitions(vfdual_host_ui_lifecycle_contract_tests
        PRIVATE VFDUAL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME vfdual_host_ui_lifecycle_contract_tests
        COMMAND vfdual_host_ui_lifecycle_contract_tests)

    add_executable(vfdual_host_window_layout_tests
        host/windows/tests/host_window_layout_tests.cpp
        host/windows/src/host_window_layout.cpp
    )
    target_include_directories(vfdual_host_window_layout_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_window_layout_tests COMMAND vfdual_host_window_layout_tests)

    add_executable(vfdual_host_recovery_policy_tests
        host/windows/tests/host_recovery_policy_tests.cpp
    )
    target_include_directories(vfdual_host_recovery_policy_tests PRIVATE host/windows/include)
    add_test(NAME vfdual_host_recovery_policy_tests COMMAND vfdual_host_recovery_policy_tests)

    add_executable(vfdual_host_published_frame_accounting_tests
        host/windows/tests/host_published_frame_accounting_tests.cpp
    )
    target_include_directories(
        vfdual_host_published_frame_accounting_tests PRIVATE
        host/windows/include
        shared/include)
    add_test(NAME vfdual_host_published_frame_accounting_tests
        COMMAND vfdual_host_published_frame_accounting_tests)

    add_executable(vfdual_streamer_metrics_csv_tests
        host/windows/tests/streamer_metrics_csv_tests.cpp
        host/windows/src/streamer_metrics_csv.cpp
    )
    target_include_directories(vfdual_streamer_metrics_csv_tests PRIVATE
        host/windows/include shared/include)
    add_test(NAME vfdual_streamer_metrics_csv_tests
        COMMAND vfdual_streamer_metrics_csv_tests)

    add_executable(vfdual_idr_request_listener_tests
        host/windows/tests/idr_request_listener_tests.cpp
        host/windows/src/idr_request_listener.cpp
        host/windows/src/udp_socket.cpp
    )
    target_include_directories(vfdual_idr_request_listener_tests PRIVATE host/windows/include)
    target_link_libraries(vfdual_idr_request_listener_tests PRIVATE ws2_32)
    add_test(NAME vfdual_idr_request_listener_tests COMMAND vfdual_idr_request_listener_tests)

    add_executable(vfdual_udp_video_publisher_contract_tests
        host/windows/tests/udp_video_publisher_contract_tests.cpp
        host/windows/src/udp_video_publisher.cpp
        host/windows/src/udp_socket.cpp
    )
    target_include_directories(vfdual_udp_video_publisher_contract_tests PRIVATE host/windows/include)
    target_link_libraries(vfdual_udp_video_publisher_contract_tests PRIVATE vfdual_protocol ws2_32)
    add_test(NAME vfdual_udp_video_publisher_contract_tests
        COMMAND vfdual_udp_video_publisher_contract_tests)

    add_executable(vfdual_udp_socket_tests
        host/windows/tests/udp_socket_tests.cpp
        host/windows/src/udp_socket.cpp
    )
    target_include_directories(vfdual_udp_socket_tests
        PRIVATE host/windows/include)
    target_link_libraries(vfdual_udp_socket_tests PRIVATE ws2_32)
    add_test(NAME vfdual_udp_socket_tests COMMAND vfdual_udp_socket_tests)
endif()

# The MAKCU ticket/visibility gate is platform-independent. Build it on
# non-Windows CI as well so generation-bound ACK semantics cannot regress just
# because the full Host/Android toolchains are unavailable.
if(NOT WIN32)
    add_executable(vfdual_makcu_output_gate_tests
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp/MakcuOutputGateTests.cpp)
    target_include_directories(vfdual_makcu_output_gate_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../android_inference_benchmark/app/src/main/cpp)
    target_link_libraries(vfdual_makcu_output_gate_tests PRIVATE Threads::Threads)
    add_test(NAME vfdual_makcu_output_gate_tests COMMAND vfdual_makcu_output_gate_tests)
endif()

function(vfdual_add_e2e_domain_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE vfdual_e2e_domain_core)
    target_include_directories(${target} PRIVATE e2e_core/tests)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    add_test(NAME ${target} COMMAND ${target})
endfunction()

vfdual_add_e2e_domain_test(vfdual_e2e_domain_native_tests e2e_core/tests/native_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_decoded_frame_metadata_tests e2e_core/tests/DecodedFrameMetadataLedgerTests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_video_delivery_tests e2e_core/tests/video_delivery_ledger_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_video_pipeline_status_tests e2e_core/tests/video_pipeline_status_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_transport_contract_tests e2e_core/tests/video_transport_contract_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_host_facade_tests e2e_core/tests/host_runtime_facade_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_epoch_store_tests e2e_core/tests/stream_identity_epoch_store_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_virtual_desktop_tests e2e_core/tests/virtual_desktop_mapper_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_control_ticket_tests e2e_core/tests/control_command_coordinator_tests.cpp)
vfdual_add_e2e_domain_test(vfdual_e2e_domain_composition_root_tests e2e_core/tests/host_runtime_composition_root_tests.cpp)

# The native contracts intentionally use the standard assert macro. Release
# configurations define NDEBUG globally, so undefine it for test executables
# only; otherwise CTest can report a false pass without evaluating a check.
get_property(vfdual_directory_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
if(MSVC)
    # CMake 3.22 initializes COMPILE_PDB_OUTPUT_DIRECTORY without a target
    # name, producing /Fd<directory>\ and an invalid empty compiler-PDB path
    # with current MSVC. Assign a unique file name to every target after the
    # complete target graph has been declared.
    foreach(vfdual_target IN LISTS vfdual_directory_targets)
        set_target_properties(${vfdual_target} PROPERTIES
            # CMake appends .pdb to COMPILE_PDB_NAME automatically.
            COMPILE_PDB_NAME "${vfdual_target}"
            COMPILE_PDB_OUTPUT_DIRECTORY
                "${CMAKE_CURRENT_BINARY_DIR}/pdb")
    endforeach()
endif()
set(vfdual_test_build_targets)
foreach(vfdual_target IN LISTS vfdual_directory_targets)
    if(vfdual_target MATCHES "_tests$")
        list(APPEND vfdual_test_build_targets ${vfdual_target})
        if(MSVC)
            target_compile_options(${vfdual_target} PRIVATE /UNDEBUG)
        else()
            target_compile_options(${vfdual_target} PRIVATE -UNDEBUG)
        endif()
    endif()
endforeach()

# Build only CTest dependencies in the disposable test tree. The formal Host
# executable is already built in its own clean tree and must not be rebuilt or
# linked together with test objects from a different dependency database.
foreach(vfdual_evaluator_target
        VisionForgeDatasetEvaluate
        VisionForgeControlTraceEvaluate)
    if(TARGET ${vfdual_evaluator_target})
        list(APPEND vfdual_test_build_targets ${vfdual_evaluator_target})
    endif()
endforeach()
add_custom_target(vfdual_test_build DEPENDS ${vfdual_test_build_targets})
