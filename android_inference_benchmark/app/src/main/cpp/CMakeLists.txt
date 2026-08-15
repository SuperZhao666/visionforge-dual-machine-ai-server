cmake_minimum_required(VERSION 3.22.1)
project(visionforge_qnn_htp)

if(NOT QNN_SDK_ROOT)
    message(FATAL_ERROR "QNN_SDK_ROOT is required. Set qnnSdkRoot in gradle.properties or QNN_SDK_ROOT in the environment.")
endif()
if(NOT ONNXRUNTIME_ANDROID_AAR OR NOT EXISTS "${ONNXRUNTIME_ANDROID_AAR}")
    message(FATAL_ERROR "ONNXRUNTIME_ANDROID_AAR must reference the pinned official Android AAR.")
endif()

set(ONNXRUNTIME_EXTRACT_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/onnxruntime-android")
file(MAKE_DIRECTORY "${ONNXRUNTIME_EXTRACT_DIR}")
file(ARCHIVE_EXTRACT
    INPUT "${ONNXRUNTIME_ANDROID_AAR}"
    DESTINATION "${ONNXRUNTIME_EXTRACT_DIR}")
set(ONNXRUNTIME_LIBRARY
    "${ONNXRUNTIME_EXTRACT_DIR}/jni/${ANDROID_ABI}/libonnxruntime.so")
if(NOT EXISTS "${ONNXRUNTIME_LIBRARY}")
    message(FATAL_ERROR
        "ONNX Runtime AAR does not contain ABI ${ANDROID_ABI}: ${ONNXRUNTIME_LIBRARY}")
endif()
add_library(onnxruntime SHARED IMPORTED)
set_target_properties(onnxruntime PROPERTIES
    IMPORTED_LOCATION "${ONNXRUNTIME_LIBRARY}")

set(VFDUAL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../../dual_machine_runtime")
set(VISIONFORGE_OPTIMIZED_CONFIG
    "$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>")

function(visionforge_harden_native_release target_name)
    target_compile_options(${target_name} PRIVATE
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-O3>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-flto=thin>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-fstack-protector-strong>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-fvisibility=hidden>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-fvisibility-inlines-hidden>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-ffunction-sections>
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:-fdata-sections>
    )
    target_compile_definitions(${target_name} PRIVATE
        $<${VISIONFORGE_OPTIMIZED_CONFIG}:_FORTIFY_SOURCE=2>
    )
endfunction()

add_library(visionforge_dual_protocol STATIC
    "${VFDUAL_ROOT}/shared/src/access_unit_fragmenter.cpp"
    "${VFDUAL_ROOT}/shared/src/access_unit_reassembler.cpp"
    "${VFDUAL_ROOT}/shared/src/image_preprocessor.cpp"
    "${VFDUAL_ROOT}/shared/src/protocol.cpp"
)
target_compile_features(visionforge_dual_protocol PUBLIC cxx_std_20)
target_include_directories(visionforge_dual_protocol PUBLIC "${VFDUAL_ROOT}/shared/include")
visionforge_harden_native_release(visionforge_dual_protocol)

add_library(visionforge_qnn_htp SHARED
    QnnHtpBridge.cpp
    RealtimeInferenceRouter.cpp
    OnnxRuntimeRealtimeExecutor.cpp
    DualMachineReceiver.cpp
    ReceiverRecoveryPolicy.cpp
    ReceiverSourceSession.cpp
    NativeH264Decoder.cpp
    YoloPostprocessor.cpp
    MobileTargetTracker.cpp
    MobileMotionPlanner.cpp
    MobileControlCore.cpp
    MakcuMoveBridge.cpp
)
target_compile_features(visionforge_qnn_htp PRIVATE cxx_std_20)
target_include_directories(visionforge_qnn_htp PRIVATE
    "${QNN_SDK_ROOT}/include/QNN"
    "${ONNXRUNTIME_EXTRACT_DIR}/headers")
visionforge_harden_native_release(visionforge_qnn_htp)
target_link_options(visionforge_qnn_htp PRIVATE
    "-Wl,-z,max-page-size=16384"
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-flto=thin>
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-Wl,--gc-sections>
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-Wl,--exclude-libs,ALL>
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-Wl,-z,relro>
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-Wl,-z,now>
    $<${VISIONFORGE_OPTIMIZED_CONFIG}:-Wl,-z,noexecstack>
)
target_link_libraries(
    visionforge_qnn_htp
    visionforge_dual_protocol
    onnxruntime
    android
    log
    mediandk
    dl)
