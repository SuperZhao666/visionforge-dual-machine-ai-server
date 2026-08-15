cmake_minimum_required(VERSION 3.22.1)
project(visionforge_qnn_model LANGUAGES C CXX)

if(NOT DEFINED QNN_SDK_ROOT)
  message(FATAL_ERROR "QNN_SDK_ROOT is required")
endif()

set(MODEL_NAME "custom_qnn_model" CACHE STRING "Generated QNN model library name")
file(GLOB MODEL_BINARY_OBJECTS "obj/local/arm64-v8a/objs/${MODEL_NAME}/*.o")
if(NOT MODEL_BINARY_OBJECTS)
  message(FATAL_ERROR "No QNN parameter objects were generated")
endif()

set(MODEL_SOURCES
    jni/QnnModel.cpp
    jni/QnnModelPal.cpp
    jni/QnnWrapperUtils.cpp
    jni/${MODEL_NAME}.cpp
    ${MODEL_BINARY_OBJECTS})

add_library(${MODEL_NAME} SHARED ${MODEL_SOURCES})
set_source_files_properties(${MODEL_BINARY_OBJECTS} PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
target_include_directories(${MODEL_NAME} PRIVATE jni "${QNN_SDK_ROOT}/include/QNN")
target_compile_features(${MODEL_NAME} PRIVATE cxx_std_11)
target_compile_options(
    ${MODEL_NAME}
    PRIVATE
    -O3
    -fvisibility=hidden
    -Wno-c99-designator
    -Wno-write-strings
    "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
    "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=.")
target_compile_definitions(${MODEL_NAME} PRIVATE QNN_API=__attribute__\(\(visibility\("default"\)\)\))
target_link_libraries(${MODEL_NAME} PRIVATE log dl m)
target_link_options(
    ${MODEL_NAME}
    PRIVATE
    -Wl,--allow-shlib-undefined
    -Wl,--build-id=none
    -Wl,-z,max-page-size=16384)
