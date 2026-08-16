#!/usr/bin/env bash
# VisionForge App/Host portable acceptance gate.
#
# This gate intentionally uses only tools available on a normal CI worker:
# Python, CMake/C++20 and JDK 17. Android SDK/NDK, Windows DXGI/NVENC,
# Qualcomm QNN/HTP and physical MAKCU/Bluetooth checks remain separate target-
# environment lanes and must never be represented as passing here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${VFDUAL_PORTABLE_BUILD_ROOT:-${TMPDIR:-/tmp}/visionforge-app-host-portable}"
NATIVE_BUILD="${BUILD_ROOT}/native-release"
JAVA_FULL="${BUILD_ROOT}/java-full"
JAVA_STRICT="${BUILD_ROOT}/java-strict"

rm -rf "${BUILD_ROOT}"
mkdir -p "${NATIVE_BUILD}" "${JAVA_FULL}" "${JAVA_STRICT}"
cd "${ROOT}"

python3 tools/check_app_host_architecture.py --root "${ROOT}"
python3 tools/check_video_transport_contract.py --root "${ROOT}"
python3 tools/check_realtime_pipeline_contract.py --root "${ROOT}"
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v

cmake -S dual_machine_runtime -B "${NATIVE_BUILD}" -DCMAKE_BUILD_TYPE=Release
cmake --build "${NATIVE_BUILD}" --parallel
ctest --test-dir "${NATIVE_BUILD}" --output-on-failure

javac --release 17 -d "${JAVA_FULL}" \
  @tools/manifests/app_host_java_full_sources.txt
java -Dvisionforge.android.project.dir="${ROOT}/android_inference_benchmark/app" \
  -cp "${JAVA_FULL}" \
  com.visionforge.inferencebenchmark.MobileRuntimeSnapshotSelfTest
java -cp "${JAVA_FULL}" com.visionforge.mobile.core.MobileCoreSelfTest
java -cp "${JAVA_FULL}" com.visionforge.mobile.application.MobileArchitectureSelfTest

javac --release 17 -Xlint:all -Werror -d "${JAVA_STRICT}" \
  @tools/manifests/app_host_java_strict_sources.txt
java -cp "${JAVA_STRICT}" com.visionforge.mobile.core.MobileCoreSelfTest
java -cp "${JAVA_STRICT}" com.visionforge.mobile.application.MobileArchitectureSelfTest
java -cp "${JAVA_STRICT}" \
  com.visionforge.inferencebenchmark.video.VideoWireProtocolSelfTest
java -cp "${JAVA_STRICT}" \
  com.visionforge.inferencebenchmark.video.VideoPreflightReassemblyWindowSelfTest
java -cp "${JAVA_STRICT}" \
  com.visionforge.inferencebenchmark.video.DecoderRestartCoordinatorSelfTest

printf '%s\n' 'VISIONFORGE_APP_HOST_PORTABLE_GATE=PASS'
