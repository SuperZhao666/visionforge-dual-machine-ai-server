param(
    [Parameter(Mandatory = $true)][string]$QnnSdkRoot,
    [Parameter(Mandatory = $true)][string]$ModelCpp,
    [Parameter(Mandatory = $true)][string]$ModelBin,
    [string]$OutputDirectory = "android_inference_benchmark/qnn_workspace/custom_android_model_lib",
    [string]$ModelName
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path $QnnSdkRoot).Path
$cpp = (Resolve-Path $ModelCpp).Path
$bin = (Resolve-Path $ModelBin).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
if (-not $ModelName) { $ModelName = [System.IO.Path]::GetFileNameWithoutExtension($cpp) }
if ($ModelName -notmatch "^[A-Za-z0-9_]+$") { throw "ModelName may contain only letters, numbers, and underscores." }
$ndkRoot = Join-Path (Get-Location) ".android-sdk/ndk/27.1.12297006"
if (-not (Test-Path $ndkRoot)) {
    $ndkRoot = Get-ChildItem (Join-Path (Get-Location) ".android-sdk/ndk") -Directory |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
$cmake = Join-Path (Get-Location) ".android-sdk/cmake/3.22.1/bin/cmake.exe"
if (-not (Test-Path $ndkRoot)) { throw "Android NDK missing: $ndkRoot" }
if (-not (Test-Path $cmake)) { throw "Android CMake missing: $cmake" }
$env:PATH = "$(Split-Path -Parent $cmake);$env:PATH"

$sourceTemplate = Join-Path (Split-Path -Parent $PSCommandPath) "qnn_android_model"
$jni = Join-Path $output "jni"
$binary = Join-Path $output "obj/binary"
$objectDirectory = Join-Path $output "obj/local/arm64-v8a/objs/$ModelName"
New-Item -ItemType Directory -Force -Path $jni, $binary, $objectDirectory | Out-Null
Copy-Item "$sourceTemplate/CMakeLists.txt" "$output/CMakeLists.txt" -Force
foreach ($source in "QnnModel.cpp", "QnnModel.hpp", "QnnModelPal.hpp", "QnnTypeMacros.hpp", "QnnWrapperUtils.cpp", "QnnWrapperUtils.hpp") {
    Copy-Item "$root/share/QNN/converter/jni/$source" "$jni/$source" -Force
}
Copy-Item "$root/share/QNN/converter/jni/linux/QnnModelPal.cpp" "$jni/QnnModelPal.cpp" -Force
Copy-Item $cpp "$jni/$ModelName.cpp" -Force
tar.exe -xf $bin -C $binary
$rawFiles = Get-ChildItem $binary -Filter *.raw
if ($rawFiles.Count -eq 0) { throw "QNN parameter archive did not contain .raw payloads" }
$objcopy = Join-Path $ndkRoot "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objcopy.exe"
Push-Location $output
try {
    foreach ($raw in $rawFiles) {
        $relativeRaw = "obj/binary/$($raw.Name)"
        $relativeObject = "obj/local/arm64-v8a/objs/$ModelName/$($raw.BaseName).o"
        & $objcopy -I binary -O elf64-littleaarch64 -B aarch64 $relativeRaw $relativeObject
        if ($LASTEXITCODE -ne 0) { throw "llvm-objcopy failed for $($raw.Name)" }
    }
} finally {
    Pop-Location
}

$build = Join-Path $output "build"
& $cmake -S $output -B $build -G Ninja "-DCMAKE_TOOLCHAIN_FILE=$ndkRoot/build/cmake/android.toolchain.cmake" -DCMAKE_BUILD_TYPE=Release -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 "-DQNN_SDK_ROOT=$root" "-DMODEL_NAME=$ModelName"
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
& $cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }
$library = Join-Path $build "lib$ModelName.so"
if (-not (Test-Path $library)) { throw "Expected QNN Android model library missing: $library" }
$strip = Join-Path $ndkRoot "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-strip.exe"
& $strip --strip-unneeded $library
if ($LASTEXITCODE -ne 0) { throw "llvm-strip failed for $library" }
Write-Output "QNN_ANDROID_MODEL_LIBRARY_OK path=$library bytes=$((Get-Item $library).Length)"
