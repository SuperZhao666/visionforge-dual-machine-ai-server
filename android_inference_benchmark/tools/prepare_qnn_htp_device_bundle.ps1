param(
    [Parameter(Mandatory = $true)][string]$QnnSdkRoot,
    [string]$ModelLibrary = "android_inference_benchmark/qnn_workspace/valorant_416_v11s_no_flash/w8a16_android_model_lib/build/libvalorant_416_v11s_no_flash_w8a16.so",
    [Parameter(Mandatory = $true)][string]$RuntimeInput,
    [string]$OutputDirectory = "android_inference_benchmark/qnn_workspace/device_bundle",
    [string]$ModelName = "valorant_416_v11s_no_flash_w8a16",
    [int]$ModelSize = 416,
    [ValidateSet(1, 2)][int]$InputElementBytes = 2,
    [int]$WarmupRuns = 30,
    [int]$MeasuredRuns = 300
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
$socArchitectureCatalogPath = Join-Path $projectRoot "qnn_htp_soc_architectures.json"
if (-not (Test-Path -LiteralPath $socArchitectureCatalogPath -PathType Leaf)) {
    throw "QNN HTP SoC architecture catalog is missing: $socArchitectureCatalogPath"
}
$socArchitectureCatalog = Get-Content -LiteralPath $socArchitectureCatalogPath `
        -Raw -Encoding UTF8 | ConvertFrom-Json
if ($socArchitectureCatalog.schema -ne "visionforge-qnn-htp-soc-architectures-v1") {
    throw "QNN HTP SoC architecture catalog schema is invalid."
}
$socArchitectures = [ordered]@{}
foreach ($property in @($socArchitectureCatalog.soc_architectures.PSObject.Properties)) {
    $architecture = "$($property.Value)".ToLowerInvariant()
    if ($property.Name -notmatch '^(SM|QCM)\d{4}$' -or
            $architecture -notmatch '^v\d{2,3}$' -or
            $socArchitectures.Contains($property.Name)) {
        throw "QNN HTP SoC architecture catalog contains an invalid entry."
    }
    $socArchitectures[$property.Name] = $architecture
}
if ($socArchitectures.Count -eq 0) {
    throw "QNN HTP SoC architecture catalog is empty."
}
$sdk = (Resolve-Path $QnnSdkRoot).Path
$model = (Resolve-Path $ModelLibrary).Path
$runtimeInput = (Resolve-Path $RuntimeInput).Path
$sdkMetadataPath = Join-Path $sdk "sdk.yaml"
if (-not (Test-Path -LiteralPath $sdkMetadataPath -PathType Leaf)) {
    throw "QNN SDK metadata is missing: $sdkMetadataPath"
}
$sdkVersions = @()
$sdkBuildIds = @()
foreach ($line in Get-Content -LiteralPath $sdkMetadataPath -Encoding UTF8) {
    if ($line -match '^version\s*:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$') {
        $sdkVersions += $Matches[1]
    }
    if ($line -match '^build_id\s*:\s*([0-9]{12}_[0-9]+)\s*$') {
        $sdkBuildIds += $Matches[1]
    }
}
if ($sdkVersions.Count -ne 1 -or $sdkBuildIds.Count -ne 1) {
    throw "QNN SDK metadata must contain one strict version and build_id: $sdkMetadataPath"
}
$qnnSdkBuildIdentity = "$($sdkVersions[0]).$($sdkBuildIds[0])"
$qnnSdkIdentity = "$($sdkVersions[0]).$($sdkBuildIds[0].Substring(0, 6))"
$modelBytes = [System.IO.File]::ReadAllBytes($model)
$modelText = [System.Text.Encoding]::GetEncoding(28591).GetString($modelBytes)
$modelSdkIdentities = @(
    [regex]::Matches(
        $modelText,
        'qaisw-v([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]{12}_[0-9]+)') |
        ForEach-Object { "$($_.Groups[1].Value).$($_.Groups[2].Value)" } |
        Sort-Object -Unique
)
if ($modelSdkIdentities.Count -ne 1) {
    throw "QNN model library must embed exactly one SDK identity: $model"
}
if ($modelSdkIdentities[0] -ne $qnnSdkBuildIdentity) {
    throw (
        "QNN SDK/model toolchain identity mismatch: " +
        "sdk=$qnnSdkBuildIdentity model=$($modelSdkIdentities[0])")
}
$qnnTypesHeader = Join-Path $sdk "include/QNN/QnnTypes.h"
if (-not (Test-Path -LiteralPath $qnnTypesHeader -PathType Leaf)) {
    throw "QNN SDK SoC mapping header is missing: $qnnTypesHeader"
}
$socModels = [ordered]@{}
foreach ($line in Get-Content -LiteralPath $qnnTypesHeader -Encoding UTF8) {
    if ($line -match "QNN_SOC_MODEL_(SM\d+)\s*=\s*(\d+)") {
        $socModels[$Matches[1]] = [int]$Matches[2]
    }
}
if ($socModels.Count -eq 0) {
    throw "QNN SDK SoC mapping header contains no Snapdragon models: $qnnTypesHeader"
}
$bundle = [System.IO.Path]::GetFullPath($OutputDirectory)
if ($WarmupRuns -le 0 -or $MeasuredRuns -le 0) { throw "WarmupRuns and MeasuredRuns must be positive" }
if ($ModelName -notmatch "^[A-Za-z0-9_]+$") { throw "ModelName may contain only letters, numbers, and underscores" }
if ($ModelSize -le 0 -or $ModelSize % 32 -ne 0) { throw "ModelSize must be a positive multiple of 32" }
if (Test-Path -LiteralPath $bundle -PathType Container) {
    Get-ChildItem -LiteralPath $bundle -File | Where-Object {
        $_.Name -match '^libQnnHtpV[0-9]{2,3}(Stub|Skel)\.so$'
    } | Remove-Item -Force
}
if (Test-Path "$bundle/device_results") {
    Remove-Item -LiteralPath "$bundle/device_results" -Recurse -Force
}
New-Item -ItemType Directory -Force -Path "$bundle/inputs", "$bundle/output" | Out-Null

$androidLibraries = Join-Path $sdk "lib/aarch64-android"
$architecturePairs = @(Get-ChildItem -LiteralPath $androidLibraries -File -ErrorAction Stop |
    ForEach-Object {
        if ($_.Name -notmatch '^libQnnHtpV([0-9]{2,3})Stub\.so$') { return }
        $architectureNumber = [int]$Matches[1]
        if ($architectureNumber -lt 68) { return }
        $architecture = "v$architectureNumber"
        $skeleton = Join-Path $sdk (
            "lib/hexagon-$architecture/unsigned/libQnnHtpV${architectureNumber}Skel.so")
        if (-not (Test-Path -LiteralPath $skeleton -PathType Leaf)) { return }
        [pscustomobject]@{
            number = $architectureNumber
            architecture = $architecture
            stub = $_.FullName
            skeleton = $skeleton
        }
    } | Sort-Object -Property number)
if ($architecturePairs.Count -eq 0) {
    throw "QNN SDK contains no complete HTP stub/skeleton architecture pair: $sdk"
}

$files = @(
    "$sdk/bin/aarch64-android/qnn-net-run",
    "$sdk/bin/aarch64-android/qnn-context-binary-generator",
    "$sdk/lib/aarch64-android/libQnnSystem.so",
    "$sdk/lib/aarch64-android/libQnnHtp.so",
    "$sdk/lib/aarch64-android/libQnnHtpPrepare.so",
    "$sdk/lib/aarch64-android/libQnnHtpNetRunExtensions.so"
)
foreach ($pair in $architecturePairs) {
    $files += $pair.stub, $pair.skeleton
}
foreach ($file in $files) {
    if (-not (Test-Path $file)) { throw "Required QAIRT artifact missing: $file" }
    Copy-Item $file $bundle -Force
}
Copy-Item $model "$bundle/lib$ModelName.so" -Force
$expectedInputBytes = $ModelSize * $ModelSize * 3 * $InputElementBytes
if ((Get-Item $runtimeInput).Length -ne $expectedInputBytes) {
    throw "QNN runtime input must contain $expectedInputBytes bytes for one ${ModelSize}x${ModelSize}x3 NHWC tensor: $runtimeInput"
}
Copy-Item $runtimeInput "$bundle/inputs/input.raw" -Force

$inputLine = "images:=inputs/input.raw"
[System.IO.File]::WriteAllLines("$bundle/inputs/warmup_input_list.txt", @($inputLine) * $WarmupRuns, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllLines("$bundle/inputs/measured_input_list.txt", @($inputLine) * $MeasuredRuns, [System.Text.UTF8Encoding]::new($false))
$htpConfig = @'
{
  "devices": [{"cores": [{"perf_profile": "burst", "rpc_control_latency": 100}]}]
}
'@
[System.IO.File]::WriteAllText("$bundle/htp_config.json", $htpConfig, [System.Text.UTF8Encoding]::new($false))
$backendConfig = @'
{
  "backend_extensions": {
    "shared_library_path": "./libQnnHtpNetRunExtensions.so",
    "config_file_path": "./htp_config.json"
  }
}
'@
[System.IO.File]::WriteAllText("$bundle/htp_backend_extensions.json", $backendConfig, [System.Text.UTF8Encoding]::new($false))
$script = @'
#!/system/bin/sh
set -eu
ROOT=$(pwd)
export LD_LIBRARY_PATH="$ROOT:${LD_LIBRARY_PATH:-}"
export ADSP_LIBRARY_PATH="$ROOT;$ROOT/"
chmod 755 ./qnn-net-run ./qnn-context-binary-generator
mkdir -p ./context ./output
./qnn-net-run --help > qnn_net_run_help.txt 2>&1 || true
./qnn-context-binary-generator --model ./lib__MODEL_NAME__.so --backend ./libQnnHtp.so --binary_file __MODEL_NAME__.htp --output_dir ./context --config_file ./htp_backend_extensions.json --profiling_level detailed --profiling_option optrace > qnn_context.log 2>&1
./qnn-net-run --backend ./libQnnHtp.so --retrieve_context ./context/__MODEL_NAME__.htp.bin --input_list ./inputs/warmup_input_list.txt --output_dir ./output/warmup --config_file ./htp_backend_extensions.json --profiling_level detailed --profiling_option optrace --use_native_input_files --use_native_output_files --keep_num_outputs 0 --log_level info > qnn_warmup.log 2>&1
./qnn-net-run --backend ./libQnnHtp.so --retrieve_context ./context/__MODEL_NAME__.htp.bin --input_list ./inputs/measured_input_list.txt --output_dir ./output/measured --config_file ./htp_backend_extensions.json --profiling_level detailed --profiling_option optrace --use_native_input_files --use_native_output_files --keep_num_outputs 0 --log_level info > qnn_net_run.log 2>&1
'@
$script = $script.Replace("__MODEL_NAME__", $ModelName)
[System.IO.File]::WriteAllText("$bundle/run_htp_benchmark.sh", $script, [System.Text.UTF8Encoding]::new($false))
$manifest = [ordered]@{
    model = "lib$ModelName.so"
    backend = "QNN HTP"
    warmup_runs = $WarmupRuns
    measured_runs = $MeasuredRuns
    input = "images [1,$ModelSize,$ModelSize,3] native NHWC; element_bytes=$InputElementBytes"
    htp_config = "burst; rpc_control_latency=100"
    qnn_sdk_identity = $qnnSdkIdentity
    qnn_sdk_build_identity = $qnnSdkBuildIdentity
    htp_architectures = @($architecturePairs | ForEach-Object { $_.architecture })
    soc_models = $socModels
    soc_architectures = $socArchitectures
    expected_evidence = @("qnn_context.log", "qnn_warmup.log", "qnn_net_run.log", "qnn_warmup_profiling.log", "qnn_measured_profiling.log", "qnn_net_run_help.txt")
}
[System.IO.File]::WriteAllText(
    "$bundle/manifest.json",
    (($manifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "QNN_HTP_DEVICE_BUNDLE_OK path=$bundle files=$((Get-ChildItem $bundle -Recurse -File).Count)"
