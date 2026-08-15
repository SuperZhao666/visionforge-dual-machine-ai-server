param(
    [string]$CanonicalDirectory = "android_inference_benchmark/qnn_workspace/cs2_vombit_416_w8a16",
    [Parameter(Mandatory = $true)][string]$EvaluationDirectory,
    [string]$QnnSdkRoot = "android_inference_benchmark/qnn_sdk/qairt/2.37.1.250807",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$canonicalRoot = (Resolve-Path $CanonicalDirectory).Path
$evaluationRoot = (Resolve-Path $EvaluationDirectory).Path
$qnnRoot = (Resolve-Path $QnnSdkRoot).Path
$expectedCanonicalRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace/cs2_vombit_416_w8a16")
)
if (-not $canonicalRoot.Equals(
        $expectedCanonicalRoot,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "CanonicalDirectory must be the dedicated CS2 path: $expectedCanonicalRoot"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot (
        "analysis_output/cs2_vombit_416_htp_numeric_" +
        (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    )
}
$evidenceRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $evidenceRoot) {
    throw "CS2 HTP evidence output already exists: $evidenceRoot"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$buildManifestPath = Join-Path $canonicalRoot "build_manifest.json"
$buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
$source = Join-Path $canonicalRoot "source/CS2_Vombit_v8s_416.onnx"
$split = Join-Path $canonicalRoot "model/cs2_vombit_416_split.onnx"
$library = Join-Path $canonicalRoot (
    "android_model_lib/build/libcs2_vombit_416_v8s_w8a16.so"
)
if ($buildManifest.schema -ne "visionforge-cs2-vombit-w8a16-build-v1" -or
        $buildManifest.build_complete -ne $true -or
        $buildManifest.model.token -ne "counter-strike-2-vombit-416-v8s" -or
        ($buildManifest.model.input -join ",") -ne "1,3,416,416" -or
        $buildManifest.model.anchors -ne 3549 -or
        $buildManifest.model.classes -ne 4 -or
        (Get-Sha256 $source) -ne $buildManifest.artifacts.source_onnx.sha256 -or
        (Get-Sha256 $split) -ne $buildManifest.artifacts.split_onnx.sha256 -or
        (Get-Sha256 $library) -ne $buildManifest.artifacts.android_library.sha256) {
    throw "CS2 canonical build manifest hash closure is invalid"
}

$runtimeInputs = @(
    Get-ChildItem -LiteralPath $evaluationRoot -File -Filter "*.raw" |
        Sort-Object Name
)
$expectedInputBytes = 416 * 416 * 3 * 2
if ($runtimeInputs.Count -lt 1 -or $runtimeInputs.Count -gt 32 -or
        @($runtimeInputs | Where-Object { $_.Length -ne $expectedInputBytes }).Count -ne 0) {
    throw "CS2 HTP numeric verification requires 1-32 valid U16 NHWC inputs"
}

$workspaceRoot = Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace"
$temporaryBundle = Join-Path $workspaceRoot (
    ".cs2_numeric_bundle." + [Guid]::NewGuid().ToString("N")
)
$temporaryPrefix = [System.IO.Path]::GetFullPath($workspaceRoot) +
    [System.IO.Path]::DirectorySeparatorChar + ".cs2_numeric_bundle."
$resolvedTemporaryBundle = [System.IO.Path]::GetFullPath($temporaryBundle)
if (-not $resolvedTemporaryBundle.StartsWith(
        $temporaryPrefix,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe CS2 temporary bundle path"
}

$prepareBundle = Join-Path $PSScriptRoot "prepare_qnn_htp_device_bundle.ps1"
$runBundle = Join-Path $PSScriptRoot "run_qnn_htp_adb.ps1"
$adb = Join-Path $repositoryRoot ".android-sdk/platform-tools/adb.exe"
$deviceRoot = "/data/local/tmp/visionforge_qnn_htp"
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$deviceInitialized = $false
try {
    & $prepareBundle `
        -QnnSdkRoot $qnnRoot `
        -ModelLibrary $library `
        -RuntimeInput $runtimeInputs[0].FullName `
        -OutputDirectory $temporaryBundle `
        -ModelName "cs2_vombit_416_v8s_w8a16" `
        -ModelSize 416 `
        -InputElementBytes 2 `
        -WarmupRuns 1 `
        -MeasuredRuns 1

    $numericRows = @()
    for ($index = 0; $index -lt $runtimeInputs.Count; $index++) {
        $targetName = "numeric_$($index.ToString('00')).raw"
        $targetPath = Join-Path $temporaryBundle "inputs/$targetName"
        New-Item -ItemType HardLink -Path $targetPath -Target $runtimeInputs[$index].FullName |
            Out-Null
        $numericRows += "images:=inputs/$targetName"
    }
    [System.IO.File]::WriteAllLines(
        (Join-Path $temporaryBundle "inputs/numeric_input_list.txt"),
        $numericRows,
        $utf8WithoutBom
    )

    $deviceInitialized = $true
    & $runBundle -BundleDirectory $temporaryBundle -DeviceDirectory $deviceRoot

    $numericExecutable = @(
        "./qnn-net-run --backend ./libQnnHtp.so",
        "--retrieve_context ./context/cs2_vombit_416_v8s_w8a16.htp.bin",
        "--input_list ./inputs/numeric_input_list.txt",
        "--output_dir ./output/numeric",
        "--config_file ./htp_backend_extensions.json",
        "--use_native_input_files --use_native_output_files",
        "--log_level info > ./cs2_numeric.log 2>&1"
    ) -join " "
    $numericCommand = "cd $deviceRoot && rm -rf ./output/numeric && $numericExecutable"
    & $adb shell $numericCommand
    if ($LASTEXITCODE -ne 0) {
        & $adb pull "$deviceRoot/cs2_numeric.log" $temporaryBundle | Out-Null
        throw "CS2 phone HTP numeric inference failed"
    }

    New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null
    & $adb pull "$deviceRoot/output/numeric" (Join-Path $evidenceRoot "device_output") |
        Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to pull CS2 HTP numeric outputs" }
    & $adb pull "$deviceRoot/cs2_numeric.log" (Join-Path $evidenceRoot "cs2_numeric.log") |
        Out-Null
    Copy-Item -LiteralPath (
        Join-Path $temporaryBundle "device_results/device_identity.json"
    ) -Destination (Join-Path $evidenceRoot "device_identity.json")
    $evidenceInputDirectory = Join-Path $evidenceRoot "inputs"
    New-Item -ItemType Directory -Force -Path $evidenceInputDirectory | Out-Null
    $evidenceInputs = @()
    for ($index = 0; $index -lt $runtimeInputs.Count; $index++) {
        $evidenceInput = Join-Path $evidenceInputDirectory (
            "input_$($index.ToString('00')).raw"
        )
        New-Item -ItemType HardLink -Path $evidenceInput `
            -Target $runtimeInputs[$index].FullName | Out-Null
        $evidenceInputs += $evidenceInput
    }

    $resultDirectories = @(
        Get-ChildItem -LiteralPath (Join-Path $evidenceRoot "device_output") `
            -Directory -Filter "Result_*" | Sort-Object Name
    )
    if ($resultDirectories.Count -ne $runtimeInputs.Count) {
        throw (
            "CS2 HTP result count mismatch: expected=$($runtimeInputs.Count) " +
            "actual=$($resultDirectories.Count)")
    }
    $resultArtifacts = @()
    for ($index = 0; $index -lt $resultDirectories.Count; $index++) {
        $coordinates = Join-Path $resultDirectories[$index].FullName "output_coordinates.raw"
        $confidences = Join-Path $resultDirectories[$index].FullName "output_confidences.raw"
        if ((Get-Item -LiteralPath $coordinates).Length -ne 56784 -or
                (Get-Item -LiteralPath $confidences).Length -ne 56784) {
            throw "CS2 HTP output tensor size mismatch in Result_$index"
        }
        $resultArtifacts += [ordered]@{
            index = $index
            input_path = $evidenceInputs[$index]
            input_sha256 = Get-Sha256 $evidenceInputs[$index]
            coordinates_path = $coordinates
            coordinates_sha256 = Get-Sha256 $coordinates
            confidences_path = $confidences
            confidences_sha256 = Get-Sha256 $confidences
        }
    }
    $executionManifest = [ordered]@{
        schema = "visionforge-cs2-phone-htp-execution-v1"
        completed_at = (Get-Date).ToUniversalTime().ToString("o")
        backend = "libQnnHtp.so"
        inferences_completed = $runtimeInputs.Count
        source_onnx_sha256 = Get-Sha256 $source
        split_onnx_sha256 = Get-Sha256 $split
        android_library_path = $library
        android_library_sha256 = Get-Sha256 $library
        qnn_sdk_version = $buildManifest.toolchain.qnn_sdk_version
        output_contract = [ordered]@{
            coordinates = "FP32 [1,4,3549]"
            confidences = "FP32 [1,4,3549]"
        }
        results = $resultArtifacts
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $evidenceRoot "execution_manifest.json"),
        ($executionManifest | ConvertTo-Json -Depth 7),
        $utf8WithoutBom
    )
    Write-Output (
        "CS2_PHONE_HTP_NUMERIC_RUN_OK " +
        "library_sha256=$($executionManifest.android_library_sha256) " +
        "inferences=$($runtimeInputs.Count) evidence=$evidenceRoot"
    )
} finally {
    if ($deviceInitialized) {
        & $adb shell "rm -rf $deviceRoot" | Out-Null
    }
    if (Test-Path -LiteralPath $resolvedTemporaryBundle) {
        if (-not $resolvedTemporaryBundle.StartsWith(
                $temporaryPrefix,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean unsafe CS2 temporary bundle path"
        }
        [System.IO.Directory]::Delete($resolvedTemporaryBundle, $true)
    }
}
