param(
    [Parameter(Mandatory = $true)][string]$SourceOnnx,
    [Parameter(Mandatory = $true)][string]$CalibrationDirectory,
    [string]$QnnSdkRoot = "android_inference_benchmark/qnn_sdk/qairt/2.37.1.250807",
    [string]$OutputDirectory = "android_inference_benchmark/qnn_workspace/ow2_416_static_decode_w8a16"
)

$ErrorActionPreference = "Stop"
$approvedSourceSha256 = "0AE9AB4AAF752B45260345FF1CE492649385B3CC768F81D11E1E658F902AB980"
$approvedQnnSdkVersion = "2.37.1.250807"
$expectedCalibrationCount = 15
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$source = (Resolve-Path $SourceOnnx).Path
$calibrationSource = (Resolve-Path $CalibrationDirectory).Path
$qnnRoot = (Resolve-Path $QnnSdkRoot).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$workspaceRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace")
)
$expectedOutputRoot = Join-Path $workspaceRoot "ow2_416_static_decode_w8a16"
if (-not $outputRoot.Equals($expectedOutputRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must be the dedicated OW2 canonical path: $expectedOutputRoot"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$sourceHash = Get-Sha256 $source
if ($sourceHash -ne $approvedSourceSha256) {
    throw "OW2 source model is not approved: expected=$approvedSourceSha256 actual=$sourceHash"
}
if ((Split-Path -Leaf $qnnRoot) -ne $approvedQnnSdkVersion) {
    throw "Unsupported QAIRT/QNN SDK version: $qnnRoot"
}

$outputParent = [System.IO.Directory]::GetParent($outputRoot).FullName
$outputName = Split-Path -Leaf $outputRoot
$stagingRoot = Join-Path $outputParent (".ow2s." + [Guid]::NewGuid().ToString("N"))
$previousRoot = Join-Path $outputParent (
    "$outputName.previous." + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") +
    "." + [Guid]::NewGuid().ToString("N")
)
$workspacePrefix = $workspaceRoot + [System.IO.Path]::DirectorySeparatorChar
$stagingPrefix = $workspacePrefix + ".ow2s."
$previousPrefix = $workspacePrefix + "$outputName.previous."
if (-not $outputRoot.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $stagingRoot.StartsWith($stagingPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $previousRoot.StartsWith($previousPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe OW2 canonical, staging, or previous path"
}

$python311 = (Get-Command python -ErrorAction Stop).Source
$python310 = Join-Path $repositoryRoot "android_inference_benchmark/toolchains/python310/python.exe"
$rewriter = Join-Path $PSScriptRoot "rewrite_qnn_split_output_model.py"
$androidModelBuilder = Join-Path $PSScriptRoot "build_qnn_android_model.ps1"
$converter = Join-Path $qnnRoot "bin/x86_64-windows-msvc/qnn-onnx-converter"
foreach ($required in $python310, $rewriter, $androidModelBuilder, $converter) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required OW2 build dependency is missing: $required"
    }
}

$published = $false
$previousMoved = $false
New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null
try {
    $sourceDirectory = Join-Path $stagingRoot "source"
    $calibrationDirectory = Join-Path $stagingRoot "calibration"
    $calibrationRawDirectory = Join-Path $calibrationDirectory "raw"
    $modelDirectory = Join-Path $stagingRoot "model"
    $qnnDirectory = Join-Path $stagingRoot "qnn"
    $androidModelDirectory = Join-Path $stagingRoot "android_model_lib"
    New-Item -ItemType Directory -Force -Path (
        $sourceDirectory,
        $calibrationRawDirectory,
        $modelDirectory,
        $qnnDirectory
    ) | Out-Null

    $canonicalSource = Join-Path $sourceDirectory "OW2.onnx"
    Copy-Item -LiteralPath $source -Destination $canonicalSource -Force
    $rawFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $calibrationSource "raw") -File -Filter "*.raw" |
            Sort-Object Name
    )
    if ($rawFiles.Count -ne $expectedCalibrationCount) {
        throw "OW2 calibration must contain exactly $expectedCalibrationCount raw tensors; found $($rawFiles.Count)"
    }
    foreach ($rawFile in $rawFiles) {
        if ($rawFile.Length -ne 2076672) {
            throw "Unexpected calibration tensor size: $($rawFile.FullName) bytes=$($rawFile.Length)"
        }
        Copy-Item -LiteralPath $rawFile.FullName -Destination (
            Join-Path $calibrationRawDirectory $rawFile.Name
        ) -Force
    }
    $inputList = Join-Path $calibrationDirectory "input_list.txt"
    $stagingInputRows = Get-ChildItem -LiteralPath $calibrationRawDirectory -File -Filter "*.raw" |
        Sort-Object Name |
        ForEach-Object { "images:=$($_.FullName)" }
    Set-Content -LiteralPath $inputList -Value $stagingInputRows -Encoding Ascii

    $splitOnnx = Join-Path $modelDirectory "ow2_416_static_split.onnx"
    & $python311 $rewriter `
        --source $canonicalSource `
        --destination $splitOnnx `
        --raw-tensor 539 `
        --classes 2 `
        --model-size 416 `
        --strides 8 16 32
    if ($LASTEXITCODE -ne 0) { throw "OW2 static ONNX rewrite failed" }

    $previousPythonPath = $env:PYTHONPATH
    $previousPath = $env:PATH
    try {
        . (Join-Path $qnnRoot "bin/envsetup.ps1") -arch X86_64
        $compatibilityPath = Join-Path $PSScriptRoot "qnn_sdk_compat"
        $env:PYTHONPATH = "$compatibilityPath;$env:PYTHONPATH"
        $qnnModelCppOutput = Join-Path $qnnDirectory "ow2_416_static_w8a16.cpp"
        & $python310 $converter `
            --input_network $splitOnnx `
            --output_path $qnnModelCppOutput `
            --input_dim images 1,3,416,416 `
            --input_layout images NCHW `
            --input_list $inputList `
            --weights_bitwidth 8 `
            --act_bitwidth 16 `
            --bias_bitwidth 32 `
            --act_quantizer_calibration min-max `
            --act_quantizer_schema asymmetric `
            --param_quantizer_calibration min-max `
            --param_quantizer_schema asymmetric `
            --use_per_channel_quantization `
            --use_native_input_files `
            --preserve_io datatype output_coordinates output_confidences
        if ($LASTEXITCODE -ne 0) { throw "OW2 W8A16 QNN conversion failed" }
    } finally {
        $env:PYTHONPATH = $previousPythonPath
        $env:PATH = $previousPath
    }

    $modelCpp = Join-Path $qnnDirectory "ow2_416_static_w8a16.cpp"
    $modelBin = Join-Path $qnnDirectory "ow2_416_static_w8a16.bin"
    $netJson = Join-Path $qnnDirectory "ow2_416_static_w8a16_net.json"
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    foreach ($generatedTextFile in $modelCpp, $netJson) {
        $generatedText = [System.IO.File]::ReadAllText($generatedTextFile)
        $generatedText = $generatedText.Replace(
            $stagingRoot,
            '${VISIONFORGE_OW2_BUILD_ROOT}'
        )
        $generatedText = $generatedText.Replace(
            $stagingRoot.Replace('\', '\\'),
            '${VISIONFORGE_OW2_BUILD_ROOT}'
        )
        [System.IO.File]::WriteAllText(
            $generatedTextFile,
            $generatedText,
            $utf8WithoutBom
        )
    }
    Push-Location $repositoryRoot
    try {
        & $androidModelBuilder `
            -QnnSdkRoot $qnnRoot `
            -ModelCpp $modelCpp `
            -ModelBin $modelBin `
            -OutputDirectory $androidModelDirectory `
            -ModelName "ow2_416_w8a16"
        if ($LASTEXITCODE -ne 0) { throw "OW2 Android QNN model library build failed" }
    } finally {
        Pop-Location
    }

    $library = Join-Path $androidModelDirectory "build/libow2_416_w8a16.so"
    foreach ($requiredArtifact in $splitOnnx, $modelCpp, $modelBin, $netJson, $library) {
        if (-not (Test-Path -LiteralPath $requiredArtifact -PathType Leaf)) {
            throw "OW2 build artifact is missing: $requiredArtifact"
        }
    }

    $publishedInputRows = Get-ChildItem -LiteralPath $calibrationRawDirectory -File -Filter "*.raw" |
        Sort-Object Name |
        ForEach-Object {
            "images:=" + (Join-Path $outputRoot "calibration/raw/$($_.Name)")
        }
    Set-Content -LiteralPath $inputList -Value $publishedInputRows -Encoding Ascii
    $calibrationArtifacts = @(
        Get-ChildItem -LiteralPath $calibrationRawDirectory -File -Filter "*.raw" |
            Sort-Object Name |
            ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    bytes = $_.Length
                    sha256 = Get-Sha256 $_.FullName
                }
            }
    )
    $buildManifest = [ordered]@{
        schema = "visionforge-ow2-static-w8a16-build-v1"
        build_complete = $true
        release_eligible = $false
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        model = [ordered]@{
            token = "overwatch2-416-yolov5"
            input = @(1, 3, 416, 416)
            anchors = 3549
            classes = 2
            control_class = 0
            raw_tensor = "539"
            strides = @(8, 16, 32)
        }
        toolchain = [ordered]@{
            qnn_sdk_version = $approvedQnnSdkVersion
            qnn_sdk_root = $qnnRoot
            python_converter = $python310
            converter = [ordered]@{ path = $converter; sha256 = Get-Sha256 $converter }
            rewriter = [ordered]@{ path = $rewriter; sha256 = Get-Sha256 $rewriter }
            android_model_builder = [ordered]@{
                path = $androidModelBuilder
                sha256 = Get-Sha256 $androidModelBuilder
            }
        }
        artifacts = [ordered]@{
            source_onnx = [ordered]@{ path = "source/OW2.onnx"; sha256 = Get-Sha256 $canonicalSource }
            split_onnx = [ordered]@{ path = "model/ow2_416_static_split.onnx"; sha256 = Get-Sha256 $splitOnnx }
            qnn_cpp = [ordered]@{ path = "qnn/ow2_416_static_w8a16.cpp"; sha256 = Get-Sha256 $modelCpp }
            qnn_bin = [ordered]@{ path = "qnn/ow2_416_static_w8a16.bin"; sha256 = Get-Sha256 $modelBin }
            qnn_net_json = [ordered]@{ path = "qnn/ow2_416_static_w8a16_net.json"; sha256 = Get-Sha256 $netJson }
            android_library = [ordered]@{ path = "android_model_lib/build/libow2_416_w8a16.so"; sha256 = Get-Sha256 $library }
            calibration_input_list = [ordered]@{ path = "calibration/input_list.txt"; sha256 = Get-Sha256 $inputList }
        }
        calibration = [ordered]@{
            count = $calibrationArtifacts.Count
            tensors = $calibrationArtifacts
        }
    }
    $buildManifestPath = Join-Path $stagingRoot "build_manifest.json"
    $buildManifestJson = $buildManifest | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText(
        $buildManifestPath,
        $buildManifestJson,
        $utf8WithoutBom
    )

    if (Test-Path -LiteralPath $outputRoot) {
        Move-Item -LiteralPath $outputRoot -Destination $previousRoot
        $previousMoved = $true
    }
    try {
        Move-Item -LiteralPath $stagingRoot -Destination $outputRoot
        $published = $true
    } catch {
        if ($previousMoved -and -not (Test-Path -LiteralPath $outputRoot)) {
            Move-Item -LiteralPath $previousRoot -Destination $outputRoot
            $previousMoved = $false
        }
        throw
    }

    $publishedLibrary = Join-Path $outputRoot "android_model_lib/build/libow2_416_w8a16.so"
    Write-Output (
        "OW2_STATIC_W8A16_BUILD_OK " +
        "source_sha256=$sourceHash " +
        "library_sha256=$(Get-Sha256 $publishedLibrary) " +
        "build_manifest=$(Join-Path $outputRoot 'build_manifest.json') " +
        "release_eligible=false"
    )
} finally {
    if (-not $published -and (Test-Path -LiteralPath $stagingRoot)) {
        $resolvedStaging = [System.IO.Path]::GetFullPath($stagingRoot)
        if (-not $resolvedStaging.StartsWith($stagingPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean unsafe OW2 staging path: $resolvedStaging"
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
