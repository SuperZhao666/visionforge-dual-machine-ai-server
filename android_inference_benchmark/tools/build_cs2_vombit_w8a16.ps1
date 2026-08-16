param(
    [Parameter(Mandatory = $true)][string]$SourceOnnx,
    [Parameter(Mandatory = $true)][string]$CalibrationDirectory,
    [string]$ApprovedSplitOnnx = "",
    [string]$QnnSdkRoot = "android_inference_benchmark/qnn_sdk/qairt/2.37.1.250807",
    [string]$OutputDirectory = "android_inference_benchmark/qnn_workspace/cs2_vombit_416_w8a16"
)

$ErrorActionPreference = "Stop"
$approvedSourceSha256 = "4D7E9F0EA790E0A2A1BBEC16D216F2B54B1F840C20F676BFBC32655E1FFDB0A7"
$approvedSplitSha256 = "DD70F00F040421EA216C3FC913B35E9BE822F65F4C3354C41F6787F5282E0E7D"
$approvedQnnSdkVersion = "2.37.1.250807"
$expectedCalibrationCount = 15
$expectedCalibrationBytes = 2076672
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$source = (Resolve-Path $SourceOnnx).Path
$calibrationSource = (Resolve-Path $CalibrationDirectory).Path
$qnnRoot = (Resolve-Path $QnnSdkRoot).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$workspaceRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace")
)
$expectedOutputRoot = Join-Path $workspaceRoot "cs2_vombit_416_w8a16"
if (-not $outputRoot.Equals(
        $expectedOutputRoot,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must be the dedicated CS2 canonical path: $expectedOutputRoot"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function New-StorageNeutralLink([string]$Source, [string]$Destination) {
    $sourceRoot = [System.IO.Path]::GetPathRoot(
        [System.IO.Path]::GetFullPath($Source)
    )
    $destinationRoot = [System.IO.Path]::GetPathRoot(
        [System.IO.Path]::GetFullPath($Destination)
    )
    if ($sourceRoot.Equals(
            $destinationRoot,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        New-Item -ItemType HardLink -Path $Destination -Target $Source | Out-Null
    } else {
        New-Item -ItemType SymbolicLink -Path $Destination -Target $Source | Out-Null
    }
}

$sourceHash = Get-Sha256 $source
if ($sourceHash -ne $approvedSourceSha256) {
    throw "CS2 source model is not approved: expected=$approvedSourceSha256 actual=$sourceHash"
}
if ((Split-Path -Leaf $qnnRoot) -ne $approvedQnnSdkVersion) {
    throw "Unsupported QAIRT/QNN SDK version: $qnnRoot"
}

$datasetManifestPath = Join-Path $calibrationSource "dataset_manifest.json"
if (-not (Test-Path -LiteralPath $datasetManifestPath -PathType Leaf)) {
    throw "CS2 calibration dataset manifest is missing: $datasetManifestPath"
}
$datasetManifest = Get-Content -LiteralPath $datasetManifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
if ($datasetManifest.schema -ne "visionforge-cs2-calibration-dataset-v1" -or
        $datasetManifest.calibration.count -ne $expectedCalibrationCount -or
        ($datasetManifest.model_input -join ",") -ne "1,3,416,416" -or
        ($datasetManifest.padding_rgb -join ",") -ne "114,114,114") {
    throw "CS2 calibration dataset manifest contract is invalid"
}
$rawSourceDirectory = Join-Path $calibrationSource "calibration/raw"
$rawFiles = @(
    Get-ChildItem -LiteralPath $rawSourceDirectory -File -Filter "*.raw" |
        Sort-Object Name
)
if ($rawFiles.Count -ne $expectedCalibrationCount) {
    throw "CS2 calibration requires exactly $expectedCalibrationCount raw tensors"
}
foreach ($rawFile in $rawFiles) {
    if ($rawFile.Length -ne $expectedCalibrationBytes) {
        throw "Unexpected CS2 calibration tensor size: $($rawFile.FullName)"
    }
    $relativeTensor = "calibration\raw\$($rawFile.Name)"
    $record = @(
        $datasetManifest.records | Where-Object {
            $_.role -eq "calibration" -and
            $_.tensor.Replace("/", "\") -eq $relativeTensor
        }
    )
    if ($record.Count -ne 1 -or
            (Get-Sha256 $rawFile.FullName) -ne $record[0].tensor_sha256) {
        throw "CS2 calibration tensor provenance mismatch: $($rawFile.Name)"
    }
}

$outputParent = [System.IO.Directory]::GetParent($outputRoot).FullName
$outputName = Split-Path -Leaf $outputRoot
$stagingRoot = Join-Path $outputParent (".cs2s." + [Guid]::NewGuid().ToString("N"))
$previousRoot = Join-Path $outputParent (
    "$outputName.previous." + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ") +
    "." + [Guid]::NewGuid().ToString("N")
)
$workspacePrefix = $workspaceRoot + [System.IO.Path]::DirectorySeparatorChar
$stagingPrefix = $workspacePrefix + ".cs2s."
$previousPrefix = $workspacePrefix + "$outputName.previous."
if (-not $outputRoot.StartsWith(
        $workspacePrefix,
        [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $stagingRoot.StartsWith(
            $stagingPrefix,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not $previousRoot.StartsWith(
            $previousPrefix,
            [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe CS2 canonical, staging, or previous path"
}

$python311 = (Get-Command python -ErrorAction Stop).Source
$python310 = Join-Path $repositoryRoot "android_inference_benchmark/toolchains/python310/python.exe"
$rewriter = Join-Path $PSScriptRoot "rewrite_yolov8_split_output_model.py"
$androidModelBuilder = Join-Path $PSScriptRoot "build_qnn_android_model.ps1"
$converter = Join-Path $qnnRoot "bin/x86_64-windows-msvc/qnn-onnx-converter"
foreach ($required in $python310, $rewriter, $androidModelBuilder, $converter) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required CS2 build dependency is missing: $required"
    }
}

$approvedSplit = $null
if ($ApprovedSplitOnnx) {
    $approvedSplit = (Resolve-Path $ApprovedSplitOnnx).Path
    $approvedSplitHash = Get-Sha256 $approvedSplit
    if ($approvedSplitHash -ne $approvedSplitSha256) {
        throw "Approved CS2 split model hash mismatch: $approvedSplitHash"
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

    $canonicalSource = Join-Path $sourceDirectory "CS2_Vombit_v8s_416.onnx"
    New-StorageNeutralLink $source $canonicalSource
    foreach ($rawFile in $rawFiles) {
        New-StorageNeutralLink $rawFile.FullName (
            Join-Path $calibrationRawDirectory $rawFile.Name
        )
    }
    $inputList = Join-Path $calibrationDirectory "input_list.txt"
    $stagingInputRows = Get-ChildItem -LiteralPath $calibrationRawDirectory -File -Filter "*.raw" |
        Sort-Object Name |
        ForEach-Object { "images:=$($_.FullName)" }
    Set-Content -LiteralPath $inputList -Value $stagingInputRows -Encoding Ascii

    $splitOnnx = Join-Path $modelDirectory "cs2_vombit_416_split.onnx"
    & $python311 $rewriter `
        --source $canonicalSource `
        --destination $splitOnnx `
        --anchors 3549 `
        --classes 4
    if ($LASTEXITCODE -ne 0) { throw "CS2 split-output ONNX rewrite failed" }
    $generatedSplitHash = Get-Sha256 $splitOnnx
    if ($generatedSplitHash -ne $approvedSplitSha256) {
        throw "CS2 split model drifted: expected=$approvedSplitSha256 actual=$generatedSplitHash"
    }
    if ($approvedSplit) {
        [System.IO.File]::Delete($splitOnnx)
        New-StorageNeutralLink $approvedSplit $splitOnnx
    }

    $previousPythonPath = $env:PYTHONPATH
    $previousPath = $env:PATH
    try {
        . (Join-Path $qnnRoot "bin/envsetup.ps1") -arch X86_64
        $compatibilityPath = Join-Path $PSScriptRoot "qnn_sdk_compat"
        $env:PYTHONPATH = "$compatibilityPath;$env:PYTHONPATH"
        $qnnModelCppOutput = Join-Path $qnnDirectory "cs2_vombit_416_v8s_w8a16.cpp"
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
        if ($LASTEXITCODE -ne 0) { throw "CS2 W8A16 QNN conversion failed" }
    } finally {
        $env:PYTHONPATH = $previousPythonPath
        $env:PATH = $previousPath
    }

    $modelCpp = Join-Path $qnnDirectory "cs2_vombit_416_v8s_w8a16.cpp"
    $modelBin = Join-Path $qnnDirectory "cs2_vombit_416_v8s_w8a16.bin"
    $netJson = Join-Path $qnnDirectory "cs2_vombit_416_v8s_w8a16_net.json"
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    foreach ($generatedTextFile in $modelCpp, $netJson) {
        $generatedText = [System.IO.File]::ReadAllText($generatedTextFile)
        $generatedText = $generatedText.Replace(
            $stagingRoot,
            '${VISIONFORGE_CS2_BUILD_ROOT}'
        )
        $generatedText = $generatedText.Replace(
            $stagingRoot.Replace('\', '\\'),
            '${VISIONFORGE_CS2_BUILD_ROOT}'
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
            -ModelName "cs2_vombit_416_v8s_w8a16"
        if ($LASTEXITCODE -ne 0) { throw "CS2 Android QNN model library build failed" }
    } finally {
        Pop-Location
    }

    $library = Join-Path $androidModelDirectory "build/libcs2_vombit_416_v8s_w8a16.so"
    foreach ($requiredArtifact in $splitOnnx, $modelCpp, $modelBin, $netJson, $library) {
        if (-not (Test-Path -LiteralPath $requiredArtifact -PathType Leaf)) {
            throw "CS2 build artifact is missing: $requiredArtifact"
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
        schema = "visionforge-cs2-vombit-w8a16-build-v1"
        build_complete = $true
        release_eligible = $false
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        model = [ordered]@{
            token = "counter-strike-2-vombit-416-v8s"
            input = @(1, 3, 416, 416)
            anchors = 3549
            classes = 4
            class_names = @("ct_body", "ct_head", "t_body", "t_head")
            target_pairs = @(@(0, 1), @(2, 3))
            output_names = @("output_coordinates", "output_confidences")
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
            source_onnx = [ordered]@{
                path = "source/CS2_Vombit_v8s_416.onnx"
                sha256 = Get-Sha256 $canonicalSource
            }
            split_onnx = [ordered]@{
                path = "model/cs2_vombit_416_split.onnx"
                sha256 = Get-Sha256 $splitOnnx
            }
            qnn_cpp = [ordered]@{
                path = "qnn/cs2_vombit_416_v8s_w8a16.cpp"
                sha256 = Get-Sha256 $modelCpp
            }
            qnn_bin = [ordered]@{
                path = "qnn/cs2_vombit_416_v8s_w8a16.bin"
                sha256 = Get-Sha256 $modelBin
            }
            qnn_net_json = [ordered]@{
                path = "qnn/cs2_vombit_416_v8s_w8a16_net.json"
                sha256 = Get-Sha256 $netJson
            }
            android_library = [ordered]@{
                path = "android_model_lib/build/libcs2_vombit_416_v8s_w8a16.so"
                sha256 = Get-Sha256 $library
            }
            calibration_input_list = [ordered]@{
                path = "calibration/input_list.txt"
                sha256 = Get-Sha256 $inputList
            }
            dataset_manifest = [ordered]@{
                source_path = $datasetManifestPath
                sha256 = Get-Sha256 $datasetManifestPath
            }
        }
        calibration = [ordered]@{
            count = $calibrationArtifacts.Count
            tensors = $calibrationArtifacts
        }
    }
    $buildManifestPath = Join-Path $stagingRoot "build_manifest.json"
    [System.IO.File]::WriteAllText(
        $buildManifestPath,
        ($buildManifest | ConvertTo-Json -Depth 9),
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
    if ($previousMoved -and (Test-Path -LiteralPath $previousRoot)) {
        [System.IO.Directory]::Delete($previousRoot, $true)
        $previousMoved = $false
    }

    $publishedLibrary = Join-Path $outputRoot "android_model_lib/build/libcs2_vombit_416_v8s_w8a16.so"
    Write-Output (
        "CS2_VOMBIT_W8A16_BUILD_OK " +
        "source_sha256=$sourceHash " +
        "split_sha256=$approvedSplitSha256 " +
        "library_sha256=$(Get-Sha256 $publishedLibrary) " +
        "build_manifest=$(Join-Path $outputRoot 'build_manifest.json') " +
        "release_eligible=false"
    )
} finally {
    if (-not $published -and (Test-Path -LiteralPath $stagingRoot)) {
        $resolvedStaging = [System.IO.Path]::GetFullPath($stagingRoot)
        if (-not $resolvedStaging.StartsWith(
                $stagingPrefix,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean unsafe CS2 staging path: $resolvedStaging"
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}
