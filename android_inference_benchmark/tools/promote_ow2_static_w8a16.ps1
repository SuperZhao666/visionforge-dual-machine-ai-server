param(
    [string]$CanonicalDirectory = "android_inference_benchmark/qnn_workspace/ow2_416_static_decode_w8a16",
    [Parameter(Mandatory = $true)][string]$NumericReport
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$expectedCanonicalRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace/ow2_416_static_decode_w8a16")
)
$canonicalRoot = (Resolve-Path $CanonicalDirectory).Path
if (-not $canonicalRoot.Equals($expectedCanonicalRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "CanonicalDirectory must be the dedicated OW2 canonical path: $expectedCanonicalRoot"
}
$reportPath = (Resolve-Path $NumericReport).Path
$buildManifestPath = Join-Path $canonicalRoot "build_manifest.json"
$buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$numeric = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($buildManifest.schema -ne "visionforge-ow2-static-w8a16-build-v1" -or
        -not $buildManifest.build_complete -or $buildManifest.release_eligible) {
    throw "Canonical OW2 build manifest is not in the expected pre-promotion state"
}
if ($numeric.schema -ne "visionforge-ow2-qnn-numeric-contract-v1" -or -not $numeric.ok) {
    throw "OW2 phone HTP numeric contract did not pass: $reportPath"
}
$expectedChecks = @(
    "static_coordinates_exact",
    "static_confidences_exact",
    "static_dynamic_decode_removed",
    "qnn_control_confidences_not_saturated",
    "control_top20_overlap",
    "control_candidate_count_matches",
    "control_candidate_set_overlap",
    "control_confidence_error",
    "control_candidate_coordinate_mean",
    "control_candidate_coordinate_p95",
    "control_candidate_coordinate_max",
    "control_nms_target_count_matches",
    "control_nms_target_iou",
    "control_nms_target_center"
)
$actualCheckNames = @($numeric.checks.PSObject.Properties.Name)
foreach ($checkName in $expectedChecks) {
    if ($checkName -notin $actualCheckNames -or -not $numeric.checks.$checkName) {
        throw "OW2 numeric contract check is missing or false: $checkName"
    }
}
$modelInput = @($buildManifest.model.input) -join ","
if ($modelInput -ne "1,3,416,416" -or
        $buildManifest.model.token -ne "overwatch2-416-yolov5" -or
        $buildManifest.model.anchors -ne 3549 -or
        $buildManifest.model.classes -ne 2 -or
        $buildManifest.model.control_class -ne 0 -or
        $buildManifest.model.raw_tensor -ne "539" -or
        $buildManifest.artifacts.source_onnx.sha256 -ne "0AE9AB4AAF752B45260345FF1CE492649385B3CC768F81D11E1E658F902AB980" -or
        $buildManifest.toolchain.qnn_sdk_version -ne "2.37.1.250807") {
    throw "Canonical OW2 build manifest model or toolchain contract is invalid"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$libraryPath = Join-Path $canonicalRoot $buildManifest.artifacts.android_library.path
$splitPath = Join-Path $canonicalRoot $buildManifest.artifacts.split_onnx.path
$sourcePath = Join-Path $canonicalRoot $buildManifest.artifacts.source_onnx.path
$libraryHash = Get-Sha256 $libraryPath
$splitHash = Get-Sha256 $splitPath
$sourceHash = Get-Sha256 $sourcePath
if ($libraryHash -ne $buildManifest.artifacts.android_library.sha256) {
    throw "Canonical OW2 library no longer matches its build manifest"
}
if ($libraryHash -ne $numeric.artifacts.qnn_android_model_library.sha256) {
    throw "Phone HTP numeric report is bound to a different OW2 library"
}
if ($splitHash -ne $numeric.artifacts.rewritten_onnx.sha256) {
    throw "Phone HTP numeric report is bound to a different static ONNX"
}
if ($sourceHash -ne $numeric.artifacts.source_onnx.sha256) {
    throw "Phone HTP numeric report is bound to a different source ONNX"
}

$canonicalNumericPath = Join-Path $canonicalRoot "numeric_contract.json"
$numericTemporary = "$canonicalNumericPath.tmp"
Copy-Item -LiteralPath $reportPath -Destination $numericTemporary -Force
Move-Item -LiteralPath $numericTemporary -Destination $canonicalNumericPath -Force
$buildManifestHash = Get-Sha256 $buildManifestPath
$numericHash = Get-Sha256 $canonicalNumericPath
$releaseManifest = [ordered]@{
    schema = "visionforge-ow2-static-w8a16-release-v1"
    complete = $true
    phone_htp_numeric_verified = $true
    promoted_at = (Get-Date).ToUniversalTime().ToString("o")
    source_onnx_sha256 = $sourceHash
    split_onnx_sha256 = $splitHash
    android_library_sha256 = $libraryHash
    build_manifest_sha256 = $buildManifestHash
    numeric_contract_sha256 = $numericHash
}
$releasePath = Join-Path $canonicalRoot "release_manifest.json"
$releaseTemporary = "$releasePath.tmp"
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$releaseManifestJson = $releaseManifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText(
    $releaseTemporary,
    $releaseManifestJson,
    $utf8WithoutBom
)
Move-Item -LiteralPath $releaseTemporary -Destination $releasePath -Force
Write-Output (
    "OW2_STATIC_W8A16_RELEASE_PROMOTED " +
    "library_sha256=$libraryHash release_manifest=$releasePath"
)
