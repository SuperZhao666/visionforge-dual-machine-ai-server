param(
    [string]$CanonicalDirectory = "android_inference_benchmark/qnn_workspace/cs2_vombit_416_w8a16",
    [Parameter(Mandatory = $true)][string]$NumericReport
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$expectedCanonicalRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot "android_inference_benchmark/qnn_workspace/cs2_vombit_416_w8a16")
)
$canonicalRoot = (Resolve-Path $CanonicalDirectory).Path
if (-not $canonicalRoot.Equals(
        $expectedCanonicalRoot,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "CanonicalDirectory must be the dedicated CS2 canonical path: $expectedCanonicalRoot"
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

$buildManifestPath = Join-Path $canonicalRoot "build_manifest.json"
$numericReportPath = (Resolve-Path $NumericReport).Path
$buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw -Encoding UTF8 |
    ConvertFrom-Json
$numeric = Get-Content -LiteralPath $numericReportPath -Raw -Encoding UTF8 |
    ConvertFrom-Json

if ($buildManifest.schema -ne "visionforge-cs2-vombit-w8a16-build-v1" -or
        -not $buildManifest.build_complete -or $buildManifest.release_eligible) {
    throw "Canonical CS2 build manifest is not in the expected pre-promotion state"
}
if ($numeric.schema -ne "visionforge-cs2-qnn-numeric-contract-v1" -or
        -not $numeric.ok) {
    throw "CS2 phone HTP numeric contract did not pass: $numericReportPath"
}

$expectedChecks = @(
    "artifact_hash_closure",
    "source_split_outputs_exact",
    "split_mixed_domain_output_removed",
    "phone_htp_outputs_finite",
    "qnn_confidences_not_saturated_per_class",
    "candidate_counts_match",
    "candidate_sets_match",
    "candidate_coordinate_error_bounded",
    "candidate_confidence_error_bounded",
    "nms_entity_counts_match",
    "nms_boxes_match",
    "known_positive_all_four_classes_present",
    "phone_htp_execution_count_bound"
)
$actualCheckNames = @($numeric.checks.PSObject.Properties.Name)
foreach ($checkName in $expectedChecks) {
    if ($checkName -notin $actualCheckNames -or -not $numeric.checks.$checkName) {
        throw "CS2 numeric contract check is missing or false: $checkName"
    }
}

$modelInput = @($buildManifest.model.input) -join ","
$classNames = @($buildManifest.model.class_names) -join ","
$outputNames = @($buildManifest.model.output_names) -join ","
$targetPairs = @($buildManifest.model.target_pairs | ForEach-Object {
        @($_) -join ","
    }) -join ";"
if ($modelInput -ne "1,3,416,416" -or
        $buildManifest.model.token -ne "counter-strike-2-vombit-416-v8s" -or
        $buildManifest.model.anchors -ne 3549 -or
        $buildManifest.model.classes -ne 4 -or
        $classNames -ne "ct_body,ct_head,t_body,t_head" -or
        $targetPairs -ne "0,1;2,3" -or
        $outputNames -ne "output_coordinates,output_confidences" -or
        $buildManifest.artifacts.source_onnx.sha256 -ne
            "4D7E9F0EA790E0A2A1BBEC16D216F2B54B1F840C20F676BFBC32655E1FFDB0A7" -or
        $buildManifest.artifacts.split_onnx.sha256 -ne
            "DD70F00F040421EA216C3FC913B35E9BE822F65F4C3354C41F6787F5282E0E7D" -or
        $buildManifest.toolchain.qnn_sdk_version -ne "2.37.1.250807") {
    throw "Canonical CS2 build manifest model or toolchain contract is invalid"
}
if ($buildManifest.licensing.source_metadata_declares -ne "AGPL-3.0" -or
        -not $buildManifest.licensing.commercial_distribution_review_required) {
    throw "CS2 source licensing review contract is missing"
}

$sourcePath = Join-Path $canonicalRoot $buildManifest.artifacts.source_onnx.path
$splitPath = Join-Path $canonicalRoot $buildManifest.artifacts.split_onnx.path
$libraryPath = Join-Path $canonicalRoot $buildManifest.artifacts.android_library.path
$sourceHash = Get-Sha256 $sourcePath
$splitHash = Get-Sha256 $splitPath
$libraryHash = Get-Sha256 $libraryPath
if ($sourceHash -ne $buildManifest.artifacts.source_onnx.sha256 -or
        $splitHash -ne $buildManifest.artifacts.split_onnx.sha256 -or
        $libraryHash -ne $buildManifest.artifacts.android_library.sha256) {
    throw "Canonical CS2 artifacts no longer match the build manifest"
}
if ($sourceHash -ne $numeric.artifacts.source_onnx.sha256 -or
        $splitHash -ne $numeric.artifacts.rewritten_onnx.sha256 -or
        $libraryHash -ne $numeric.artifacts.qnn_android_model_library.sha256) {
    throw "Phone HTP numeric report is bound to different CS2 artifacts"
}

$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
$canonicalNumericPath = Join-Path $canonicalRoot "numeric_contract.json"
$numericTemporary = "$canonicalNumericPath.tmp"
[System.IO.File]::WriteAllText(
    $numericTemporary,
    ([System.IO.File]::ReadAllText($numericReportPath)),
    $utf8WithoutBom
)
Move-Item -LiteralPath $numericTemporary -Destination $canonicalNumericPath -Force

$releaseManifest = [ordered]@{
    schema = "visionforge-cs2-vombit-w8a16-release-v1"
    complete = $true
    integration_eligible = $true
    phone_htp_numeric_verified = $true
    commercial_distribution_review_required = $true
    commercial_release_eligible = $false
    promoted_at = (Get-Date).ToUniversalTime().ToString("o")
    source_onnx_sha256 = $sourceHash
    split_onnx_sha256 = $splitHash
    android_library_sha256 = $libraryHash
    build_manifest_sha256 = Get-Sha256 $buildManifestPath
    numeric_contract_sha256 = Get-Sha256 $canonicalNumericPath
}
$releasePath = Join-Path $canonicalRoot "release_manifest.json"
$releaseTemporary = "$releasePath.tmp"
[System.IO.File]::WriteAllText(
    $releaseTemporary,
    ($releaseManifest | ConvertTo-Json -Depth 4),
    $utf8WithoutBom
)
Move-Item -LiteralPath $releaseTemporary -Destination $releasePath -Force
Write-Output (
    "CS2_VOMBIT_W8A16_INTEGRATION_PROMOTED " +
    "library_sha256=$libraryHash release_manifest=$releasePath " +
    "commercial_release_eligible=false"
)
