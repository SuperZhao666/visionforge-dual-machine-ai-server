param(
    [Parameter(Mandatory = $true)][string]$QnnSdkRoot,
    [string]$ResultsDirectory = "android_inference_benchmark/qnn_workspace/device_bundle/device_results",
    [switch]$EnableOptrace
)

$ErrorActionPreference = "Stop"
$sdk = (Resolve-Path $QnnSdkRoot).Path
$results = (Resolve-Path $ResultsDirectory).Path
$profileViewer = Join-Path $sdk "bin/x86_64-windows-msvc/qnn-profile-viewer.exe"
$htpReader = Join-Path $sdk "lib/x86_64-windows-msvc/QnnHtpOptraceProfilingReader.dll"
foreach ($required in @($profileViewer, $htpReader)) {
    if (-not (Test-Path $required)) { throw "Required QAIRT profiling artifact missing: $required" }
}

$profile = Join-Path $results "qnn_measured_profiling.log"
if (-not (Test-Path $profile)) {
    throw "No measured HTP profiling log found. Run run_qnn_htp_adb.ps1 successfully first: $profile"
}
$reportDirectory = Join-Path $results "profile_report"
New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
$defaultCsv = Join-Path $reportDirectory "qnn_measured_default.csv"
$optraceOutput = Join-Path $reportDirectory "qnn_measured_htp_optrace.json"

& $profileViewer --input_log $profile --output $defaultCsv
if ($LASTEXITCODE -ne 0) { throw "QAIRT default profiling reader failed with exit code $LASTEXITCODE." }
$optraceGenerated = $false
if ($EnableOptrace) {
    $contextProfile = Join-Path $results "context/qnn-profiling-data_0.log"
    if (-not (Test-Path $contextProfile)) { throw "No HTP context profiling log found: $contextProfile" }
    & $profileViewer --input_log "$contextProfile,$profile" --reader $htpReader --output $optraceOutput
    if ($LASTEXITCODE -ne 0) { throw "QAIRT HTP Optrace profiling reader failed with exit code $LASTEXITCODE." }
    $optraceGenerated = $true
}

$identity = Join-Path $results "device_identity.json"
$summary = [ordered]@{
    measured_profile = (Resolve-Path $profile).Path
    default_csv = (Resolve-Path $defaultCsv).Path
    htp_optrace = if ($optraceGenerated) { (Resolve-Path $optraceOutput).Path } else { $null }
    device_identity = if (Test-Path $identity) { (Resolve-Path $identity).Path } else { $null }
    generated_at_utc = [DateTime]::UtcNow.ToString("o")
}
$summaryPath = Join-Path $reportDirectory "profile_artifacts.json"
[System.IO.File]::WriteAllText(
    $summaryPath,
    (($summary | ConvertTo-Json) + [Environment]::NewLine),
    [System.Text.UTF8Encoding]::new($false)
)
Write-Output "QNN_HTP_PROFILE_ANALYSIS_OK report=$reportDirectory"
