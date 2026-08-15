param(
    [Parameter(Mandatory = $true)]
    [string]$Serial,
    [Parameter(Mandatory = $true)]
    [string]$MainApk,
    [Parameter(Mandatory = $true)]
    [string]$TestApk,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [int]$PollIntervalMillis = 5000
)

$ErrorActionPreference = "Stop"

if ($PollIntervalMillis -lt 1000) {
    throw "PollIntervalMillis must be at least 1000"
}

$adbPath = (Get-Command adb -ErrorAction Stop).Source
$resolvedMainApk = (Resolve-Path -LiteralPath $MainApk -ErrorAction Stop).Path
$resolvedTestApk = (Resolve-Path -LiteralPath $TestApk -ErrorAction Stop).Path
$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory
$logPath = Join-Path $resolvedOutputDirectory "package-guardian.jsonl"
$stopFile = Join-Path $resolvedOutputDirectory "stop-package-guardian"
$instrumentationComponent =
        "com.visionforge.mobile.test/com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation"
$stopSignal = [System.Threading.ManualResetEventSlim]::new($false)

function Write-GuardianEvent {
    param(
        [string]$Event,
        [hashtable]$Detail
    )

    $payload = [ordered]@{
        timestamp = [DateTimeOffset]::Now.ToString("o")
        event = $Event
        serial = $Serial
    }
    foreach ($entry in $Detail.GetEnumerator()) {
        $payload[$entry.Key] = $entry.Value
    }
    Add-Content -LiteralPath $logPath -Encoding utf8 `
            -Value ($payload | ConvertTo-Json -Compress -Depth 6)
}

function Invoke-AdbText {
    param([string[]]$Arguments)

    $output = @(& $adbPath @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "adb exit=$LASTEXITCODE output=$($output -join ' ')"
    }
    return $output -join "`n"
}

function Test-ProbePackagesReady {
    $instrumentation = Invoke-AdbText @(
        "-s", $Serial, "shell", "pm", "list", "instrumentation")
    if (-not $instrumentation.Contains($instrumentationComponent)) {
        return $false
    }
    $mainPath = Invoke-AdbText @(
        "-s", $Serial, "shell", "pm", "path", "com.visionforge.mobile")
    $testPath = Invoke-AdbText @(
        "-s", $Serial, "shell", "pm", "path", "com.visionforge.mobile.test")
    return $mainPath.Contains("package:") `
            -and $testPath.Contains("package:")
}

function Install-ProbePackages {
    $mainResult = Invoke-AdbText @(
        "-s", $Serial, "install", "-r", $resolvedMainApk)
    $testResult = Invoke-AdbText @(
        "-s", $Serial, "install", "-r", $resolvedTestApk)
    if (-not $mainResult.Contains("Success") -or -not $testResult.Contains("Success")) {
        throw "adb install did not report Success"
    }
    if (-not (Test-ProbePackagesReady)) {
        throw "probe instrumentation is still unavailable after install -r"
    }
}

Write-GuardianEvent "portable_backend_package_guardian_started" @{
    poll_interval_millis = $PollIntervalMillis
    main_apk = $resolvedMainApk
    test_apk = $resolvedTestApk
    install_semantics = "adb_install_r_only"
}

try {
    while (-not (Test-Path -LiteralPath $stopFile)) {
        try {
            if (-not (Test-ProbePackagesReady)) {
                Write-GuardianEvent "portable_backend_probe_packages_missing" @{
                    repair_started = $true
                }
                Install-ProbePackages
                Write-GuardianEvent "portable_backend_probe_packages_repaired" @{
                    repair_succeeded = $true
                    install_semantics = "adb_install_r_only"
                }
            }
        } catch {
            Write-GuardianEvent "portable_backend_probe_package_repair_failed" @{
                repair_succeeded = $false
                failure_type = $_.Exception.GetType().Name
                failure = $_.Exception.ToString()
            }
        }
        $null = $stopSignal.Wait($PollIntervalMillis)
    }
} finally {
    Write-GuardianEvent "portable_backend_package_guardian_stopped" @{
        stop_file_observed = (Test-Path -LiteralPath $stopFile)
    }
    $stopSignal.Dispose()
}
