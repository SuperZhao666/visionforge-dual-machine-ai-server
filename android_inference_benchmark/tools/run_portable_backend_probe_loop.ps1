[CmdletBinding()]
param(
    [string]$Serial = "emulator-5554",
    [ValidateRange(1, 64)]
    [int]$IterationsPerBackend = 16,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "../output/portable-backend-continuous"),
    [ValidateRange(60, 3600)]
    [int]$ProbeTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$adbCommand = Get-Command adb -ErrorAction Stop
$adbPath = $adbCommand.Source
$runner = "com.visionforge.mobile.test/com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation"
$backends = @("onnxruntime_cpu", "onnxruntime_nnapi")
$expectedExecutions = 4 * $IterationsPerBackend
$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$stopFile = Join-Path $resolvedOutputDirectory "STOP"
$summaryFile = Join-Path $resolvedOutputDirectory "probe-summary.jsonl"
$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
$failureBackoff = [System.Threading.ManualResetEventSlim]::new($false)
$consecutiveFailures = 0

[System.IO.Directory]::CreateDirectory($resolvedOutputDirectory) | Out-Null

function Write-SummaryRecord {
    param([hashtable]$Record)

    $json = $Record | ConvertTo-Json -Compress
    [System.IO.File]::AppendAllText(
        $summaryFile,
        $json + [Environment]::NewLine,
        $utf8WithoutBom)
}

function Invoke-PortableBackendProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Backend,
        [Parameter(Mandatory = $true)]
        [long]$Cycle
    )

    $temporaryTag = "probe-$PID-$Cycle-$Backend-$([Guid]::NewGuid().ToString('N'))"
    $standardOutputPath = Join-Path $resolvedOutputDirectory "$temporaryTag.stdout.tmp"
    $standardErrorPath = Join-Path $resolvedOutputDirectory "$temporaryTag.stderr.tmp"
    $process = $null
    $timedOut = $false
    try {
        $arguments = @(
            "-s", $Serial,
            "shell", "am", "instrument", "-w",
            "-e", "mode", "portable_backend_probe",
            "-e", "backendToken", $Backend,
            "-e", "iterations", [string]$IterationsPerBackend,
            $runner
        )
        $process = Start-Process `
            -FilePath $adbPath `
            -ArgumentList $arguments `
            -NoNewWindow `
            -PassThru `
            -RedirectStandardOutput $standardOutputPath `
            -RedirectStandardError $standardErrorPath
        # Windows PowerShell 5.1 can leave Start-Process.ExitCode unset when
        # redirected child processes finish before their native handle is
        # materialized. Acquire it before waiting so a successful probe is not
        # misclassified as exit_code=null.
        $null = $process.Handle
        $timedOut = -not $process.WaitForExit($ProbeTimeoutSeconds * 1000)
        if ($timedOut) {
            try {
                $process.Kill()
                $process.WaitForExit()
            }
            catch {
                # The process may have exited between WaitForExit and Kill.
            }
        }
        else {
            # The parameterless wait drains redirected-stream completion
            # notifications; Refresh then makes the native exit code
            # authoritative for marker checks.
            $process.WaitForExit()
            $process.Refresh()
        }
        $completedExitCode = if ($timedOut) { -2 } else { $process.ExitCode }

        $output = @()
        if ([System.IO.File]::Exists($standardOutputPath)) {
            $output += [System.IO.File]::ReadAllLines($standardOutputPath)
        }
        if ([System.IO.File]::Exists($standardErrorPath)) {
            $output += [System.IO.File]::ReadAllLines($standardErrorPath)
        }
        if ($timedOut) {
            $output += "VISIONFORGE_PORTABLE_PROBE_TIMEOUT backend=$Backend timeout_seconds=$ProbeTimeoutSeconds"
        }
        return [pscustomobject]@{
            Output = $output
            ExitCode = $completedExitCode
            TimedOut = $timedOut
        }
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
        foreach ($temporaryPath in @($standardOutputPath, $standardErrorPath)) {
            if ([System.IO.File]::Exists($temporaryPath)) {
                [System.IO.File]::Delete($temporaryPath)
            }
        }
    }
}

Write-SummaryRecord @{
    event = "portable_backend_probe_loop_started"
    timestamp = [DateTimeOffset]::Now.ToString("o")
    pid = $PID
    serial = $Serial
    iterations_per_backend = $IterationsPerBackend
    expected_executions_per_backend = $expectedExecutions
    probe_timeout_seconds = $ProbeTimeoutSeconds
    stop_file = $stopFile
}

$cycle = 0L
while (-not [System.IO.File]::Exists($stopFile)) {
    $cycle++
    foreach ($backend in $backends) {
        if ([System.IO.File]::Exists($stopFile)) { break }

        $started = [DateTimeOffset]::Now
        $output = @()
        $exitCode = -1
        $failureType = "none"
        try {
            $probe = Invoke-PortableBackendProbe -Backend $backend -Cycle $cycle
            $output = @($probe.Output)
            $exitCode = $probe.ExitCode
            if ($probe.TimedOut) {
                $failureType = "instrumentation_timeout"
                Write-SummaryRecord @{
                    event = "portable_backend_probe_instrumentation_timeout"
                    timestamp = [DateTimeOffset]::Now.ToString("o")
                    cycle = $cycle
                    backend = $backend
                    timeout_seconds = $ProbeTimeoutSeconds
                }
            }
        }
        catch {
            $failureType = $_.Exception.GetType().Name
            $output = @($_.Exception.ToString())
        }
        $latestOutputFile = Join-Path $resolvedOutputDirectory "latest-$backend.txt"
        $outputText = (($output | ForEach-Object { [string]$_ }) `
                -join [Environment]::NewLine) + [Environment]::NewLine
        [System.IO.File]::WriteAllText(
            $latestOutputFile,
            $outputText,
            $utf8WithoutBom)

        $successMarker = "MOBILE_PORTABLE_BACKEND_PROBE_OK models=4 iterations=$IterationsPerBackend executions=$expectedExecutions backend=$backend"
        $succeeded = $exitCode -eq 0 -and ($output -contains $successMarker)
        if ($succeeded) {
            $consecutiveFailures = 0
        }
        else {
            $consecutiveFailures++
            if ($failureType -eq "none") {
                $failureType = "instrumentation_exit_or_marker_mismatch"
            }
        }
        Write-SummaryRecord @{
            event = $(if ($succeeded) {
                "portable_backend_probe_cycle_completed"
            } else {
                "portable_backend_probe_cycle_failed"
            })
            timestamp = [DateTimeOffset]::Now.ToString("o")
            cycle = $cycle
            backend = $backend
            iterations = $IterationsPerBackend
            executions = $(if ($succeeded) { $expectedExecutions } else { 0 })
            elapsed_millis = [long]([DateTimeOffset]::Now - $started).TotalMilliseconds
            exit_code = $exitCode
            failure_type = $failureType
            consecutive_failures = $consecutiveFailures
            latest_output = $latestOutputFile
        }

        if (-not $succeeded) {
            # Failure recovery belongs to the test harness, not inference
            # pacing. Successful rounds still start back-to-back with no FPS
            # cap, fixed frame period, or inter-round sleep.
            $failureExponent = [Math]::Min(5, $consecutiveFailures - 1)
            $recoveryDelayMillis = [long][Math]::Min(
                    30000,
                    1000 * [Math]::Pow(2, $failureExponent))
            Write-SummaryRecord @{
                event = "portable_backend_probe_recovery_deferred"
                timestamp = [DateTimeOffset]::Now.ToString("o")
                cycle = $cycle
                backend = $backend
                delay_millis = $recoveryDelayMillis
                consecutive_failures = $consecutiveFailures
                retry_forever_until_stop_file = $true
            }
            $failureBackoff.Wait([int]$recoveryDelayMillis) | Out-Null
        }
    }
}

$failureBackoff.Dispose()

Write-SummaryRecord @{
    event = "portable_backend_probe_loop_stopped"
    timestamp = [DateTimeOffset]::Now.ToString("o")
    pid = $PID
    serial = $Serial
    completed_cycles = $cycle
}
