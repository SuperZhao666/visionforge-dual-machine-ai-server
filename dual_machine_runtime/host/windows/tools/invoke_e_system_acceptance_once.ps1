[CmdletBinding()]
param(
    [switch]$SkipRestartForTesting
)

$ErrorActionPreference = 'Stop'
Add-Type -Namespace VisionForgeAcceptance -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern uint SetThreadExecutionState(uint esFlags);
'@
# Keep the display awake for the whole acceptance window. A DPMS-sleeping
# monitor makes display enumeration come back empty on this machine, which
# used to hang the run on a modal box (E-system acceptance #6).
[void][VisionForgeAcceptance.NativeMethods]::SetThreadExecutionState(0x80000003)
$harnessPath = Join-Path $PSScriptRoot 'run_e_system_acceptance.ps1'
$expectedHashPath = Join-Path $PSScriptRoot 'expected_sha256.txt'
$wrapperStartedAt = Get-Date
$wrapperRunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$wrapperRunDirectory = Join-Path $PSScriptRoot ('results\wrapper_run_' + $wrapperRunId)
$wrapperProgressPath = Join-Path $wrapperRunDirectory 'wrapper-progress.jsonl'
$wrapperResultPath = Join-Path $wrapperRunDirectory 'acceptance-wrapper-result.json'
$wrapperFailure = $null
$wrapperFailurePath = $null
$identityWaitNote = 'not_attempted'

function Write-WrapperProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [string]$Status = 'ok',
        [string]$Detail = ''
    )
    try {
        if (-not (Test-Path -LiteralPath $wrapperRunDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $wrapperRunDirectory -Force | Out-Null
        }
        $event = [ordered]@{
            timestamp = (Get-Date).ToString('o')
            stage = $Stage
            status = $Status
            detail = $Detail
            harness_path = $harnessPath
            expected_hash_path = $expectedHashPath
        }
        $event | ConvertTo-Json -Compress -Depth 4 |
            Add-Content -LiteralPath $wrapperProgressPath -Encoding UTF8
    } catch {
        # The wrapper must continue even if its own diagnostic file cannot be written.
    }
}

Write-WrapperProgress -Stage 'wrapper_started'

function Wait-NetworkIdentityStable {
    # The dynamic machine-identity tool on this installation (scheduled task
    # NoName_AutoStart, logon trigger) re-applies its identity in TWO waves
    # after interactive logon: the MAC is randomized early, and minutes later a
    # manual 10.57.49.x alias is written with "set address", which WIPES every
    # other address on the adapter. The 2026-07-25 acceptance runs #2-#4 were
    # all lost to that second wave deleting the freshly provisioned 10.57.23.1
    # mid-run (DHCP bind 10049 / heartbeat loss). Do not trust a short quiet
    # window: only proceed after the tool's alias has been observed AND the
    # identity has then stayed unchanged, or after a long no-change window.
    param(
        [int]$StablePolls = 5,
        [int]$PollIntervalSeconds = 3,
        [int]$MaximumWaitSeconds = 420,
        [int]$NoAliasStablePolls = 20
    )
    $deadline = (Get-Date).AddSeconds($MaximumWaitSeconds)
    $lastFingerprint = $null
    $stableCount = 0
    $sawIdentityToolAlias = $false
    while ((Get-Date) -lt $deadline) {
        $fingerprint = ''
        try {
            $adapters = Get-NetAdapter -Physical -ErrorAction Stop
            $parts = foreach ($adapter in $adapters) {
                $addresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
                    -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.IPAddress }
                '{0}|{1}|{2}' -f $adapter.ifIndex, $adapter.MacAddress, `
                    (($addresses | Sort-Object) -join ',')
            }
            $fingerprint = ($parts | Sort-Object) -join ';'
        } catch {
            $fingerprint = "query_failed:$($_.Exception.Message)"
        }
        if ($fingerprint -match '10\.57\.(4[0-9]|[5-9][0-9])\.' -and
            $fingerprint -notmatch '10\.57\.23\.') {
            $sawIdentityToolAlias = $true
        }
        if ($fingerprint -eq $lastFingerprint) {
            $stableCount += 1
            # After the identity tool's alias has been observed, a short quiet
            # window is enough; without it, demand a long no-change window.
            $requiredPolls = $NoAliasStablePolls
            if ($sawIdentityToolAlias) { $requiredPolls = $StablePolls }
            if ($stableCount -ge $requiredPolls) {
                return [pscustomobject]@{
                    Settled = $true
                    SawIdentityToolAlias = $sawIdentityToolAlias
                    Fingerprint = $fingerprint
                }
            }
        } else {
            $stableCount = 0
            $lastFingerprint = $fingerprint
        }
        Start-Sleep -Seconds $PollIntervalSeconds
    }
    return [pscustomobject]@{
        Settled = $false
        SawIdentityToolAlias = $sawIdentityToolAlias
        Fingerprint = $lastFingerprint
    }
}

try {
    if (-not (Test-Path -LiteralPath $harnessPath -PathType Leaf)) {
        throw "Acceptance harness not found: $harnessPath"
    }
    if (-not (Test-Path -LiteralPath $expectedHashPath -PathType Leaf)) {
        throw "Expected-hash file not found: $expectedHashPath"
    }
    Write-WrapperProgress -Stage 'inputs_verified'

    $expectedHash = (Get-Content -Raw -Encoding ASCII -LiteralPath $expectedHashPath).Trim()
    if ($expectedHash -notmatch '^[0-9A-Fa-f]{64}$') {
        throw "Expected-hash file is invalid: $expectedHashPath"
    }
    Write-WrapperProgress -Stage 'expected_hash_loaded' -Detail $expectedHash

    Write-WrapperProgress -Stage 'identity_wait_started'
    $identityWait = Wait-NetworkIdentityStable
    $identityWaitNote = "settled=$($identityWait.Settled) " +
        "identity_tool_alias_seen=$($identityWait.SawIdentityToolAlias) " +
        "fingerprint=$($identityWait.Fingerprint)"
    Write-WrapperProgress -Stage 'identity_wait_finished' -Detail $identityWaitNote
    if (-not $identityWait.Settled) {
        # Continue even without a settled identity: the harness still records
        # full failure evidence, which beats never running at all.
        Write-Warning "Network identity did not settle in time; continuing. $identityWaitNote"
    }

    # The phone loses its CAT6 lease while the PC reboots. Give the operator a
    # short, visible window to replug the phone so its DHCP retries land inside
    # the Host bootstrap that starts right after this pause.
    try {
        Write-WrapperProgress -Stage 'operator_replug_prompt_started'
        & "$env:SystemRoot\System32\msg.exe" '*' /TIME:25 `
            'VF 验收即将开始：请现在把手机从扩展坞拔下再插回一次，然后不要碰电脑。' | Out-Null
    } catch {
        Write-WrapperProgress -Stage 'operator_replug_prompt_failed' `
            -Status 'warning' -Detail $_.Exception.Message
        Write-Host 'VF acceptance: replug the phone USB-C now, then hands off.'
    }
    Start-Sleep -Seconds 25
    Write-WrapperProgress -Stage 'operator_replug_window_finished'

    Write-WrapperProgress -Stage 'harness_started'
    & $harnessPath `
        -ExpectedSha256 $expectedHash `
        -MaximumRuntimeSeconds 300 `
        -MinimumQualitySamples 10
    Write-WrapperProgress -Stage 'harness_finished'
} catch {
    $wrapperFailure = $_.Exception.ToString()
    $failure = [ordered]@{
        schema_version = 1
        status = 'wrapper_failed'
        failure_reason = $wrapperFailure
        started_at = $wrapperStartedAt.ToString('o')
        finished_at = (Get-Date).ToString('o')
        harness_path = $harnessPath
        expected_hash_path = $expectedHashPath
        identity_wait = $identityWaitNote
        wrapper_progress_path = $wrapperProgressPath
    }
    $candidateFailureDirectories = @(
        $wrapperRunDirectory,
        (Join-Path $PSScriptRoot ('results\wrapper_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
        (Join-Path $env:TEMP 'VFHost_E_Acceptance_wrapper_failure')
    )
    foreach ($directory in $candidateFailureDirectories) {
        try {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            $wrapperFailurePath = Join-Path $directory 'acceptance-result.json'
            $failure | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath $wrapperFailurePath -Encoding UTF8
            if ($wrapperFailurePath -ne $wrapperResultPath) {
                $failure | ConvertTo-Json -Depth 4 |
                    Set-Content -LiteralPath $wrapperResultPath -Encoding UTF8
            }
            break
        } catch {
            $wrapperFailurePath = $null
        }
    }
    Write-WrapperProgress -Stage 'wrapper_failed' -Status 'failed' `
        -Detail $wrapperFailure
} finally {
    if (-not $SkipRestartForTesting) {
        try {
            Write-WrapperProgress -Stage 'restart_schedule_started'
            $restartProcess = Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" `
                -ArgumentList '/r', '/t', '30', '/c',
                    'VF Host E-system acceptance finished; returning to the default Windows installation.' `
                -WindowStyle Hidden -Wait -PassThru
            if ($restartProcess.ExitCode -ne 0) {
                throw "shutdown.exe exited with code $($restartProcess.ExitCode)"
            }
            Write-WrapperProgress -Stage 'restart_schedule_finished'
        } catch {
            try {
                & "$env:SystemRoot\System32\shutdown.exe" /r /t 30 /c `
                    'VF Host E-system acceptance finished; returning to the default Windows installation.'
                if ($LASTEXITCODE -ne 0) {
                    throw "shutdown.exe exited with code $LASTEXITCODE"
                }
                Write-WrapperProgress -Stage 'restart_schedule_finished' `
                    -Detail 'fallback_shutdown_command'
            } catch {
                Write-WrapperProgress -Stage 'restart_schedule_failed' `
                    -Status 'failed' -Detail $_.Exception.ToString()
                if ($wrapperFailure) {
                    $wrapperFailure += "`nRestart scheduling also failed: $($_.Exception)"
                } else {
                    $wrapperFailure = "Restart scheduling failed: $($_.Exception)"
                }
            }
        }
    } else {
        Write-WrapperProgress -Stage 'restart_skipped' -Detail 'SkipRestartForTesting'
    }
}

if ($wrapperFailure) {
    throw "VF Host one-time acceptance failed. evidence=$wrapperFailurePath detail=$wrapperFailure"
}

$success = [ordered]@{
    schema_version = 1
    status = 'wrapper_finished'
    started_at = $wrapperStartedAt.ToString('o')
    finished_at = (Get-Date).ToString('o')
    harness_path = $harnessPath
    expected_hash_path = $expectedHashPath
    identity_wait = $identityWaitNote
    wrapper_progress_path = $wrapperProgressPath
}
$success | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $wrapperResultPath -Encoding UTF8
