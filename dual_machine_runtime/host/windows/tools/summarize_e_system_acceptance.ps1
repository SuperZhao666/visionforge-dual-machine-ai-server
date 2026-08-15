[CmdletBinding()]
param(
    [string]$AcceptanceRoot = 'E:\Users\Administrator\Desktop\VFHost_E_Acceptance',
    [string]$EventPath = 'E:\Users\Administrator\AppData\Local\VisionForge\DualMachine\host-events.jsonl',
    [string]$HostExecutablePath = '',
    [string]$OfflineUserHivePath = 'E:\Users\Administrator\NTUSER.DAT',
    [string]$RunOnceValueName = 'VisionForgeHostEAcceptance',
    [string]$OutputDirectory = '',
    [int]$TailEvents = 4096
)

$ErrorActionPreference = 'Stop'

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $AcceptanceRoot 'analysis'
}
if (-not $HostExecutablePath) {
    $HostExecutablePath = Join-Path (Split-Path -Parent $AcceptanceRoot) 'VFHost.exe'
}

$expectedHashPath = Join-Path $AcceptanceRoot 'expected_sha256.txt'
$resultsRoot = Join-Path $AcceptanceRoot 'results'
$diagnosisJsonPath = Join-Path $OutputDirectory 'latest-diagnosis.json'
$diagnosisMarkdownPath = Join-Path $OutputDirectory 'latest-diagnosis.md'

function Read-JsonLines {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$Tail = 4096
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    $items = foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8 -Tail $Tail) {
        if (-not $line) { continue }
        try {
            $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            [pscustomobject]@{
                parse_error = $_.Exception.Message
                raw_line = $line
            }
        }
    }
    return @($items)
}

function Read-ExpectedHash {
    if (-not (Test-Path -LiteralPath $expectedHashPath -PathType Leaf)) {
        return $null
    }
    $value = (Get-Content -Raw -Encoding ASCII -LiteralPath $expectedHashPath).Trim()
    if ($value -match '^[0-9A-Fa-f]{64}$') {
        return $value.ToLowerInvariant()
    }
    return $value
}

function Get-FileSha256OrNull {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-FileLastWriteTimeOrNull {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    return (Get-Item -LiteralPath $Path).LastWriteTime
}

function Invoke-RegQueryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,
        [Parameter(Mandatory = $true)]
        [string]$ValueName
    )
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & reg.exe query $KeyPath /v $ValueName 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        exit_code = $exitCode
        output = ($output -join "`n")
        present = $exitCode -eq 0
    }
}

function Get-RunOnceState {
    $relativeKey = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $hkcuState = Invoke-RegQueryValue `
        -KeyPath "HKCU\$relativeKey" `
        -ValueName $RunOnceValueName
    if ($hkcuState.present) {
        return [ordered]@{
            source = 'HKCU'
            present = $true
            value_name = $RunOnceValueName
            raw = $hkcuState.output
        }
    }

    if (-not (Test-Path -LiteralPath $OfflineUserHivePath -PathType Leaf)) {
        return [ordered]@{
            source = 'offline_hive_missing'
            present = $false
            value_name = $RunOnceValueName
            raw = $hkcuState.output
        }
    }

    $mountName = "HKU\VF_E_SUMMARY_$PID"
    $loaded = $false
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $loadOutput = & reg.exe load $mountName $OfflineUserHivePath 2>&1
            $loadExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($loadExitCode -ne 0) {
            return [ordered]@{
                source = 'offline_hive_load_failed'
                present = $false
                value_name = $RunOnceValueName
                raw = ($loadOutput -join "`n")
            }
        }
        $loaded = $true
        $offlineState = Invoke-RegQueryValue `
            -KeyPath "$mountName\$relativeKey" `
            -ValueName $RunOnceValueName
        return [ordered]@{
            source = 'offline_hive'
            present = [bool]$offlineState.present
            value_name = $RunOnceValueName
            raw = $offlineState.output
        }
    } finally {
        if ($loaded) {
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            $previousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & reg.exe unload $mountName | Out-Null
            } finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
        }
    }
}

function Get-LatestResultDirectory {
    if (-not (Test-Path -LiteralPath $resultsRoot -PathType Container)) {
        return $null
    }
    return Get-ChildItem -LiteralPath $resultsRoot -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Read-ResultJson {
    param([string]$Directory)
    if (-not $Directory) { return $null }
    $path = Join-Path $Directory 'acceptance-result.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        return Get-Content -Raw -Encoding UTF8 -LiteralPath $path |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            status = 'parse_failed'
            failure_reason = $_.Exception.Message
            path = $path
        }
    }
}

function Get-LatestTrace {
    param([object[]]$Events)
    $validEvents = @($Events | Where-Object { $_.trace_id -and $_.timestamp_unix_ms })
    if ($validEvents.Count -eq 0) { return $null }
    $latestEvent = $validEvents |
        Sort-Object { [long]$_.timestamp_unix_ms } |
        Select-Object -Last 1
    $traceId = [string]$latestEvent.trace_id
    $traceEvents = @($validEvents | Where-Object { $_.trace_id -eq $traceId } |
        Sort-Object { [int]$_.sequence })
    if ($traceEvents.Count -eq 0) { return $null }
    return [pscustomobject]@{
        trace_id = $traceId
        build_sha256 = [string]$traceEvents[0].build_sha256
        first_timestamp_unix_ms = [long]$traceEvents[0].timestamp_unix_ms
        last_timestamp_unix_ms = [long]$traceEvents[-1].timestamp_unix_ms
        event_count = $traceEvents.Count
        events = $traceEvents
    }
}

function Find-LastEvent {
    param(
        [object[]]$Events,
        [string]$Name
    )
    return $Events | Where-Object event -eq $Name | Select-Object -Last 1
}

function Match-DetailValue {
    param(
        [string]$Detail,
        [string]$Key
    )
    if (-not $Detail) { return $null }
    $escaped = [regex]::Escape($Key)
    $match = [regex]::Match($Detail, "(?:^| )$escaped=([^ ]+)")
    if ($match.Success) { return $match.Groups[1].Value }
    return $null
}

function Get-AttemptSummary {
    param([object[]]$Events)
    $attemptIds = @($Events | Where-Object { $null -ne $_.attempt_id } |
        ForEach-Object { [int]$_.attempt_id } |
        Sort-Object -Unique)
    return @($attemptIds | ForEach-Object {
        $attemptId = $_
        $attemptEvents = @($Events | Where-Object { [int]$_.attempt_id -eq $attemptId })
        [ordered]@{
            attempt_id = $attemptId
            event_count = $attemptEvents.Count
            first_event = if ($attemptEvents.Count) { [string]$attemptEvents[0].event } else { $null }
            last_event = if ($attemptEvents.Count) { [string]$attemptEvents[-1].event } else { $null }
            direct_link = if ($attemptEvents.Count) {
                $event = Find-LastEvent $attemptEvents 'host_direct_link_bootstrap'
                if ($event) { [string]$event.detail } else { $null }
            } else { $null }
            dhcp = if ($attemptEvents.Count) {
                $event = Find-LastEvent $attemptEvents 'host_dhcp_bootstrap'
                if ($event) { [string]$event.detail } else { $null }
            } else { $null }
            failure = if ($attemptEvents.Count) {
                $event = $attemptEvents |
                    Where-Object { [string]$_.event -match 'failed|cancelled' } |
                    Select-Object -Last 1
                if ($event) { "$($event.event): $($event.detail)" } else { $null }
            } else { $null }
        }
    })
}

function Get-RootCause {
    param(
        [object]$Trace,
        [object]$LatestResult,
        [string]$ExpectedHash,
        [string]$HostExecutableHash,
        [object]$HostExecutableLastWriteTime,
        [object]$EventLogLastWriteTime
    )
    if (-not $Trace) {
        return [ordered]@{
            category = 'no_host_trace'
            summary = 'No Host trace was found in host-events.jsonl.'
            evidence = 'host-events.jsonl missing or empty'
        }
    }

    $events = @($Trace.events)
    $build = ([string]$Trace.build_sha256).ToLowerInvariant()
    if ($ExpectedHash -and $build -and $build -ne $ExpectedHash.ToLowerInvariant()) {
        if ($HostExecutableHash -and
                $HostExecutableHash.ToLowerInvariant() -eq $ExpectedHash.ToLowerInvariant() -and
                $null -ne $HostExecutableLastWriteTime -and
                $null -ne $EventLogLastWriteTime -and
                $EventLogLastWriteTime -lt $HostExecutableLastWriteTime) {
            return [ordered]@{
                category = 'no_fresh_trace_after_exe_update'
                summary = 'Expected Host EXE is present, but host-events.jsonl has not been updated since that EXE was copied. The newest available failure belongs to an older binary.'
                evidence = "trace_build=$build expected=$($ExpectedHash.ToLowerInvariant()) host_exe_last_write=$($HostExecutableLastWriteTime.ToString('o')) event_log_last_write=$($EventLogLastWriteTime.ToString('o'))"
            }
        }
        return [ordered]@{
            category = 'old_exe_or_wrong_binary'
            summary = 'Latest Host trace was produced by a binary whose SHA256 does not match expected_sha256.txt.'
            evidence = "trace_build=$build expected=$($ExpectedHash.ToLowerInvariant())"
        }
    }

    $streamStarted = Find-LastEvent $events 'host_stream_started'
    if ($streamStarted) {
        $qualityCount = @($events | Where-Object event -eq 'host_cat6_quality').Count
        return [ordered]@{
            category = 'stream_started'
            summary = 'Host reached the stream stage; inspect quality events for stability and loss.'
            evidence = "quality_event_count=$qualityCount stream_detail=$($streamStarted.detail)"
        }
    }

    $directLinkFailed = $events |
        Where-Object { $_.event -eq 'host_cat6_bootstrap_failed' -and
            [string]$_.detail -match 'no_wired_adapter|no_unnumbered_wired_adapter' } |
        Select-Object -Last 1
    if ($directLinkFailed) {
        return [ordered]@{
            category = 'no_usable_wired_adapter'
            summary = 'The Host could not find an operational physical Ethernet adapter for CAT6.'
            evidence = [string]$directLinkFailed.detail
        }
    }

    $dhcpFailure = $events |
        Where-Object { $_.event -eq 'host_dhcp_bootstrap' -and
            [string]$_.detail -match 'code=10049|hex=0x2741' } |
        Select-Object -Last 1
    if ($dhcpFailure) {
        $stage = Match-DetailValue ([string]$dhcpFailure.detail) 'startup_stage'
        $matchCount = Match-DetailValue ([string]$dhcpFailure.detail) 'interface_match_count'
        $backendEvents = @($events | Where-Object {
            $_.event -match 'host_cat6_bootstrap_diagnostic|host_direct_link_bootstrap' -and
            [string]$_.detail -match 'persistent_netsh'
        })
        $backendEvidence = if ($backendEvents.Count -gt 0) {
            'persistent_netsh_seen=1'
        } else {
            'persistent_netsh_seen=0'
        }
        return [ordered]@{
            category = 'dhcp_bind_10049'
            summary = 'DHCP server could not bind the configured CAT6 host address; this fails before phone handshake and before video streaming.'
            evidence = "startup_stage=$stage interface_match_count=$matchCount $backendEvidence detail=$($dhcpFailure.detail)"
        }
    }

    $androidSummary = if ($LatestResult) { $LatestResult.android_network_summary } else { $null }
    if ($androidSummary -and
            [string]$androidSummary.eth0_state -eq 'UP' -and
            $androidSummary.eth0_has_ipv4 -eq $false) {
        $dhcpEvent = Find-LastEvent $events 'host_dhcp_bootstrap'
        $dhcpDetail = if ($dhcpEvent) { [string]$dhcpEvent.detail } else { 'missing' }
        return [ordered]@{
            category = 'android_eth0_no_ipv4'
            summary = 'Android sees the physical eth0 link, but it has no app-usable IPv4 network, so the phone cannot bind the fixed CAT6 receiver or send the CAT6-ready heartbeat.'
            evidence = "eth0_state=$($androidSummary.eth0_state) eth0_has_ipv4=$($androidSummary.eth0_has_ipv4) ethernet_network_agent=$($androidSummary.ethernet_network_agent) tethering_interface=$($androidSummary.tethering_interface) tethering_interface_mode=$($androidSummary.tethering_interface_mode) dhcp=$dhcpDetail"
        }
    }

    if ($androidSummary -and
            $androidSummary.eth0_has_ipv4 -eq $true -and
            $androidSummary.package_debuggable -eq $true) {
        $dhcpEvent = Find-LastEvent $events 'host_dhcp_bootstrap'
        $dhcpDetail = if ($dhcpEvent) { [string]$dhcpEvent.detail } else { 'missing' }
        $receivedPackets = if ($dhcpEvent) {
            Match-DetailValue ([string]$dhcpEvent.detail) 'received_packets'
        } else {
            $null
        }
        if ($dhcpDetail -match 'failure_stage=mobile_ready_timeout') {
            return [ordered]@{
                category = 'android_debug_apk_authorization_closed'
                summary = 'Android has the fixed CAT6 IPv4 address, but the installed Android package is debuggable. Formal authorization stays fail-closed without release security material, so the receiver/ready path does not open.'
                evidence = "eth0_has_ipv4=$($androidSummary.eth0_has_ipv4) package_version=$($androidSummary.package_version_name) package_debuggable=$($androidSummary.package_debuggable) authorization_security_failed=$($androidSummary.authorization_security_failed) received_packets=$receivedPackets dhcp=$dhcpDetail"
            }
        }
    }

    $lastFailure = $events |
        Where-Object { [string]$_.event -match 'failed|cancelled' } |
        Select-Object -Last 1
    if ($lastFailure) {
        return [ordered]@{
            category = 'host_failure'
            summary = "Latest Host failure event is $($lastFailure.event)."
            evidence = [string]$lastFailure.detail
        }
    }

    $lastEvent = $events | Select-Object -Last 1
    return [ordered]@{
        category = 'incomplete_or_unknown'
        summary = 'Latest Host trace has no stream start and no recognized hard failure.'
        evidence = "last_event=$($lastEvent.event) detail=$($lastEvent.detail)"
    }
}

function Get-ProgressTail {
    param([string]$Name)
    if (-not (Test-Path -LiteralPath $resultsRoot -PathType Container)) {
        return @()
    }
    $latest = Get-ChildItem -LiteralPath $resultsRoot -Recurse -File -Filter $Name |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $latest) { return @() }
    return @(Read-JsonLines -Path $latest.FullName -Tail 40)
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$expectedHash = Read-ExpectedHash
$hostExeHash = Get-FileSha256OrNull -Path $HostExecutablePath
$hostExeLastWriteTime = Get-FileLastWriteTimeOrNull -Path $HostExecutablePath
$eventLogLastWriteTime = Get-FileLastWriteTimeOrNull -Path $EventPath
$runOnceState = Get-RunOnceState
$events = Read-JsonLines -Path $EventPath -Tail $TailEvents
$latestTrace = Get-LatestTrace -Events $events
$latestResultDirectory = Get-LatestResultDirectory
$latestResult = if ($latestResultDirectory) {
    Read-ResultJson -Directory $latestResultDirectory.FullName
} else {
    $null
}
$rootCause = Get-RootCause `
    -Trace $latestTrace `
    -LatestResult $latestResult `
    -ExpectedHash $expectedHash `
    -HostExecutableHash $hostExeHash `
    -HostExecutableLastWriteTime $hostExeLastWriteTime `
    -EventLogLastWriteTime $eventLogLastWriteTime
$attempts = if ($latestTrace) { Get-AttemptSummary -Events $latestTrace.events } else { @() }
$wrapperProgressTail = Get-ProgressTail -Name 'wrapper-progress.jsonl'
$harnessProgressTail = Get-ProgressTail -Name 'acceptance-progress.jsonl'

$diagnosis = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    acceptance_root = $AcceptanceRoot
    host_executable_path = $HostExecutablePath
    host_executable_sha256 = $hostExeHash
    host_executable_last_write_time = if ($null -ne $hostExeLastWriteTime) {
        $hostExeLastWriteTime.ToString('o')
    } else {
        $null
    }
    host_executable_matches_expected = if ($expectedHash -and $hostExeHash) {
        $expectedHash.ToLowerInvariant() -eq $hostExeHash.ToLowerInvariant()
    } else {
        $false
    }
    run_once = $runOnceState
    expected_sha256 = $expectedHash
    expected_hash_path = $expectedHashPath
    event_path = $EventPath
    event_log_last_write_time = if ($null -ne $eventLogLastWriteTime) {
        $eventLogLastWriteTime.ToString('o')
    } else {
        $null
    }
    event_count_loaded = $events.Count
    latest_result_directory = if ($latestResultDirectory) {
        $latestResultDirectory.FullName
    } else {
        $null
    }
    latest_result_status = if ($latestResult) { [string]$latestResult.status } else { $null }
    latest_result_failure_reason = if ($latestResult) { [string]$latestResult.failure_reason } else { $null }
    latest_trace = if ($latestTrace) {
        [ordered]@{
            trace_id = $latestTrace.trace_id
            build_sha256 = $latestTrace.build_sha256
            event_count = $latestTrace.event_count
            first_timestamp_unix_ms = $latestTrace.first_timestamp_unix_ms
            last_timestamp_unix_ms = $latestTrace.last_timestamp_unix_ms
            first_event = [string]$latestTrace.events[0].event
            last_event = [string]$latestTrace.events[-1].event
        }
    } else {
        $null
    }
    root_cause = $rootCause
    attempt_summary = $attempts
    wrapper_progress_tail = $wrapperProgressTail
    harness_progress_tail = $harnessProgressTail
}

$diagnosis | ConvertTo-Json -Depth 12 |
    Set-Content -LiteralPath $diagnosisJsonPath -Encoding UTF8

$markdown = New-Object System.Collections.Generic.List[string]
$markdown.Add('# VF Host E-system Diagnosis')
$markdown.Add('')
$markdown.Add("- Generated: $($diagnosis.generated_at)")
$markdown.Add("- Acceptance root: $AcceptanceRoot")
$markdown.Add("- Expected SHA256: $expectedHash")
$markdown.Add("- Host EXE: $HostExecutablePath")
$markdown.Add("- Host EXE SHA256: $hostExeHash")
$markdown.Add("- Host EXE matches expected: $($diagnosis.host_executable_matches_expected)")
$markdown.Add("- RunOnce present: $($runOnceState.present) via $($runOnceState.source)")
$markdown.Add("- Latest result: $($diagnosis.latest_result_status)")
if ($diagnosis.latest_result_failure_reason) {
    $markdown.Add("- Latest result failure: $($diagnosis.latest_result_failure_reason)")
}
if ($latestTrace) {
    $markdown.Add("- Latest trace: $($latestTrace.trace_id)")
    $markdown.Add("- Latest trace build: $($latestTrace.build_sha256)")
    $markdown.Add("- Latest trace events: $($latestTrace.event_count)")
    $markdown.Add("- Latest trace last event: $($latestTrace.events[-1].event)")
} else {
    $markdown.Add('- Latest trace: missing')
}
$markdown.Add('')
$markdown.Add('## Root Cause')
$markdown.Add('')
$markdown.Add("- Category: $($rootCause.category)")
$markdown.Add("- Summary: $($rootCause.summary)")
$markdown.Add("- Evidence: $($rootCause.evidence)")
$markdown.Add('')
$markdown.Add('## Attempts')
$markdown.Add('')
if ($attempts.Count -eq 0) {
    $markdown.Add('- No attempts found.')
} else {
    foreach ($attempt in $attempts) {
        $markdown.Add("- attempt=$($attempt.attempt_id) first=$($attempt.first_event) last=$($attempt.last_event)")
        if ($attempt.failure) {
            $markdown.Add("  failure=$($attempt.failure)")
        }
    }
}
$markdown.Add('')
$markdown.Add('## Evidence Files')
$markdown.Add('')
$markdown.Add("- JSON: $diagnosisJsonPath")
$markdown.Add("- Markdown: $diagnosisMarkdownPath")
if ($latestResultDirectory) {
    $markdown.Add("- Latest acceptance directory: $($latestResultDirectory.FullName)")
}
$markdown | Set-Content -LiteralPath $diagnosisMarkdownPath -Encoding UTF8

[pscustomobject]@{
    Status = 'written'
    RootCause = $rootCause.category
    DiagnosisJson = $diagnosisJsonPath
    DiagnosisMarkdown = $diagnosisMarkdownPath
}
