[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSha256,
    [ValidateRange(30, 600)]
    [int]$MaximumRuntimeSeconds = 150,
    [ValidateRange(2, 100)]
    [int]$MinimumQualitySamples = 10,
    [string]$HostExecutablePath = '',
    [string]$ResultRoot = '',
    [string]$AdbPath = '',
    [string]$AndroidDeviceSerial = '',
    [string]$AndroidPackageName = 'com.visionforge.mobile',
    [switch]$RestartWhenFinished
)

$ErrorActionPreference = 'Stop'
$expectedHash = $ExpectedSha256.ToUpperInvariant()
$desktop = [Environment]::GetFolderPath('Desktop')
$hostExe = if ($HostExecutablePath) {
    [IO.Path]::GetFullPath($HostExecutablePath)
} else {
    Join-Path $desktop 'VFHost.exe'
}
$acceptanceRoot = Join-Path $desktop 'VFHost_E_Acceptance'
$effectiveResultRoot = if ($ResultRoot) {
    [IO.Path]::GetFullPath($ResultRoot)
} else {
    Join-Path $acceptanceRoot 'results'
}
$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$resultDirectory = Join-Path $effectiveResultRoot $runId
$eventPath = Join-Path $env:LOCALAPPDATA 'VisionForge\DualMachine\host-events.jsonl'
$resultPath = Join-Path $resultDirectory 'acceptance-result.json'
$progressPath = Join-Path $resultDirectory 'acceptance-progress.jsonl'
$transcriptPath = Join-Path $resultDirectory 'acceptance-transcript.txt'
$networkPath = Join-Path $resultDirectory 'network-snapshot.txt'
$androidNetworkPath = Join-Path $resultDirectory 'android-network-snapshot.txt'
$eventSnapshotPath = Join-Path $resultDirectory 'filtered-events.jsonl'
$emergencySnapshotPath = Join-Path $resultDirectory 'emergency-events.log'
$metricsSnapshotPath = Join-Path $resultDirectory 'host-metrics-tail.csv'
$hostProcess = $null
$traceId = $null
$status = 'failed'
$failureReason = $null
$startedAt = Get-Date
$eventNotBeforeUnixMs = ([DateTimeOffset]$startedAt).ToUnixTimeMilliseconds() - 1000
$hardFailureEventPattern = '^host_(?:runtime_initialization_failed|cat6_bootstrap_failed|worker_exception|display_refresh_failed|firewall_health_failed)$'
$minimumPublishedFrameDelta = 500L
$maximumQualityGapMs = 15000L
$maximumQualityAgeMs = 10000L
$maximumEventTailLines = 4096
$events = @()

function Read-AcceptanceEvents {
    if (-not (Test-Path -LiteralPath $eventPath -PathType Leaf)) {
        return @()
    }
    # Host JSONL is always UTF-8. Windows PowerShell 5.1 otherwise decodes a
    # BOM-less file with the active ANSI code page and corrupts Chinese native
    # error messages in the acceptance report.
    $parsed = foreach ($line in Get-Content -LiteralPath $eventPath -Encoding UTF8 `
            -Tail $maximumEventTailLines -ErrorAction SilentlyContinue) {
        try {
            $event = $line | ConvertFrom-Json -ErrorAction Stop
            if ($event.build_sha256 -ieq $expectedHash -and
                [long]$event.timestamp_unix_ms -ge $eventNotBeforeUnixMs) {
                $event
            }
        } catch {
            # The final JSONL line may be observed while the Host is flushing it.
        }
    }
    if ($traceId) {
        return @($parsed | Where-Object trace_id -eq $traceId)
    }
    return @($parsed)
}

function Read-PublishedFrames([object]$qualityEvent) {
    if ($null -eq $qualityEvent) { return 0L }
    $match = [regex]::Match([string]$qualityEvent.detail, '(?:^| )published_frames=(\d+)')
    if (-not $match.Success) { return 0L }
    return [long]$match.Groups[1].Value
}

function Measure-QualityProgress([object[]]$qualityEvents, [int]$requiredSamples) {
    $window = @($qualityEvents | Select-Object -Last $requiredSamples)
    if ($window.Count -lt $requiredSamples) {
        return [pscustomobject]@{
            is_sustained = $false
            frame_delta = 0L
            duration_ms = 0L
            maximum_gap_ms = 0L
            newest_age_ms = [long]::MaxValue
            monotonically_increasing = $false
            link_healthy = $false
        }
    }
    $firstFrames = Read-PublishedFrames $window[0]
    $lastFrames = Read-PublishedFrames $window[-1]
    $monotonic = $true
    $maximumGap = 0L
    for ($index = 1; $index -lt $window.Count; ++$index) {
        $previousFrames = Read-PublishedFrames $window[$index - 1]
        $currentFrames = Read-PublishedFrames $window[$index]
        if ($currentFrames -le $previousFrames) { $monotonic = $false }
        $gap = [long]$window[$index].timestamp_unix_ms -
            [long]$window[$index - 1].timestamp_unix_ms
        if ($gap -gt $maximumGap) { $maximumGap = $gap }
    }
    $duration = [long]$window[-1].timestamp_unix_ms - [long]$window[0].timestamp_unix_ms
    $newestAge = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -
        [long]$window[-1].timestamp_unix_ms
    $frameDelta = $lastFrames - $firstFrames
    $lastDetail = [string]$window[-1].detail
    $linkHealthy = $lastDetail -match '(?:^| )loss=0(?: |$)' -and
        $lastDetail -match '(?:^| )mobile_reachable=1(?: |$)'
    $sustained = $monotonic -and $frameDelta -ge $minimumPublishedFrameDelta -and
        $maximumGap -le $maximumQualityGapMs -and
        $newestAge -ge 0 -and $newestAge -le $maximumQualityAgeMs -and $linkHealthy
    return [pscustomobject]@{
        is_sustained = $sustained
        frame_delta = $frameDelta
        duration_ms = $duration
        maximum_gap_ms = $maximumGap
        newest_age_ms = $newestAge
        monotonically_increasing = $monotonic
        link_healthy = $linkHealthy
    }
}

function Get-PhysicalEthernetState {
    $adapters = @(Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.HardwareInterface -and [string]$_.MediaType -eq '802.3' } |
        Sort-Object InterfaceGuid)
    return @($adapters | ForEach-Object {
        $adapter = $_
        $interface = Get-NetIPInterface -AddressFamily IPv4 `
            -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 `
            -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            Sort-Object IPAddress |
            ForEach-Object {
                [ordered]@{
                    ip_address = $_.IPAddress
                    prefix_length = $_.PrefixLength
                    prefix_origin = [string]$_.PrefixOrigin
                    suffix_origin = [string]$_.SuffixOrigin
                    skip_as_source = $_.SkipAsSource
                }
            })
        $gateways = @(Get-NetRoute -AddressFamily IPv4 `
            -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' `
            -ErrorAction SilentlyContinue |
            Sort-Object NextHop, RouteMetric |
            ForEach-Object {
                [ordered]@{
                    next_hop = $_.NextHop
                    route_metric = $_.RouteMetric
                    policy_store = [string]$_.PolicyStore
                }
            })
        $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 `
            -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            ForEach-Object ServerAddresses)
        [ordered]@{
            interface_guid = [string]$adapter.InterfaceGuid
            interface_index = $adapter.ifIndex
            name = $adapter.Name
            description = $adapter.InterfaceDescription
            mac_address = $adapter.MacAddress
            status = [string]$adapter.Status
            dhcp = if ($interface) { [string]$interface.Dhcp } else { $null }
            interface_metric = if ($interface) { $interface.InterfaceMetric } else { $null }
            ipv4_addresses = $addresses
            default_gateways = $gateways
            dns_servers = $dns
        }
    })
}

function Resolve-AdbPath {
    param([string]$RequestedPath)
    $candidates = @()
    if ($RequestedPath) { $candidates += $RequestedPath }
    if ($env:VISIONFORGE_ADB) { $candidates += $env:VISIONFORGE_ADB }

    $workspaceRoot = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\..\..\..'))
    $candidates += (Join-Path $workspaceRoot '.android-sdk\platform-tools\adb.exe')

    $pathCommand = Get-Command adb -ErrorAction SilentlyContinue
    if ($pathCommand) { $candidates += $pathCommand.Source }

    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        $fullPath = [IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            return $fullPath
        }
    }
    return $null
}

function Resolve-AdbSelector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Adb,
        [string]$RequestedSerial = ''
    )
    if ($RequestedSerial) {
        return [pscustomobject]@{
            status = 'selected_by_serial'
            selector = @('-s', $RequestedSerial)
            serial = $RequestedSerial
            transport_id = $null
            devices_output = $null
        }
    }

    $devicesOutput = (& $Adb devices -l 2>&1) -join [Environment]::NewLine
    $devices = @()
    foreach ($line in ($devicesOutput -split "`r?`n")) {
        if ($line -notmatch '\sdevice(?:\s|$)') { continue }
        $serial = ($line -split '\s+', 2)[0]
        $transportId = $null
        if ($line -match 'transport_id:(\d+)') {
            $transportId = $Matches[1]
        }
        $devices += [pscustomobject]@{
            serial = $serial
            transport_id = $transportId
            raw = $line
        }
    }
    if ($devices.Count -eq 0) {
        return [pscustomobject]@{
            status = 'no_online_device'
            selector = @()
            serial = $null
            transport_id = $null
            devices_output = $devicesOutput
        }
    }

    $selected = $devices | Sort-Object {
        if ($_.transport_id) { [int]$_.transport_id } else { [int]::MaxValue }
    } | Select-Object -First 1
    if ($selected.transport_id) {
        return [pscustomobject]@{
            status = 'selected_by_transport'
            selector = @('-t', [string]$selected.transport_id)
            serial = [string]$selected.serial
            transport_id = [string]$selected.transport_id
            devices_output = $devicesOutput
        }
    }
    return [pscustomobject]@{
        status = 'selected_by_serial'
        selector = @('-s', [string]$selected.serial)
        serial = [string]$selected.serial
        transport_id = $null
        devices_output = $devicesOutput
    }
}

function Invoke-AdbShellText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Adb,
        [Parameter(Mandatory = $true)]
        [string[]]$Selector,
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    try {
        return ((& $Adb @Selector shell $Command 2>&1) | Out-String).TrimEnd()
    } catch {
        return "command_failed: $($_.Exception.Message)"
    }
}

function Select-AndroidSnapshotSummary {
    param([string]$Text)
    $eth0HasIpv4 = $Text -match '(?m)^    inet\s+\d+\.\d+\.\d+\.\d+/'
    $eth0State = $null
    if ($Text -match '(?m)^\d+:\s+eth0:.*\bstate\s+([A-Z_]+)\b') {
        $eth0State = $Matches[1]
    }
    $ethernetNetworkAgent = $null
    if ($Text -match 'networkAgent:\s*([^,\r\n]+)') {
        $ethernetNetworkAgent = $Matches[1].Trim()
    }
    $tetheringInterface = $null
    if ($Text -match 'Interface used for tethering:\s*([^\r\n]+)') {
        $tetheringInterface = $Matches[1].Trim()
    }
    $tetheringMode = $null
    if ($Text -match 'Tethering interface mode:\s*([^\r\n]+)') {
        $tetheringMode = $Matches[1].Trim()
    }
    $packageVersionName = $null
    if ($Text -match '(?m)^\s*versionName=([^\s\r\n]+)') {
        $packageVersionName = $Matches[1].Trim()
    }
    $packageDebuggable = $false
    if ($Text -match '(?m)^\s*pkgFlags=\[[^\]]*\bDEBUGGABLE\b') {
        $packageDebuggable = $true
    }
    $eventText = (($Text -split "`r?`n") |
        Where-Object { $_ -notmatch '\badbd\s+: in ShellService:' }) -join "`n"
    $authorizationSecurityFailed = [bool](
        $eventText -match 'VisionForgeMobile:.*dual_machine_authorization_runtime_failed' -or
        $eventText -match 'VisionForgeMobile:.*authorization_security_configuration_failed' -or
        $eventText -match '发布安全材料缺失或无效'
    )
    return [ordered]@{
        eth0_state = $eth0State
        eth0_has_ipv4 = [bool]$eth0HasIpv4
        ethernet_network_agent = $ethernetNetworkAgent
        tethering_interface = $tetheringInterface
        tethering_interface_mode = $tetheringMode
        package_version_name = $packageVersionName
        package_debuggable = $packageDebuggable
        authorization_security_failed = $authorizationSecurityFailed
    }
}

function Save-AndroidNetworkSnapshot {
    $adb = Resolve-AdbPath -RequestedPath $AdbPath
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('=== Android ADB Snapshot ===')
    $lines.Add("captured_at=$((Get-Date).ToString('o'))")
    if (-not $adb) {
        $lines.Add('status=adb_missing')
        Set-Content -LiteralPath $androidNetworkPath -Value $lines -Encoding UTF8
        return [ordered]@{
            status = 'adb_missing'
            path = $androidNetworkPath
            summary = $null
        }
    }

    $selector = Resolve-AdbSelector -Adb $adb -RequestedSerial $AndroidDeviceSerial
    $lines.Add("adb=$adb")
    $lines.Add("selector_status=$($selector.status)")
    $lines.Add("serial=$($selector.serial)")
    $lines.Add("transport_id=$($selector.transport_id)")
    $lines.Add('=== adb devices -l ===')
    if ($selector.devices_output) { $lines.Add($selector.devices_output) }
    if ($selector.status -eq 'no_online_device') {
        Set-Content -LiteralPath $androidNetworkPath -Value $lines -Encoding UTF8
        return [ordered]@{
            status = 'no_online_device'
            path = $androidNetworkPath
            summary = $null
        }
    }

    $commands = [ordered]@{
        'getprop identity' = 'getprop ro.product.manufacturer; getprop ro.product.model; getprop ro.product.device; getprop ro.soc.model; getprop ro.board.platform'
        'id' = 'id'
        'ip addr show eth0' = 'ip addr show eth0'
        'ip -4 addr show eth0' = 'ip -4 addr show eth0'
        'ip route show table all' = 'ip route show table all'
        'dumpsys ethernet' = 'dumpsys ethernet'
        'dumpsys tethering' = 'dumpsys tethering'
        'cmd ethernet help' = 'cmd ethernet help'
        'cmd tethering help' = 'cmd tethering help'
        'settings global ethernet/tether' = "settings list global | grep -i -E 'ethernet|tether|rndis|ncm'"
        'mobile package summary' = "dumpsys package $AndroidPackageName | grep -E 'Package \[|versionName|versionCode|pkgFlags|signatures|firstInstallTime|lastUpdateTime|installerPackageName'"
        'mobile authorization log tail' = "logcat -d -t 800 | grep -i -E 'VisionForgeMobile|dual_machine_authorization_runtime_failed|authorization_security|formal_usage|dual_machine_formal|APP_SCOUT_HANG'"
        'mobile runtime pid' = "pidof $AndroidPackageName"
    }
    foreach ($entry in $commands.GetEnumerator()) {
        $lines.Add("=== Android: $($entry.Key) ===")
        $lines.Add((Invoke-AdbShellText -Adb $adb `
                    -Selector ([string[]]$selector.selector) `
                    -Command $entry.Value))
    }

    $text = $lines -join [Environment]::NewLine
    $summary = Select-AndroidSnapshotSummary -Text $text
    Set-Content -LiteralPath $androidNetworkPath -Value $text -Encoding UTF8
    return [ordered]@{
        status = 'captured'
        path = $androidNetworkPath
        summary = $summary
    }
}

function Save-DiagnosticArtifacts([object[]]$acceptedEvents, [int]$targetProcessId) {
    $eventLines = @($acceptedEvents | ForEach-Object {
        $_ | ConvertTo-Json -Compress -Depth 10
    })
    Set-Content -LiteralPath $eventSnapshotPath -Value $eventLines -Encoding UTF8

    $emergencyPath = Join-Path $env:TEMP 'VFHost-emergency.log'
    if (Test-Path -LiteralPath $emergencyPath -PathType Leaf) {
        $emergencyLines = @(Get-Content -Encoding UTF8 -LiteralPath $emergencyPath |
            Where-Object {
                $_ -match ('(?:^| )pid=' + $targetProcessId + '(?: |$)') -and
                $_ -match 'timestamp_unix_ms=(\d+)' -and
                [long]$Matches[1] -ge $eventNotBeforeUnixMs
            })
        Set-Content -LiteralPath $emergencySnapshotPath `
            -Value $emergencyLines -Encoding UTF8
    }

    $metricsPath = Join-Path $env:LOCALAPPDATA `
        'VisionForge\DualMachine\host-metrics-v5.csv'
    if (Test-Path -LiteralPath $metricsPath -PathType Leaf) {
        Get-Content -Encoding UTF8 -LiteralPath $metricsPath -Tail 250 |
            Set-Content -LiteralPath $metricsSnapshotPath -Encoding UTF8
    }

    $crashDirectory = Join-Path $env:LOCALAPPDATA 'VisionForge\DualMachine\crashes'
    $crashes = @()
    if (Test-Path -LiteralPath $crashDirectory -PathType Container) {
        $crashes = @(Get-ChildItem -LiteralPath $crashDirectory -File |
            Where-Object Name -Like "*-pid$targetProcessId-*" )
        if ($crashes.Count -gt 0) {
            $crashSnapshotDirectory = Join-Path $resultDirectory 'crashes'
            New-Item -ItemType Directory -Path $crashSnapshotDirectory -Force | Out-Null
            $crashes | Copy-Item -Destination $crashSnapshotDirectory
        }
    }
    return $crashes.Count
}

function Stop-AcceptanceHost {
    if (-not $hostProcess -or $hostProcess.HasExited) { return $true }
    [void]$hostProcess.CloseMainWindow()
    if ($hostProcess.WaitForExit(10000)) { return $true }
    Stop-Process -Id $hostProcess.Id -Force -ErrorAction SilentlyContinue
    [void]$hostProcess.WaitForExit(5000)
    return $false
}

function Write-AcceptanceProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,
        [string]$Status = 'ok',
        [string]$Detail = ''
    )
    try {
        if (-not (Test-Path -LiteralPath $resultDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
        }
        $hostPid = $null
        if ($hostProcess) { $hostPid = $hostProcess.Id }
        $event = [ordered]@{
            timestamp = (Get-Date).ToString('o')
            stage = $Stage
            status = $Status
            detail = $Detail
            trace_id = $traceId
            host_pid = $hostPid
            result_directory = $resultDirectory
        }
        $event | ConvertTo-Json -Compress -Depth 4 |
            Add-Content -LiteralPath $progressPath -Encoding UTF8
    } catch {
        # Do not let acceptance diagnostics break the acceptance run.
    }
}

Write-AcceptanceProgress -Stage 'harness_started'

try {
    New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
    Start-Transcript -LiteralPath $transcriptPath -Force | Out-Null
    Write-AcceptanceProgress -Stage 'transcript_started'
    $preRunEthernetState = @(Get-PhysicalEthernetState)
    $preRunEthernetStateJson = $preRunEthernetState |
        ConvertTo-Json -Compress -Depth 10
    Write-AcceptanceProgress -Stage 'pre_network_snapshot_captured' `
        -Detail "ethernet_adapter_count=$($preRunEthernetState.Count)"

    if (-not (Test-Path -LiteralPath $hostExe -PathType Leaf)) {
        throw "Host EXE not found: $hostExe"
    }
    $actualHash = (Get-FileHash -LiteralPath $hostExe -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        throw "Host EXE hash mismatch: expected=$expectedHash actual=$actualHash"
    }
    Write-AcceptanceProgress -Stage 'host_hash_verified' -Detail $actualHash

    $existingProcess = Get-Process -Name @('VFHost', 'VisionForgeHost') `
        -ErrorAction SilentlyContinue
    if ($existingProcess) {
        $status = 'preexisting_host_running'
        throw 'A VF Host process was already running before acceptance.'
    }
    Write-AcceptanceProgress -Stage 'preexisting_host_check_passed'

    $deadline = (Get-Date).AddSeconds($MaximumRuntimeSeconds)
    # A hard process crash cannot be retried from inside the app, so the
    # harness relaunches the Host itself (bounded). E-system acceptance #7
    # died with 0xC0000005 seconds after launch on this machine.
    $maximumLaunchAttempts = 3
    $launchAttempt = 0
    $hostProcess = $null
    while ((Get-Date) -lt $deadline) {
        if ($null -eq $hostProcess -or $hostProcess.HasExited) {
            if ($null -ne $hostProcess) {
                $exitCode = $hostProcess.ExitCode
                Write-Output "VFHost exited before acceptance (exit_code=$exitCode, launch=$launchAttempt)"
            }
            if ($launchAttempt -ge $maximumLaunchAttempts) {
                $failureReason = "VFHost exited before acceptance completed after $launchAttempt launches."
                break
            }
            $launchAttempt += 1
            $traceId = $null
            Write-AcceptanceProgress -Stage 'host_launch_started' `
                -Detail "launch=$launchAttempt"
            $hostProcess = Start-Process -FilePath $hostExe `
                -ArgumentList '--acceptance-autostart' -PassThru
            Write-Output "Started VFHost pid=$($hostProcess.Id) hash=$actualHash launch=$launchAttempt"
            Write-AcceptanceProgress -Stage 'host_launch_finished' `
                -Detail "launch=$launchAttempt pid=$($hostProcess.Id)"
        }
        Start-Sleep -Seconds 2
        $candidateEvents = Read-AcceptanceEvents
        if (-not $traceId) {
            $processStart = $candidateEvents |
                Where-Object {
                    $_.event -eq 'host_process_start' -and
                    $_.detail -match ('(?:^| )pid=' + $hostProcess.Id + '(?: |$)')
                } |
                Select-Object -Last 1
            if ($processStart) {
                $traceId = [string]$processStart.trace_id
                Write-Output "Bound acceptance trace_id=$traceId"
                Write-AcceptanceProgress -Stage 'trace_bound' -Detail $traceId
            }
        }
        $events = Read-AcceptanceEvents
        # host_cat6_bootstrap_failed is retried automatically by the
        # acceptance autostart path (the machine-identity tool on this machine
        # rewrites the adapter mid-bootstrap, and only a later attempt can
        # provision a surviving link). Only non-retryable hard failures abort
        # the wait early; process exits are relaunched above.
        $hardFailure = $events |
            Where-Object {
                $_.event -Match $hardFailureEventPattern -and
                $_.event -ne 'host_cat6_bootstrap_failed'
            } |
            Select-Object -Last 1
        if ($hardFailure) {
            $failureReason = "$($hardFailure.event): $($hardFailure.detail)"
            Write-AcceptanceProgress -Stage 'hard_failure_observed' `
                -Status 'failed' -Detail $failureReason
            break
        }
        $streamStarted = @($events | Where-Object event -eq 'host_stream_started').Count -gt 0
        $encoderSelected = @($events | Where-Object event -eq 'host_encoder_selected').Count -gt 0
        $qualityEvents = @($events | Where-Object event -eq 'host_cat6_quality')
        $lastQuality = $qualityEvents | Select-Object -Last 1
        $publishedFrames = Read-PublishedFrames $lastQuality
        $qualityProgress = Measure-QualityProgress $qualityEvents $MinimumQualitySamples
        $pollDetail = ("launch={0} events={1} stream_started={2} encoder_selected={3} " +
            "quality_samples={4} published_frames={5} frame_delta={6} " +
            "sustained={7}") -f $launchAttempt, $events.Count, $streamStarted,
            $encoderSelected, $qualityEvents.Count, $publishedFrames,
            $qualityProgress.frame_delta, $qualityProgress.is_sustained
        Write-AcceptanceProgress -Stage 'acceptance_poll' `
            -Detail $pollDetail
        if ($streamStarted -and $encoderSelected -and
            $qualityEvents.Count -ge $MinimumQualitySamples -and
            $publishedFrames -ge 1000 -and $qualityProgress.is_sustained) {
            $status = 'passed'
            Write-AcceptanceProgress -Stage 'sustained_stream_evidence_observed' `
                -Detail "published_frames=$publishedFrames quality_samples=$($qualityEvents.Count)"
            break
        }
    }

    if ($status -ne 'passed' -and -not $failureReason) {
        $failureReason = 'Acceptance deadline expired before sustained host_stream_started evidence.'
        Write-AcceptanceProgress -Stage 'deadline_expired' `
            -Status 'failed' -Detail $failureReason
    }

    Write-AcceptanceProgress -Stage 'host_stop_started'
    $closedCleanly = Stop-AcceptanceHost
    Write-AcceptanceProgress -Stage 'host_stop_finished' `
        -Detail "closed_cleanly=$closedCleanly"
    Start-Sleep -Milliseconds 750
    $events = Read-AcceptanceEvents
    # Bootstrap failures superseded by a later successful CAT6-ready attempt
    # are recoveries, not hard failures (retry-tolerant acceptance).
    $lastCat6Ready = $events |
        Where-Object event -eq 'host_cat6_ready' |
        Select-Object -Last 1
    $hardFailures = @($events |
        Where-Object {
            $_.event -Match $hardFailureEventPattern -and (
                $_.event -ne 'host_cat6_bootstrap_failed' -or
                $null -eq $lastCat6Ready -or
                [long]$_.timestamp_unix_ms -gt [long]$lastCat6Ready.timestamp_unix_ms)
        })
    $recoveryFailures = @($events | Where-Object event -eq 'host_stream_recovery_attempt_failed')
    $streamStopped = @($events | Where-Object event -eq 'host_stream_stopped').Count -gt 0
    $directLinkBootstrapEvent = $events |
        Where-Object event -eq 'host_direct_link_bootstrap' |
        Select-Object -Last 1
    $directLinkBootstrapStatus = 'missing'
    if ($directLinkBootstrapEvent -and
        [string]$directLinkBootstrapEvent.detail -match '(?:^| )status=([a-z_]+)(?: |$)') {
        $directLinkBootstrapStatus = $Matches[1]
    }
    $directLinkRestoreEvent = $events |
        Where-Object event -eq 'host_direct_link_clean_shutdown_restore' |
        Select-Object -Last 1
    $directLinkRestoreStatus = 'missing'
    if ($directLinkRestoreEvent -and
        [string]$directLinkRestoreEvent.detail -match '(?:^| )status=([a-z_]+)(?: |$)') {
        $directLinkRestoreStatus = $Matches[1]
    }
    $postRunEthernetState = @(Get-PhysicalEthernetState)
    $postRunEthernetStateJson = $postRunEthernetState |
        ConvertTo-Json -Compress -Depth 10
    Write-AcceptanceProgress -Stage 'post_network_snapshot_captured' `
        -Detail "ethernet_adapter_count=$($postRunEthernetState.Count)"
    $ethernetStateRestored = $preRunEthernetStateJson -eq $postRunEthernetStateJson
    $restoreStatusValid = if ($directLinkBootstrapStatus -eq 'provisioned') {
        $directLinkRestoreStatus -eq 'restored'
    } else {
        $directLinkRestoreStatus -in @('restored', 'not_required')
    }
    $directLinkRestored = $directLinkBootstrapStatus -ne 'missing' -and
        $restoreStatusValid -and $ethernetStateRestored
    if ($status -eq 'passed' -and $hardFailures.Count -gt 0) {
        $status = 'failed'
        $lastHardFailure = $hardFailures | Select-Object -Last 1
        $failureReason =
            "Hard failure observed before final evidence: $($lastHardFailure.event): " +
            [string]$lastHardFailure.detail
    }
    if ($status -eq 'passed' -and
        (-not $closedCleanly -or -not $streamStopped -or -not $directLinkRestored)) {
        $status = 'failed'
        $failureReason =
            "Clean shutdown evidence missing: close_main_window=$closedCleanly " +
            "host_stream_stopped=$streamStopped bootstrap_status=$directLinkBootstrapStatus " +
            "restore_status=$directLinkRestoreStatus ethernet_state_restored=$ethernetStateRestored"
    }

    $networkText = @(
        '=== Physical Ethernet before Host ==='
        ($preRunEthernetState | ConvertTo-Json -Depth 10)
        '=== Physical Ethernet after clean shutdown ==='
        ($postRunEthernetState | ConvertTo-Json -Depth 10)
        '=== Get-NetAdapter ==='
        (Get-NetAdapter | Sort-Object ifIndex | Format-List Name, InterfaceDescription, ifIndex, Status, LinkSpeed | Out-String)
        '=== Get-NetIPAddress IPv4 ==='
        (Get-NetIPAddress -AddressFamily IPv4 | Sort-Object InterfaceIndex, IPAddress | Format-Table -AutoSize | Out-String)
        '=== Get-NetRoute IPv4 ==='
        (Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix, RouteMetric | Format-Table -AutoSize | Out-String)
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $networkPath -Value $networkText -Encoding UTF8
    Write-AcceptanceProgress -Stage 'network_snapshot_saved' `
        -Detail $networkPath
    $androidNetworkSnapshot = Save-AndroidNetworkSnapshot
    $androidNetworkSummaryJson = if ($androidNetworkSnapshot.summary) {
        $androidNetworkSnapshot.summary | ConvertTo-Json -Compress -Depth 6
    } else {
        ''
    }
    Write-AcceptanceProgress -Stage 'android_network_snapshot_saved' `
        -Detail "status=$($androidNetworkSnapshot.status) summary=$androidNetworkSummaryJson"

    $qualityEvents = @($events | Where-Object event -eq 'host_cat6_quality')
    $lastQuality = $qualityEvents | Select-Object -Last 1
    $qualityProgress = Measure-QualityProgress $qualityEvents $MinimumQualitySamples
    $encoderEvent = $events | Where-Object event -eq 'host_encoder_selected' | Select-Object -Last 1
    $streamEvent = $events | Where-Object event -eq 'host_stream_started' | Select-Object -Last 1
    $crashArtifactCount = Save-DiagnosticArtifacts $events $hostProcess.Id
    Write-AcceptanceProgress -Stage 'diagnostic_artifacts_saved' `
        -Detail "event_count=$($events.Count) crash_artifact_count=$crashArtifactCount"
    $windowsVersion = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result = [ordered]@{
        schema_version = 1
        status = $status
        failure_reason = $failureReason
        expected_sha256 = $expectedHash
        actual_sha256 = (Get-FileHash -LiteralPath $hostExe -Algorithm SHA256).Hash
        trace_id = $traceId
        started_at = $startedAt.ToString('o')
        finished_at = (Get-Date).ToString('o')
        windows = [ordered]@{
            product_name = $windowsVersion.ProductName
            display_version = $windowsVersion.DisplayVersion
            current_build = $windowsVersion.CurrentBuild
            ubr = $windowsVersion.UBR
            system_drive = $env:SystemDrive
            user_name = $env:USERNAME
            interactive_session = [Environment]::UserInteractive
        }
        gpu_names = @(Get-CimInstance Win32_VideoController | ForEach-Object Name)
        event_count = $events.Count
        quality_sample_count = $qualityEvents.Count
        published_frames = Read-PublishedFrames $lastQuality
        published_frame_delta = $qualityProgress.frame_delta
        quality_window_duration_ms = $qualityProgress.duration_ms
        quality_maximum_gap_ms = $qualityProgress.maximum_gap_ms
        quality_newest_age_ms = $qualityProgress.newest_age_ms
        quality_monotonically_increasing = $qualityProgress.monotonically_increasing
        quality_link_healthy = $qualityProgress.link_healthy
        hard_failure_count = $hardFailures.Count
        recovery_failure_count = $recoveryFailures.Count
        crash_artifact_count = $crashArtifactCount
        clean_shutdown = $closedCleanly
        stream_stopped = $streamStopped
        direct_link_restored = [bool]$directLinkRestored
        direct_link_bootstrap_status = $directLinkBootstrapStatus
        direct_link_restore_status = $directLinkRestoreStatus
        ethernet_state_restored = $ethernetStateRestored
        direct_link_restore_detail = if ($directLinkRestoreEvent) {
            [string]$directLinkRestoreEvent.detail
        } else {
            $null
        }
        encoder_detail = if ($encoderEvent) { [string]$encoderEvent.detail } else { $null }
        stream_detail = if ($streamEvent) { [string]$streamEvent.detail } else { $null }
        last_quality_detail = if ($lastQuality) { [string]$lastQuality.detail } else { $null }
        event_log_path = $eventPath
        filtered_event_snapshot_path = $eventSnapshotPath
        network_snapshot_path = $networkPath
        android_network_snapshot_path = $androidNetworkPath
        android_network_snapshot_status = [string]$androidNetworkSnapshot.status
        android_network_summary = $androidNetworkSnapshot.summary
        emergency_snapshot_path = if (Test-Path -LiteralPath $emergencySnapshotPath) {
            $emergencySnapshotPath
        } else {
            $null
        }
        metrics_snapshot_path = if (Test-Path -LiteralPath $metricsSnapshotPath) {
            $metricsSnapshotPath
        } else {
            $null
        }
        evidence_files = [ordered]@{
            filtered_events = 'filtered-events.jsonl'
            network_snapshot = 'network-snapshot.txt'
            android_network_snapshot = 'android-network-snapshot.txt'
            transcript = 'acceptance-transcript.txt'
            metrics_tail = if (Test-Path -LiteralPath $metricsSnapshotPath) {
                'host-metrics-tail.csv'
            } else {
                $null
            }
            emergency_events = if (Test-Path -LiteralPath $emergencySnapshotPath) {
                'emergency-events.log'
            } else {
                $null
            }
            crash_directory = if ($crashArtifactCount -gt 0) { 'crashes' } else { $null }
        }
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-AcceptanceProgress -Stage 'result_written' `
        -Status $status -Detail $resultPath
    Write-Output "Acceptance status=$status result=$resultPath"
} catch {
    if (-not $failureReason) {
        $failureReason = $_.Exception.ToString()
    }
    $failureStatus = if ($status -eq 'preexisting_host_running') {
        $status
    } else {
        'harness_failed'
    }
    $status = $failureStatus
    Write-AcceptanceProgress -Stage $failureStatus `
        -Status 'failed' -Detail $failureReason
    $fallback = [ordered]@{
        schema_version = 1
        status = $failureStatus
        failure_reason = $failureReason
        expected_sha256 = $expectedHash
        trace_id = $traceId
        started_at = $startedAt.ToString('o')
        finished_at = (Get-Date).ToString('o')
        evidence_files = [ordered]@{
            transcript = 'acceptance-transcript.txt'
        }
    }
    $fallback | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Error $failureReason
} finally {
    Write-AcceptanceProgress -Stage 'final_stop_started'
    [void](Stop-AcceptanceHost)
    Write-AcceptanceProgress -Stage 'final_stop_finished'
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    Write-AcceptanceProgress -Stage 'transcript_stopped'
    if ($RestartWhenFinished) {
        Write-AcceptanceProgress -Stage 'restart_schedule_started'
        $restartProcess = Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" `
            -ArgumentList '/r', '/t', '30', '/c',
                'VF Host E-system acceptance finished; returning to the default Windows installation.' `
            -WindowStyle Hidden -Wait -PassThru
        if ($restartProcess.ExitCode -ne 0) {
            throw "shutdown.exe exited with code $($restartProcess.ExitCode)"
        }
        Write-AcceptanceProgress -Stage 'restart_schedule_finished'
    } else {
        Write-AcceptanceProgress -Stage 'restart_not_requested'
    }
}

if ($status -ne 'passed') {
    Write-AcceptanceProgress -Stage 'throwing_failed_status' `
        -Status 'failed' -Detail "status=$status reason=$failureReason"
    throw "VF Host acceptance failed: status=$status result=$resultPath reason=$failureReason"
}
