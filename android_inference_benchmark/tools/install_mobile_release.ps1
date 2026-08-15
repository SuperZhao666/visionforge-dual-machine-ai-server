param(
    [switch]$Build,
    [switch]$Launch,
    [switch]$VerifyUi,
    [switch]$AllowDevelopmentSigning,
    [switch]$RemoveLegacyBenchmarkPackage,
    [string]$ApkPath,
    [string]$WindowsExePath,
    [string]$HostExePath,
    [string]$BluetoothRouteEvidencePath,
    [string]$BluetoothRouteMobileLogPath,
    [string]$MakcuRouteEvidencePath,
    [string]$MakcuRouteMobileLogPath,
    [string]$FinalSafeIdleEvidencePath,
    [string]$FinalSafeIdleMobileLogPath,
    [string]$FinalSafeIdleUiXmlPath,
    [string]$AdbPath = $env:VISIONFORGE_ADB,
    [string]$DeviceSerial = $env:ANDROID_SERIAL
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem
trap {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
$projectRoot = Split-Path $PSScriptRoot -Parent
$workspaceRoot = Split-Path $projectRoot -Parent
$defaultApk = Join-Path $projectRoot "app/build/outputs/apk/release/app-release.apk"
$apk = if ([string]::IsNullOrWhiteSpace($ApkPath)) {
    $defaultApk
} elseif ([System.IO.Path]::IsPathRooted($ApkPath)) {
    $ApkPath
} else {
    Join-Path $projectRoot $ApkPath
}
$packageName = "com.visionforge.mobile"
$legacyBenchmarkPackageName = "com.visionforge.inferencebenchmark"
$activityName = "com.visionforge.inferencebenchmark.MainActivity"

function Resolve-AdbPath {
    param([string]$RequestedPath, [string]$Root)
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) { $candidates += $RequestedPath }
    $candidates += (Join-Path $Root ".android-sdk/platform-tools/adb.exe")
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $pathCommand = Get-Command adb -ErrorAction SilentlyContinue
    if ($null -ne $pathCommand) { return $pathCommand.Source }
    throw "ADB missing. Pass -AdbPath, set VISIONFORGE_ADB, or install the workspace Android SDK."
}

function Get-AdbDeviceRows {
    param([string]$Adb)
    return @(& $Adb devices -l | Select-Object -Skip 1 | ForEach-Object {
        $line = $_.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { return }
        $match = [regex]::Match(
            $line,
            '^(?<serial>.+?)\s+(?<state>device|offline|unauthorized)\b')
        if (-not $match.Success) { return }
        [pscustomobject]@{
            serial = $match.Groups['serial'].Value
            state = $match.Groups['state'].Value
            raw = $line
        }
    })
}

function Get-AdbPhysicalDeviceKey {
    param([string]$Serial)
    $match = [regex]::Match(
        $Serial,
        '^(?<base>adb-[^ ]+?)(?: \(\d+\))?\._adb-tls-connect\._tcp$')
    if ($match.Success) { return $match.Groups['base'].Value }
    return $Serial
}

function Assert-NoDuplicateAdbTransports {
    param($DeviceRows)
    $onlineRows = @($DeviceRows | Where-Object { $_.state -eq 'device' })
    $duplicates = @($onlineRows | Group-Object -Property {
            Get-AdbPhysicalDeviceKey $_.serial
        } | Where-Object {
            $_.Count -gt 1 -and $_.Name -match '^adb-'
        })
    if ($duplicates.Count -eq 0) { return }
    $details = ($duplicates | ForEach-Object {
            $serials = ($_.Group | ForEach-Object { $_.serial }) -join ', '
            "$($_.Name): $serials"
        }) -join '; '
    throw (
        "Duplicate ADB mDNS transports detected for the same phone: $details. " +
        "Disconnect the stale duplicate with adb disconnect `"<duplicate-serial>`", " +
        "then rerun this release installer. Refusing to continue because a " +
        "debug APK can overwrite the verified release package through the other transport.")
}

function Resolve-DeviceSerial {
    param([string]$Adb, [string]$RequestedSerial)
    $deviceRows = Get-AdbDeviceRows $Adb
    Assert-NoDuplicateAdbTransports $deviceRows
    $onlineSerials = @($deviceRows | Where-Object { $_.state -eq 'device' } |
        ForEach-Object { $_.serial })
    if (-not [string]::IsNullOrWhiteSpace($RequestedSerial)) {
        if ($onlineSerials -notcontains $RequestedSerial) {
            throw "Requested ADB device is not online: $RequestedSerial"
        }
        return $RequestedSerial
    }
    if ($onlineSerials.Count -ne 1) {
        throw "Expected exactly one authorised ADB device, found $($onlineSerials.Count). Pass -DeviceSerial when several are connected."
    }
    return $onlineSerials[0]
}

function Assert-LastExitCode {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." }
}

function ConvertTo-QuotedAdbProcessArgument {
    param([string]$Value)
    if ($Value.Contains('"')) {
        throw "ADB process argument contains an unsupported quote character."
    }
    return '"' + $Value + '"'
}

function Test-DevicePackageInstalled {
    param([string]$Adb, [string]$Serial, [string]$Package)
    $output = & $Adb -s $Serial shell pm path $Package 2>$null
    return $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($output -join "`n"))
}

function Stop-DevicePackageIfPresent {
    param([string]$Adb, [string]$Serial, [string]$Package)
    if (-not (Test-DevicePackageInstalled $Adb $Serial $Package)) { return $false }
    & $Adb -s $Serial shell am force-stop $Package | Out-Null
    Assert-LastExitCode "Force-stop package $Package"
    return $true
}

function Invoke-MobileApkInstall {
    param([string]$Adb, [string]$Serial, [string]$Apk)
    $stdoutPath = $null
    $stderrPath = $null
    try {
        $stdoutPath = (New-TemporaryFile).FullName
        $stderrPath = (New-TemporaryFile).FullName
        $process = Start-Process -FilePath $Adb `
            -ArgumentList @(
                "-s",
                (ConvertTo-QuotedAdbProcessArgument $Serial),
                "install",
                "-r",
                (ConvertTo-QuotedAdbProcessArgument $Apk)) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath
        $installExitCode = $process.ExitCode
        $installOutput = @()
        if (Test-Path -LiteralPath $stdoutPath) {
            $installOutput += Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $stderrPath) {
            $installOutput += Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue
        }
    } finally {
        foreach ($temporaryPath in @($stdoutPath, $stderrPath)) {
            if (-not [string]::IsNullOrWhiteSpace($temporaryPath) -and
                    (Test-Path -LiteralPath $temporaryPath)) {
                Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $installText = ($installOutput | Out-String).Trim()
    if ($installExitCode -eq 0) { return $installText }
    if ($installText -match 'INSTALL_FAILED_USER_RESTRICTED') {
        throw @"
APK installation was blocked by the device policy: INSTALL_FAILED_USER_RESTRICTED.
This is a phone/tablet-side USB installation restriction, not an APK build failure.
On HyperOS/MIUI, unlock the device and enable/confirm Developer options -> USB install / Install via USB, then rerun this script.
Raw adb output:
$installText
"@
    }
    throw "APK installation failed with exit code $installExitCode.`n$installText"
}

function Assert-MobileApkContainsMigrationModels {
    param([string]$Apk)
    $requiredEntries = @(
        "lib/arm64-v8a/libvalorant_416_v11s_no_flash_w8a16.so",
        "lib/arm64-v8a/libow2_416_w8a16.so",
        "lib/arm64-v8a/libdelta_416_v8s_w8a16.so",
        "lib/arm64-v8a/libcs2_vombit_416_v8s_w8a16.so"
    )
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Apk)
    try {
        $entryNames = @($archive.Entries | ForEach-Object { $_.FullName })
        $missingEntries = @($requiredEntries | Where-Object {
                $entryNames -notcontains $_
            })
        if ($missingEntries.Count -gt 0) {
            throw (
                "APK does not contain the required four-model 416 QNN payload. " +
                "Missing entries: $($missingEntries -join ', '). " +
                "Rebuild the current release APK before installing.")
        }
    } finally {
        $archive.Dispose()
    }
}

function Assert-MobileApkFreshForMigration {
    param(
        [string]$Apk,
        [string]$Root
    )
    $criticalInputs = @(
        "app/build.gradle",
        "app/src/main/java/com/visionforge/inferencebenchmark/MobileModelCatalog.java",
        "app/src/main/jniLibs/arm64-v8a/libvalorant_416_v11s_no_flash_w8a16.so",
        "app/src/main/jniLibs/arm64-v8a/libow2_416_w8a16.so",
        "app/src/main/jniLibs/arm64-v8a/libdelta_416_v8s_w8a16.so",
        "app/src/main/jniLibs/arm64-v8a/libcs2_vombit_416_v8s_w8a16.so"
    )
    $apkItem = Get-Item -LiteralPath $Apk
    $newerInputs = @()
    foreach ($relativeInput in $criticalInputs) {
        $inputPath = Join-Path $Root $relativeInput
        if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) {
            throw "Required migration input is missing: $inputPath"
        }
        $inputItem = Get-Item -LiteralPath $inputPath
        if ($inputItem.LastWriteTimeUtc -gt $apkItem.LastWriteTimeUtc) {
            $newerInputs += [pscustomobject]@{
                path = $inputPath
                last_write_time = $inputItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }
    if ($newerInputs.Count -gt 0) {
        $details = ($newerInputs | ForEach-Object {
                "$($_.path) [$($_.last_write_time)]"
            }) -join "; "
        throw (
            "APK is older than current four-model migration inputs and cannot " +
            "prove this build. apk=$Apk apk_last_write=$($apkItem.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) " +
            "newer_inputs=$details. Re-run with -Build after configuring release " +
            "security material, or pass a freshly built current release APK.")
    }
}

function Get-InstalledPackageSummary {
    param([string]$Adb, [string]$Serial, [string]$Package)
    $text = (& $Adb -s $Serial shell dumpsys package $Package) -join "`n"
    $versionName = ""
    if ($text -match '(?m)^\s*versionName=([^\s\r\n]+)') {
        $versionName = $Matches[1]
    }
    $pkgFlags = ""
    if ($text -match '(?m)^\s*pkgFlags=\[([^\]]*)\]') {
        $pkgFlags = $Matches[1].Trim()
    }
    return [pscustomobject]@{
        version_name = $versionName
        pkg_flags = $pkgFlags
        debuggable = [bool]($pkgFlags -match '\bDEBUGGABLE\b')
    }
}

function Assert-MobileApkPathLooksReleaseCandidate {
    param([string]$Apk)
    $fileName = [System.IO.Path]::GetFileName($Apk)
    $normalisedPath = $Apk.Replace('/', '\')
    if ($fileName -match '(?i)debug' -or $normalisedPath -match '(?i)\\debug\\') {
        throw (
            "Debug APK paths are not accepted by the release installer: $Apk. " +
            "Build a current release APK instead; development signing, when " +
            "explicitly allowed, must still use the release build type.")
    }
}

function Resolve-ApkSignerPath {
    param([string]$Root)
    $candidate = Join-Path $Root ".android-sdk/build-tools/35.0.0/apksigner.bat"
    if (Test-Path -LiteralPath $candidate) {
        return (Resolve-Path -LiteralPath $candidate).Path
    }
    $pathCommand = Get-Command apksigner -ErrorAction SilentlyContinue
    if ($null -ne $pathCommand) { return $pathCommand.Source }
    throw "apksigner missing. The release installer must verify APK signer identity before installation."
}

function Get-MobileApkSigningSummary {
    param([string]$Apk, [string]$Root)
    $apksigner = Resolve-ApkSignerPath $Root
    $output = @(& $apksigner verify --verbose --print-certs $Apk)
    Assert-LastExitCode "APK signer verification"
    $text = ($output | Out-String)
    $v1Verified = [bool]($text -match 'Verified using v1 scheme \(JAR signing\): true')
    $v2Verified = [bool]($text -match 'Verified using v2 scheme \(APK Signature Scheme v2\): true')
    $v3Verified = [bool]($text -match 'Verified using v3 scheme \(APK Signature Scheme v3\): true')
    $signerDigests = @(
        [regex]::Matches(
            $text,
            'Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]+)') |
            ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() }
    )
    $debugDn = [bool]($text -match 'Signer #\d+ certificate DN: .*CN=Android Debug')
    $debugDigest = $signerDigests -contains (
        '179faf0492d0b49d66bdefcc66bc51541602525a25b8af8c4e42345a770c7155')
    return [pscustomobject]@{
        v1_verified = $v1Verified
        v2_verified = $v2Verified
        v3_verified = $v3Verified
        current_signer_count = $signerDigests.Count
        android_debug_certificate = ($debugDn -or $debugDigest)
        raw = $text.Trim()
    }
}

function Assert-MobileApkSigningIdentity {
    param([string]$Apk, [string]$Root, [bool]$AllowDevelopment)
    $summary = Get-MobileApkSigningSummary $Apk $Root
    if (-not ($summary.v2_verified -or $summary.v3_verified)) {
        throw "APK is not verified with APK Signature Scheme v2 or v3 and cannot be installed as a release candidate."
    }
    if (-not $AllowDevelopment -and $summary.v1_verified) {
        throw "Production APK must not use APK Signature Scheme v1."
    }
    if (-not $AllowDevelopment -and -not $summary.v3_verified) {
        throw "Production APK is not verified with APK Signature Scheme v3."
    }
    if (-not $AllowDevelopment -and $summary.current_signer_count -ne 1) {
        throw "Production APK must contain exactly one current signer."
    }
    if (-not $AllowDevelopment -and $summary.android_debug_certificate) {
        throw (
            "APK is signed with the Android Debug certificate and cannot be used " +
            "for production release installation. Provide production Android " +
            "release signing credentials, rebuild, or pass -AllowDevelopmentSigning " +
            "only for local device acceptance.")
    }
}

function Get-UiDocument {
    param([string]$Adb, [string]$Serial, [string]$OutputDirectory, [string]$Label)
    $remoteXml = "/sdcard/Download/visionforge-ui-$Label.xml"
    $localXml = Join-Path $OutputDirectory "$Label.xml"
    $captureSucceeded = $false
    foreach ($attempt in 1..3) {
        & $Adb -s $Serial shell rm -f $remoteXml | Out-Null
        & $Adb -s $Serial shell uiautomator dump --compressed $remoteXml | Out-Null
        if ($LASTEXITCODE -eq 0) {
            & $Adb -s $Serial shell test -s $remoteXml | Out-Null
            $captureSucceeded = $LASTEXITCODE -eq 0
        }
        if ($captureSucceeded) { break }
        Start-Sleep -Milliseconds (250 * $attempt)
    }
    if (-not $captureSucceeded) {
        throw "UI hierarchy capture ($Label) did not produce a document after 3 attempts."
    }
    & $Adb -s $Serial pull $remoteXml $localXml | Out-Null
    Assert-LastExitCode "UI hierarchy pull ($Label)"
    return [xml](Get-Content -LiteralPath $localXml -Raw -Encoding utf8)
}

function Save-DeviceScreenshot {
    param([string]$Adb, [string]$Serial, [string]$OutputDirectory, [string]$Label)
    $remotePng = "/sdcard/Download/visionforge-ui-$Label.png"
    $localPng = Join-Path $OutputDirectory "$Label.png"
    & $Adb -s $Serial shell screencap -p $remotePng | Out-Null
    Assert-LastExitCode "Screenshot capture ($Label)"
    & $Adb -s $Serial pull $remotePng $localPng | Out-Null
    Assert-LastExitCode "Screenshot pull ($Label)"
    return $localPng
}

function Find-NodeByDescription {
    param([xml]$Document, [string]$Description)
    return @($Document.SelectNodes('//node')) | Where-Object {
        $_.'content-desc' -eq $Description
    } | Select-Object -First 1
}

function Find-NodeByResourceId {
    param([xml]$Document, [string]$ResourceName)
    $qualifiedName = "$packageName`:id/$ResourceName"
    return @($Document.SelectNodes('//node')) | Where-Object {
        $_.'resource-id' -eq $qualifiedName
    } | Select-Object -First 1
}

function Find-ScrollableNode {
    param([xml]$Document)
    $nodes = @($Document.SelectNodes('//node'))
    $scrollable = $nodes | Where-Object {
        $_.scrollable -eq 'true'
    } | Select-Object -First 1
    if ($null -ne $scrollable) { return $scrollable }
    $automationIds = @(
        'vf.page_scroll.authorization',
        'vf.page_scroll.inference',
        'vf.page_scroll.control'
    )
    $identifiedScroll = $nodes | Where-Object {
        $automationIds -contains $_.'content-desc'
    } | Select-Object -First 1
    if ($null -ne $identifiedScroll) { return $identifiedScroll }
    return $nodes | Where-Object {
        $_.'class' -eq 'android.widget.ScrollView' -or
                $_.'class' -eq 'androidx.core.widget.NestedScrollView'
    } | Select-Object -First 1
}

function Test-UiDocumentBelongsToPackage {
    param([xml]$Document)
    $ownedNode = @($Document.SelectNodes('//node')) | Where-Object {
        $_.package -eq $packageName
    } | Select-Object -First 1
    return $null -ne $ownedNode
}

function Assert-Node {
    param($Node, [string]$Description)
    if ($null -eq $Node) { throw "Required UI node missing: $Description" }
}

function Test-NodeVisible {
    param($Node)
    if ($null -eq $Node) { return $false }
    $visible = $Node.'visible-to-user'
    return [string]::IsNullOrWhiteSpace($visible) -or $visible -eq 'true'
}

function Assert-VisibleNode {
    param($Node, [string]$Description)
    Assert-Node $Node $Description
    if (-not (Test-NodeVisible $Node)) {
        throw "Required UI node is not visible: $Description"
    }
}

function Assert-VisibleNodeText {
    param($Node, [string]$ExpectedText, [string]$Description)
    Assert-VisibleNode $Node $Description
    if ($Node.text -ne $ExpectedText) {
        throw "Required UI node text mismatch: $Description expected='$ExpectedText' actual='$($Node.text)'"
    }
}

function New-TextFromCodepoints {
    param([int[]]$Codepoints)
    return -join ($Codepoints | ForEach-Object { [char]$_ })
}

function Assert-MissingOrHiddenNode {
    param($Node, [string]$Description)
    if (Test-NodeVisible $Node) {
        throw "UI node must be hidden for the selected model: $Description"
    }
}

function Invoke-NodeTap {
    param([string]$Adb, [string]$Serial, $Node, [string]$Description)
    Ensure-MobileForeground $Adb $Serial
    Assert-VisibleNode $Node $Description
    if ($Node.bounds -notmatch '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$') {
        throw "Invalid UI bounds for $Description`: $($Node.bounds)"
    }
    $left = [int]$Matches[1]
    $top = [int]$Matches[2]
    $right = [int]$Matches[3]
    $bottom = [int]$Matches[4]
    $x = [int](($left + $right) / 2)
    $y = [int](($top + $bottom) / 2)
    & $Adb -s $Serial shell input tap $x $y | Out-Null
    Assert-LastExitCode "Tap $Description"
    Start-Sleep -Milliseconds 350
}

function Get-FocusedPackage {
    param([string]$Adb, [string]$Serial)
    $windowState = (& $Adb -s $Serial shell dumpsys window) -join "`n"
    $focusMatch = [regex]::Match(
        $windowState,
        'mCurrentFocus=Window\{[^ ]+ [^ ]+ (?<package>[^/ ]+)/')
    if ($focusMatch.Success) { return $focusMatch.Groups['package'].Value }
    $appMatch = [regex]::Match(
        $windowState,
        'mFocusedApp=ActivityRecord\{[^ ]+ [^ ]+ (?<package>[^/ ]+)/')
    if ($appMatch.Success) { return $appMatch.Groups['package'].Value }
    return ""
}

function Start-MobileActivity {
    param([string]$Adb, [string]$Serial)
    & $Adb -s $Serial shell am start -W -n "$packageName/$activityName"
    Assert-LastExitCode "Application cold start"
}

function Ensure-MobileForeground {
    param([string]$Adb, [string]$Serial)
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $focusedPackage = Get-FocusedPackage $Adb $Serial
        if ($focusedPackage -eq $packageName) { return }
        & $Adb -s $Serial shell input keyevent KEYCODE_HOME | Out-Null
        Assert-LastExitCode "Return device to launcher before VisionForge relaunch"
        Start-MobileActivity $Adb $Serial | Out-Null
        Start-Sleep -Milliseconds (400 * $attempt)
    }
    $focusedPackage = Get-FocusedPackage $Adb $Serial
    throw "VisionForge Mobile is not foreground after launch attempts. focused_package=$focusedPackage expected=$packageName"
}

function Invoke-ScrollForward {
    param([string]$Adb, [string]$Serial, [xml]$Document, [string]$Description)
    $node = Find-ScrollableNode $Document
    Assert-Node $node "$Description scroll container"
    if ($node.bounds -notmatch '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$') {
        throw "Invalid UI bounds for $Description scroll container: $($node.bounds)"
    }
    $left = [int]$Matches[1]
    $top = [int]$Matches[2]
    $right = [int]$Matches[3]
    $bottom = [int]$Matches[4]
    $x = [int](($left + $right) / 2)
    $inset = [int](($bottom - $top) * 0.15)
    & $Adb -s $Serial shell input swipe $x ($bottom - $inset) $x ($top + $inset) 350 | Out-Null
    Assert-LastExitCode "Scroll $Description"
    Start-Sleep -Milliseconds 350
}

function Capture-UiState {
    param([string]$Adb, [string]$Serial, [string]$OutputDirectory, [string]$Label)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Ensure-MobileForeground $Adb $Serial
        $document = Get-UiDocument $Adb $Serial $OutputDirectory $Label
        if (Test-UiDocumentBelongsToPackage $document) {
            [void](Save-DeviceScreenshot $Adb $Serial $OutputDirectory $Label)
            return $document
        }
        Start-MobileActivity $Adb $Serial | Out-Null
        Start-Sleep -Milliseconds (500 * $attempt)
    }
    throw "UI hierarchy capture ($Label) did not belong to $packageName after relaunch attempts."
}

function Capture-ControlState {
    param([string]$Adb, [string]$Serial, [string]$OutputDirectory, [string]$Label)
    $document = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $document = Capture-UiState $Adb $Serial $OutputDirectory $Label
        if ($null -ne (Find-NodeByDescription $document 'vf.page_scroll.control')) {
            return $document
        }
        $controlNavigation = Find-NodeByDescription $document 'vf.nav.control'
        if ($null -ne $controlNavigation) {
            Invoke-NodeTap $Adb $Serial $controlNavigation "control navigation for $Label"
        }
        Start-Sleep -Milliseconds (250 * $attempt)
    }
    throw "Control page did not become visible for $Label after model/navigation update."
}

function Assert-VisibleAimTargets {
    param(
        [xml]$Document,
        [string[]]$ExpectedTargets,
        [string[]]$HiddenTargets,
        [string]$ModelLabel
    )
    foreach ($target in $ExpectedTargets) {
        Assert-VisibleNode (Find-NodeByDescription $Document "vf.aim_target.$target") `
            "$ModelLabel aim target $target"
    }
    foreach ($target in $HiddenTargets) {
        Assert-MissingOrHiddenNode (Find-NodeByDescription $Document "vf.aim_target.$target") `
            "$ModelLabel unsupported aim target $target"
    }
}

function Assert-ModelTargetMatrix {
    param([string]$Adb, [string]$Serial, [xml]$Control, [string]$OutputDirectory)
    $valorantModel = Find-NodeByDescription $Control `
        'vf.game_model.valorant-yellow-416-v11s-no-flash'
    $ow2Model = Find-NodeByDescription $Control 'vf.game_model.overwatch2-416-yolov5'
    $deltaModel = Find-NodeByDescription $Control 'vf.game_model.delta-force-416-v8s'
    $cs2Model = Find-NodeByDescription $Control `
        'vf.game_model.counter-strike-2-vombit-416-v8s'
    $valorantText = New-TextFromCodepoints @(0x65E0, 0x754F, 0x5951, 0x7EA6)
    $ow2Text = New-TextFromCodepoints @(0x5B88, 0x671B, 0x5148, 0x950B)
    $deltaText = New-TextFromCodepoints @(0x4E09, 0x89D2, 0x6D32, 0x884C, 0x52A8)
    $cs2Text = New-TextFromCodepoints @(0x53CD, 0x6050, 0x7CBE, 0x82F1, 0x32)
    Assert-VisibleNodeText $valorantModel $valorantText 'Valorant 416 model selector'
    Assert-VisibleNodeText $ow2Model $ow2Text 'OW2 416 model selector'
    Assert-VisibleNodeText $deltaModel $deltaText 'Delta Force 416 model selector'
    Assert-VisibleNodeText $cs2Model $cs2Text 'Counter-Strike 2 416 model selector'

    Assert-VisibleAimTargets $Control @('body', 'head') `
        @('teammate', 'ai', 'crosshair') 'Valorant'

    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $Control `
            'vf.game_model.overwatch2-416-yolov5') 'OW2 model selector'
    $ow2 = Capture-ControlState $Adb $Serial $OutputDirectory "03-control-ow2-targets"
    Assert-VisibleAimTargets $ow2 @('body', 'head') `
        @('teammate', 'ai', 'crosshair') 'OW2'

    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $ow2 `
            'vf.game_model.delta-force-416-v8s') 'Delta Force model selector'
    $delta = Capture-ControlState $Adb $Serial $OutputDirectory "03-control-delta-targets"
    Assert-VisibleAimTargets $delta @('body', 'head', 'teammate', 'ai', 'crosshair') `
        @() 'Delta Force'

    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $delta `
            'vf.game_model.counter-strike-2-vombit-416-v8s') `
        'Counter-Strike 2 model selector'
    $cs2 = Capture-ControlState $Adb $Serial $OutputDirectory "03-control-cs2-targets"
    Assert-VisibleAimTargets $cs2 @('ct_body', 'ct_head', 't_body', 't_head') `
        @('body', 'head', 'teammate', 'ai', 'crosshair') 'Counter-Strike 2'

    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $cs2 `
            'vf.game_model.valorant-yellow-416-v11s-no-flash') 'restore Valorant model selector'
}

function Invoke-UiAcceptance {
    param([string]$Adb, [string]$Serial)
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputDirectory = Join-Path $projectRoot "output/device-acceptance/$timestamp"
    [void](New-Item -ItemType Directory -Path $outputDirectory -Force)

    $shell = Capture-UiState $Adb $Serial $outputDirectory "01-shell"
    foreach ($navigationId in @('vf.nav.authorization', 'vf.nav.inference', 'vf.nav.control')) {
        Assert-Node (Find-NodeByDescription $shell $navigationId) $navigationId
    }
    if ($null -ne (Find-NodeByDescription $shell 'vf.nav.link')) {
        throw "Standalone link navigation must be absent after link/inference merge."
    }
    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $shell 'vf.nav.inference') 'inference navigation'
    $inference = Capture-UiState $Adb $Serial $outputDirectory "02-inference"
    Assert-Node (Find-NodeByDescription $inference 'vf.page_scroll.inference') `
        'unified inference page'
    Assert-Node (Find-NodeByDescription $inference 'vf.inference.link_status') `
        'link status inside unified inference page'
    if ($null -ne (Find-NodeByDescription $inference 'vf.inference.start') -or
        $null -ne (Find-NodeByDescription $inference 'vf.inference.stop')) {
        throw 'Manual inference start/stop controls must be absent in automatic Host-driven mode.'
    }

    Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $inference 'vf.nav.control') 'control navigation'
    $control = Capture-UiState $Adb $Serial $outputDirectory "03-control"
    Assert-Node (Find-NodeByDescription $control 'vf.page_scroll.control') 'control page'
    if ($null -ne (Find-NodeByDescription $control 'vf.control_output_toggle')) {
        throw "Removed control-lock prompt card is still present."
    }
    $removedControlLockText = New-TextFromCodepoints @(
        33258, 21160, 25511, 21046, 24050, 38381, 38145)
    if ($control.OuterXml.Contains($removedControlLockText)) {
        throw "Removed control-lock prompt text is still present."
    }
    Assert-ModelTargetMatrix $Adb $Serial $control $outputDirectory

    $diagnosticsToggle = Find-NodeByDescription $control 'vf.diagnostics_toggle'
    if ($null -ne $diagnosticsToggle) {
        Invoke-NodeTap $Adb $Serial $diagnosticsToggle 'diagnostics navigation'
        $diagnostics = Capture-UiState $Adb $Serial $outputDirectory "04-diagnostics"
        $rawToggle = Find-NodeByResourceId $diagnostics 'diagnostics_raw_toggle'
        foreach ($attempt in 1..3) {
            if ($null -ne $rawToggle) { break }
            Invoke-ScrollForward $Adb $Serial $diagnostics 'diagnostics page'
            $diagnostics = Capture-UiState $Adb $Serial $outputDirectory "04-diagnostics-actions-$attempt"
            $rawToggle = Find-NodeByResourceId $diagnostics 'diagnostics_raw_toggle'
        }
        Assert-Node $rawToggle 'diagnostics raw-report toggle'
        Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $diagnostics 'vf.nav.inference') 'inference navigation restore'
    } else {
        Invoke-NodeTap $Adb $Serial (Find-NodeByDescription $control 'vf.nav.inference') 'inference navigation restore'
    }
    Write-Host "VISIONFORGE_MOBILE_UI_OK screenshots=$outputDirectory unified_inference=true control_lock_card_absent=true"
    return $outputDirectory
}

function Resolve-PythonPath {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $pythonCommand) { return $pythonCommand.Source }
    $pyCommand = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $pyCommand) { return $pyCommand.Source }
    throw "Python is required to generate formal device evidence."
}

function Assert-AndroidProductionSigningInputs {
    param([string]$Root)
    $python = Resolve-PythonPath
    $script = Join-Path $Root "tools/verify_android_production_signing_inputs.py"
    & $python $script
    Assert-LastExitCode "Android production release signing preflight"
}

function Write-FormalDeviceEvidence {
    param(
        [string]$Adb,
        [string]$Serial,
        [string]$Apk,
        [string]$OutputDirectory,
        [string]$InstalledPackageVersion,
        [string]$WindowsExe,
        [string]$HostExe,
        [string]$BluetoothRouteEvidence,
        [string]$BluetoothRouteMobileLog,
        [string]$MakcuRouteEvidence,
        [string]$MakcuRouteMobileLog,
        [string]$FinalSafeIdleEvidence,
        [string]$FinalSafeIdleMobileLog,
        [string]$FinalSafeIdleUiXml
    )
    $mobileLog = Join-Path $OutputDirectory "mobile-logcat.txt"
    & $Adb -s $Serial logcat -d -v time > $mobileLog
    Assert-LastExitCode "Formal device evidence logcat capture"
    $python = Resolve-PythonPath
    $script = Join-Path $workspaceRoot "tools/create_formal_device_evidence.py"
    $arguments = @(
        $script,
        "--android-apk", $Apk,
        "--ui-evidence-dir", $OutputDirectory,
        "--mobile-log", $mobileLog,
        "--device-serial", $Serial,
        "--installed-package-version", $InstalledPackageVersion,
        "--apk-installed",
        "--output", (Join-Path $OutputDirectory "formal_device_evidence.json"),
        "--require-complete"
    )
    if (-not [string]::IsNullOrWhiteSpace($WindowsExe)) {
        $arguments += @("--windows-exe", $WindowsExe)
    }
    if (-not [string]::IsNullOrWhiteSpace($HostExe)) {
        $arguments += @("--host-exe", $HostExe)
    }
    $routeInputs = @(
        [pscustomobject]@{
            name = "Bluetooth HID"
            evidence = $BluetoothRouteEvidence
            mobile_log = $BluetoothRouteMobileLog
            evidence_argument = "--bluetooth-route-evidence"
        },
        [pscustomobject]@{
            name = "MAKCU"
            evidence = $MakcuRouteEvidence
            mobile_log = $MakcuRouteMobileLog
            evidence_argument = "--makcu-route-evidence"
        }
    )
    foreach ($routeInput in $routeInputs) {
        if ([string]::IsNullOrWhiteSpace($routeInput.evidence) -or
            [string]::IsNullOrWhiteSpace($routeInput.mobile_log)) {
            throw "$($routeInput.name) physical route evidence and mobile log are required for formal release evidence."
        }
        if (-not (Test-Path -LiteralPath $routeInput.evidence -PathType Leaf)) {
            throw "$($routeInput.name) physical route evidence is missing: $($routeInput.evidence)"
        }
        if (-not (Test-Path -LiteralPath $routeInput.mobile_log -PathType Leaf)) {
            throw "$($routeInput.name) mobile event log is missing: $($routeInput.mobile_log)"
        }
        $arguments += @(
            $routeInput.evidence_argument,
            (Resolve-Path -LiteralPath $routeInput.evidence).Path,
            "--mobile-log",
            (Resolve-Path -LiteralPath $routeInput.mobile_log).Path
        )
    }
    $safeIdleInputs = @(
        [pscustomobject]@{
            name = "final safe-idle evidence"
            value = $FinalSafeIdleEvidence
        },
        [pscustomobject]@{
            name = "final safe-idle mobile event log"
            value = $FinalSafeIdleMobileLog
        },
        [pscustomobject]@{
            name = "final safe-idle UI XML"
            value = $FinalSafeIdleUiXml
        }
    )
    foreach ($safeIdleInput in $safeIdleInputs) {
        if ([string]::IsNullOrWhiteSpace($safeIdleInput.value)) {
            throw "$($safeIdleInput.name) is required for formal release evidence."
        }
        if (-not (Test-Path -LiteralPath $safeIdleInput.value -PathType Leaf)) {
            throw "$($safeIdleInput.name) is missing: $($safeIdleInput.value)"
        }
    }
    $resolvedSafeIdleEvidence =
        (Resolve-Path -LiteralPath $FinalSafeIdleEvidence).Path
    $resolvedSafeIdleMobileLog =
        (Resolve-Path -LiteralPath $FinalSafeIdleMobileLog).Path
    $resolvedSafeIdleUiXml =
        (Resolve-Path -LiteralPath $FinalSafeIdleUiXml).Path
    $archivedSafeIdleUiXml = Join-Path $OutputDirectory "05-final-safe-idle.xml"
    Copy-Item -LiteralPath $resolvedSafeIdleUiXml -Destination $archivedSafeIdleUiXml -Force
    $arguments += @(
        "--final-safe-idle-evidence", $resolvedSafeIdleEvidence,
        "--mobile-log", $resolvedSafeIdleMobileLog
    )
    & $python @arguments
    Assert-LastExitCode "Formal device evidence generation"
    return Join-Path $OutputDirectory "formal_device_evidence.json"
}

$adb = Resolve-AdbPath $AdbPath $workspaceRoot

if ($Build) {
    if (-not $AllowDevelopmentSigning) {
        Assert-AndroidProductionSigningInputs $workspaceRoot
    }
    $defaultQnnRoot = Join-Path $projectRoot "qnn_sdk/qairt/2.37.1.250807"
    $qnnRoot = if ([string]::IsNullOrWhiteSpace($env:QNN_SDK_ROOT)) {
        $defaultQnnRoot
    } else {
        $env:QNN_SDK_ROOT
    }
    if (-not (Test-Path -LiteralPath $qnnRoot)) { throw "QNN SDK missing: $qnnRoot" }
    $qnnRoot = (Resolve-Path -LiteralPath $qnnRoot).Path
    $env:QNN_SDK_ROOT = $qnnRoot
    $gradleArguments = @(':app:verifyMobileRuntimeSnapshot', ':app:assembleRelease', '--offline')
    if ($AllowDevelopmentSigning) {
        $gradleArguments += '-PvisionforgeAllowDevelopmentSigning=true'
    }
    Push-Location $projectRoot
    try {
        & .\gradlew.bat @gradleArguments
        Assert-LastExitCode "Android release build"
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path -LiteralPath $apk)) {
    throw "APK missing: $apk. Re-run with -Build for the default release APK or pass an existing -ApkPath."
}
$apk = (Resolve-Path -LiteralPath $apk).Path
Assert-MobileApkPathLooksReleaseCandidate $apk
Assert-MobileApkContainsMigrationModels $apk
Assert-MobileApkFreshForMigration $apk $projectRoot
Assert-MobileApkSigningIdentity $apk $workspaceRoot ([bool]$AllowDevelopmentSigning)

$serial = Resolve-DeviceSerial $adb $DeviceSerial
$legacyPackagePresentBeforeInstall =
    Test-DevicePackageInstalled $adb $serial $legacyBenchmarkPackageName
if ($legacyPackagePresentBeforeInstall) {
    [void](Stop-DevicePackageIfPresent $adb $serial $legacyBenchmarkPackageName)
    if ($RemoveLegacyBenchmarkPackage) {
        & $adb -s $serial uninstall $legacyBenchmarkPackageName | Out-Null
        Assert-LastExitCode "Legacy benchmark package uninstall"
        $legacyPackagePresentBeforeInstall = $false
    } else {
        Write-Warning (
            "Legacy package $legacyBenchmarkPackageName is installed and was force-stopped. " +
            "The production package is $packageName; uninstall the legacy app manually, " +
            "or rerun with -RemoveLegacyBenchmarkPackage if its local data is no longer needed.")
    }
}
$installOutput = Invoke-MobileApkInstall $adb $serial $apk
if (-not (Test-DevicePackageInstalled $adb $serial $packageName)) {
    throw "APK installation reported success, but package $packageName is not installed."
}
$installedPackage = Get-InstalledPackageSummary $adb $serial $packageName
if ($installedPackage.debuggable) {
    throw (
        "Installed package $packageName is DEBUGGABLE and cannot be used for " +
        "formal CAT6/model acceptance. Install a current signed release APK. " +
        "versionName=$($installedPackage.version_name) pkgFlags=[$($installedPackage.pkg_flags)]")
}

$uiEvidence = "not_requested"
$formalDeviceEvidence = "not_requested"
if ($Launch -or $VerifyUi) {
    & $adb -s $serial logcat -c
    Assert-LastExitCode "Logcat reset"
    & $adb -s $serial shell am force-stop $packageName
    Assert-LastExitCode "Application force-stop"
    & $adb -s $serial shell pm grant $packageName android.permission.POST_NOTIFICATIONS `
        2>$null | Out-Null
    Start-MobileActivity $adb $serial
    Start-Sleep -Seconds 1
    Ensure-MobileForeground $adb $serial

    $appProcessId = (& $adb -s $serial shell pidof $packageName).Trim()
    if ([string]::IsNullOrWhiteSpace($appProcessId)) {
        throw "Application process is not running after launch."
    }
    $fatalLog = & $adb -s $serial logcat -d -v brief 'AndroidRuntime:E' '*:S' |
        Select-String -Pattern 'FATAL EXCEPTION|Process: com\.visionforge\.mobile'
    if ($fatalLog) { throw "AndroidRuntime fatal exception detected after launch.`n$fatalLog" }

    if ($VerifyUi) {
        $windowState = (& $adb -s $serial shell dumpsys window) -join "`n"
        if ($windowState -match 'isKeyguardShowing=true') {
            throw "UI verification is blocked by the device PIN keyguard. Unlock normally and rerun -VerifyUi."
        }
        $uiEvidence = Invoke-UiAcceptance $adb $serial
        $formalDeviceEvidence = Write-FormalDeviceEvidence `
            $adb $serial $apk $uiEvidence $installedPackage.version_name `
            $WindowsExePath $HostExePath `
            $BluetoothRouteEvidencePath $BluetoothRouteMobileLogPath `
            $MakcuRouteEvidencePath $MakcuRouteMobileLogPath `
            $FinalSafeIdleEvidencePath $FinalSafeIdleMobileLogPath `
            $FinalSafeIdleUiXmlPath
    }
}

$sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $apk).Hash
Write-Output (
    "VISIONFORGE_MOBILE_INSTALL_OK apk=$apk device=$serial sha256=$sha256 " +
    "package_version=$($installedPackage.version_name) package_debuggable=$($installedPackage.debuggable) " +
    "legacy_package_present_before_install=$legacyPackagePresentBeforeInstall " +
    "install_output={$installOutput} ui_evidence=$uiEvidence " +
    "formal_device_evidence=$formalDeviceEvidence")
