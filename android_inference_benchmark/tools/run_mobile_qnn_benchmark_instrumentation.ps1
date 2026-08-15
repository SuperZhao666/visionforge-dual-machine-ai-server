param(
    [switch]$Build,
    [string]$ModelToken,
    [string]$DeviceSerial = $env:ANDROID_SERIAL,
    [string]$AdbPath = $env:VISIONFORGE_ADB,
    [string]$MainApkPath,
    [string]$TestApkPath,
    [string]$QnnSdkRoot,
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
trap {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}

$projectRoot = Split-Path $PSScriptRoot -Parent
$workspaceRoot = Split-Path $projectRoot -Parent
$packageName = "com.visionforge.mobile"
$testPackageName = "com.visionforge.mobile.test"
$instrumentationClass = "com.visionforge.inferencebenchmark.PairingIdentityTestInstrumentation"
$defaultMainApk = Join-Path $projectRoot "app/build/outputs/apk/debug/app-debug.apk"
$defaultTestApk = Join-Path $projectRoot "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"

function Resolve-LocalPath {
    param([string]$Path, [string]$DefaultPath)
    $candidate = if ([string]::IsNullOrWhiteSpace($Path)) {
        $DefaultPath
    } elseif ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    } else {
        Join-Path $projectRoot $Path
    }
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Required file is missing: $candidate"
    }
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Resolve-AdbPath {
    param([string]$RequestedPath)
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) { $candidates += $RequestedPath }
    $candidates += (Join-Path $workspaceRoot ".android-sdk/platform-tools/adb.exe")
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $pathCommand = Get-Command adb -ErrorAction SilentlyContinue
    if ($null -ne $pathCommand) { return $pathCommand.Source }
    throw "ADB missing. Pass -AdbPath, set VISIONFORGE_ADB, or install the workspace Android SDK."
}

function Resolve-DeviceSerial {
    param([string]$Adb, [string]$RequestedSerial)
    $onlineSerials = @(& $Adb devices | Select-Object -Skip 1 | ForEach-Object {
        if ($_ -match '^(\S+)\s+device$') { $Matches[1] }
    })
    if (-not [string]::IsNullOrWhiteSpace($RequestedSerial)) {
        if ($onlineSerials -notcontains $RequestedSerial) {
            throw "Requested ADB device is not online: $RequestedSerial"
        }
        return $RequestedSerial
    }
    $deduplicatedSerials = @($onlineSerials | Group-Object -Property {
        Normalize-AdbSerial $_
    } | ForEach-Object {
        $_.Group | Select-Object -First 1
    })
    if ($deduplicatedSerials.Count -ne 1) {
        $mdns = ((& $Adb mdns services 2>$null) | Out-String).Trim()
        throw "Expected exactly one authorised ADB device, found $($onlineSerials.Count) entries / $($deduplicatedSerials.Count) unique devices.`n$mdns"
    }
    return $deduplicatedSerials[0]
}

function Normalize-AdbSerial {
    param([string]$Serial)
    if ([string]::IsNullOrWhiteSpace($Serial)) { return "" }
    return ($Serial -replace '\s+\(\d+\)(?=\._adb-tls-connect\._tcp$)', '')
}

function Assert-LastExitCode {
    param([string]$Operation)
    if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." }
}

function Invoke-GradleBuild {
    param([string]$SdkRoot)
    if ([string]::IsNullOrWhiteSpace($SdkRoot)) {
        $SdkRoot = Join-Path $projectRoot "qnn_sdk/qairt/2.37.1.250807"
    }
    if (-not (Test-Path -LiteralPath $SdkRoot)) {
        throw "QNN SDK root is missing: $SdkRoot"
    }
    $env:GRADLE_USER_HOME = Join-Path $workspaceRoot ".gradle-user-home"
    Push-Location $projectRoot
    try {
        & .\gradlew.bat --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest `
            "-PqnnSdkRoot=$((Resolve-Path -LiteralPath $SdkRoot).Path)"
        Assert-LastExitCode "Gradle debug APK build"
    } finally {
        Pop-Location
    }
}

function Invoke-ApkInstall {
    param([string]$Adb, [string]$Serial, [string]$Apk)
    & $Adb -s $Serial install -r $Apk
    Assert-LastExitCode "Install $Apk"
}

function Get-DeviceIdentity {
    param([string]$Adb, [string]$Serial)
    $propertyNames = @(
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.product.device",
        "ro.soc.manufacturer",
        "ro.soc.model",
        "ro.board.platform",
        "ro.hardware",
        "ro.build.version.release",
        "ro.build.fingerprint"
    )
    $identity = [ordered]@{ adb_device = $Serial }
    foreach ($propertyName in $propertyNames) {
        $identity[$propertyName] = ((& $Adb -s $Serial shell "getprop $propertyName") | Out-String).Trim()
    }
    return $identity
}

if ($Build) {
    Invoke-GradleBuild $QnnSdkRoot
}

$adb = Resolve-AdbPath $AdbPath
$serial = Resolve-DeviceSerial $adb $DeviceSerial
$mainApk = Resolve-LocalPath $MainApkPath $defaultMainApk
$testApk = Resolve-LocalPath $TestApkPath $defaultTestApk

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputDirectory = Join-Path $workspaceRoot "analysis_output/mobile_qnn_benchmark_$timestamp"
} elseif (-not [System.IO.Path]::IsPathRooted($OutputDirectory)) {
    $OutputDirectory = Join-Path $workspaceRoot $OutputDirectory
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

Invoke-ApkInstall $adb $serial $mainApk
Invoke-ApkInstall $adb $serial $testApk

$identity = Get-DeviceIdentity $adb $serial
$identityPath = Join-Path $OutputDirectory "device_identity.json"
[System.IO.File]::WriteAllText(
    $identityPath,
    (($identity | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    [System.Text.UTF8Encoding]::new($false)
)

& $adb -s $serial shell am force-stop $packageName | Out-Null

$instrumentArgs = @(
    "-s", $serial,
    "shell", "am", "instrument", "-w",
    "-e", "mode", "qnn_benchmark"
)
if (-not [string]::IsNullOrWhiteSpace($ModelToken)) {
    $instrumentArgs += @("-e", "modelToken", $ModelToken)
}
$instrumentArgs += "$testPackageName/$instrumentationClass"

$output = & $adb @instrumentArgs 2>&1
$outputPath = Join-Path $OutputDirectory "mobile_qnn_benchmark.txt"
$output | Set-Content -LiteralPath $outputPath -Encoding utf8
$text = ($output | Out-String)
if ($LASTEXITCODE -ne 0 -or $text -notmatch "MOBILE_QNN_BENCHMARK_OK") {
    throw "Mobile QNN benchmark failed. Output saved to $outputPath"
}

Write-Output "MOBILE_QNN_BENCHMARK_SCRIPT_OK serial=$serial output=$outputPath identity=$identityPath"
