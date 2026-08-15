param(
    [string]$BundleDirectory = "android_inference_benchmark/qnn_workspace/device_bundle",
    [string]$DeviceDirectory = "/data/local/tmp/visionforge_qnn_htp"
)

$ErrorActionPreference = "Stop"
$utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
$adb = Join-Path (Get-Location) ".android-sdk/platform-tools/adb.exe"
if (-not (Test-Path $adb)) { throw "ADB missing: $adb" }
$bundle = (Resolve-Path $BundleDirectory).Path
$devices = & $adb devices | Select-Object -Skip 1 | Where-Object { $_ -match "\tdevice$" }
if ($devices.Count -ne 1) { throw "Expected exactly one authorized ADB device, found $($devices.Count)." }
if ($DeviceDirectory -ne "/data/local/tmp/visionforge_qnn_htp") {
    throw "DeviceDirectory is intentionally fixed to the isolated VisionForge QNN staging directory."
}

$propertyNames = @(
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.soc.manufacturer",
    "ro.soc.model",
    "ro.board.platform",
    "ro.hardware",
    "ro.build.version.release",
    "ro.build.fingerprint"
)
$identity = [ordered]@{}
foreach ($propertyName in $propertyNames) {
    $identity[$propertyName] = ((& $adb shell "getprop $propertyName") | Out-String).Trim()
}
$identity["adb_device"] = (($devices | Select-Object -First 1) -split "`t")[0]
$identityPath = Join-Path $bundle "device_identity.json"
[System.IO.File]::WriteAllText(
    $identityPath,
    (($identity | ConvertTo-Json) + [Environment]::NewLine),
    $utf8WithoutBom
)

# The bundle manifest is generated from the exact SDK that supplied its runtime
# closure. Never search another installed SDK for a potentially different enum.
$manifestPath = Join-Path $bundle "manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "QNN HTP bundle manifest is missing: $manifestPath"
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$socModels = @{}
foreach ($property in @($manifest.soc_models.PSObject.Properties)) {
    if ($property.Name -notmatch '^SM\d+$' -or
            "$($property.Value)" -notmatch '^\d+$') {
        throw "QNN HTP bundle manifest contains an invalid SoC mapping."
    }
    $socModels[$property.Name] = [int]$property.Value
}
if ($socModels.Count -eq 0) {
    throw "QNN HTP bundle manifest has no SDK-bound SoC mapping. Rebuild the bundle."
}
$detectedText = ($identity.Values -join " ").ToUpperInvariant()
$socArchitectures = @{}
foreach ($property in @($manifest.soc_architectures.PSObject.Properties)) {
    $architecture = "$($property.Value)".ToLowerInvariant()
    if ($property.Name -notmatch '^(SM|QCM)\d{4}$' -or
            $architecture -notmatch '^v\d{2,3}$') {
        throw "QNN HTP bundle manifest contains an invalid SoC architecture entry."
    }
    $socArchitectures[$property.Name] = $architecture
}
if ($socArchitectures.Count -eq 0) {
    throw "QNN HTP bundle manifest has no SoC architecture catalog. Rebuild the bundle."
}
$packagedArchitectures = @($manifest.htp_architectures | ForEach-Object {
        "$($_)".ToLowerInvariant()
    })
$knownSoc = $socArchitectures.Keys | Where-Object {
    $socPattern = [regex]::Escape($_)
    $detectedText -match "(^|[^A-Z0-9])$socPattern([^A-Z0-9]|$)"
} | Select-Object -First 1
if ($knownSoc) {
    $expectedArchitecture = $socArchitectures[$knownSoc]
    if ($packagedArchitectures -notcontains $expectedArchitecture) {
        throw (
            "Known device $knownSoc requires HTP $expectedArchitecture, " +
            "but bundle packages: $($packagedArchitectures -join ',').")
    }
}
$matchedSoc = $socModels.Keys | Where-Object {
    $socPattern = [regex]::Escape($_)
    $detectedText -match "(^|[^A-Z0-9])$socPattern([^A-Z0-9]|$)"
} | Select-Object -First 1
if ($matchedSoc) {
    $configPath = Join-Path $bundle "htp_config.json"
    $config = Get-Content $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.devices[0] | Add-Member -Force -NotePropertyName soc_model -NotePropertyValue $socModels[$matchedSoc]
    [System.IO.File]::WriteAllText(
        $configPath,
        (($config | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        $utf8WithoutBom
    )
    $identity["qnn_soc_model"] = $matchedSoc
    $identity["qnn_soc_model_id"] = $socModels[$matchedSoc]
    [System.IO.File]::WriteAllText(
        $identityPath,
        (($identity | ConvertTo-Json) + [Environment]::NewLine),
        $utf8WithoutBom
    )
}

& $adb shell "rm -rf $DeviceDirectory && mkdir -p $DeviceDirectory"
if ($LASTEXITCODE -ne 0) { throw "Unable to initialize the isolated QNN staging directory." }
& $adb push "$bundle/." "$DeviceDirectory/"
if ($LASTEXITCODE -ne 0) { throw "Unable to push the QNN HTP bundle to the device." }
& $adb shell "cd $DeviceDirectory && sh ./run_htp_benchmark.sh"
$runExitCode = $LASTEXITCODE
$hostResults = Join-Path $bundle "device_results"
New-Item -ItemType Directory -Force -Path $hostResults | Out-Null
Copy-Item $identityPath $hostResults -Force
& $adb pull "$DeviceDirectory/qnn_context.log" $hostResults
& $adb pull "$DeviceDirectory/qnn_warmup.log" $hostResults
& $adb pull "$DeviceDirectory/qnn_net_run.log" $hostResults
& $adb pull "$DeviceDirectory/qnn_net_run_help.txt" $hostResults
& $adb pull "$DeviceDirectory/output/warmup/qnn-profiling-data_0.log" (Join-Path $hostResults "qnn_warmup_profiling.log")
& $adb pull "$DeviceDirectory/output/measured/qnn-profiling-data_0.log" (Join-Path $hostResults "qnn_measured_profiling.log")
& $adb pull "$DeviceDirectory/context" $hostResults
if ($runExitCode -ne 0) {
    throw "QNN HTP device command failed with exit code $runExitCode. Logs were pulled to $hostResults for diagnosis."
}
Write-Output "QNN_HTP_ADB_RUN_OK results=$hostResults"
