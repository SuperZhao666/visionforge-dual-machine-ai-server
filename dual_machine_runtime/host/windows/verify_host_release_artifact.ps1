[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$VersionFile,

    [Parameter(Mandatory = $true)]
    [string]$PrivateSymbolsDirectory,

    [switch]$RequireAuthenticode
)

Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$ErrorActionPreference = 'Stop'

function Invoke-DumpBin {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $output = & $script:DumpBinPath @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
    return $output
}

function Require-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($Text -notmatch $Pattern) {
        throw "VF Host release is missing $Description"
    }
}

function Write-Utf8WithoutBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Contents
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Contents,
        [System.Text.UTF8Encoding]::new($false))
}

$resolvedExe = (Resolve-Path -LiteralPath $ExePath).Path
$exe = Get-Item -LiteralPath $resolvedExe
if ($exe.Name -cne 'VFHost.exe' -or $exe.Length -le 0) {
    throw "Formal Host artifact must be a non-empty VFHost.exe: $resolvedExe"
}

$resolvedVersionFile = (Resolve-Path -LiteralPath $VersionFile).Path
$releaseVersion = [System.IO.File]::ReadAllText($resolvedVersionFile).Trim()
if ($releaseVersion -notmatch '^([0-9]+)\.([0-9]+)\.([0-9]+)$') {
    throw "Dual-machine release version must be stable SemVer: $releaseVersion"
}
$expectedWindowsVersion = "$releaseVersion.0"
$versionInfo = $exe.VersionInfo
if ($versionInfo.FileVersion -ne $expectedWindowsVersion -or
    $versionInfo.ProductVersion -ne $expectedWindowsVersion) {
    throw "VF Host version metadata mismatch: expected=$expectedWindowsVersion file=$($versionInfo.FileVersion) product=$($versionInfo.ProductVersion)"
}

$dumpBin = Get-Command dumpbin.exe -ErrorAction Stop
$script:DumpBinPath = $dumpBin.Source
$headers = Invoke-DumpBin -Arguments @('/headers', $resolvedExe)
$loadConfig = Invoke-DumpBin -Arguments @('/loadconfig', $resolvedExe)
$dependents = Invoke-DumpBin -Arguments @('/dependents', $resolvedExe)

Require-Text $headers '(?im)^\s*8664 machine \(x64\)\s*$' 'x64 machine identity'
Require-Text $headers '(?im)^\s*2 subsystem \(Windows GUI\)\s*$' 'Windows GUI subsystem'
Require-Text $headers '(?im)^\s*High Entropy Virtual Addresses\s*$' 'High Entropy VA'
Require-Text $headers '(?im)^\s*Dynamic base\s*$' 'ASLR/Dynamic Base'
Require-Text $headers '(?im)^\s*NX compatible\s*$' 'DEP/NX compatibility'
Require-Text $headers '(?im)^\s*Control Flow Guard\s*$' 'Control Flow Guard image flag'
Require-Text $headers '(?im)^\s*CET compatible\s*$' 'CET compatibility'
Require-Text $loadConfig '(?im)^\s*CF instrumented\s*$' 'Control Flow Guard instrumentation'

$guardCountMatch = [regex]::Match(
    $loadConfig,
    '(?im)^\s*([0-9A-F]+)\s+Guard CF function count\s*$')
if (-not $guardCountMatch.Success -or
    [Convert]::ToInt32($guardCountMatch.Groups[1].Value, 16) -le 0) {
    throw 'VF Host release has no guarded Control Flow Guard functions'
}
$guardFunctionCount = [Convert]::ToInt32(
    $guardCountMatch.Groups[1].Value,
    16)

if ($dependents -match '(?im)^\s*(?:MSVCP\d+|VCRUNTIME\d*(?:_\d+)?|UCRTBASE)\.DLL\s*$') {
    throw 'VF Host release unexpectedly depends on a dynamic MSVC/UCRT runtime'
}

$siblingPdb = [System.IO.Path]::ChangeExtension($resolvedExe, '.pdb')
if (Test-Path -LiteralPath $siblingPdb) {
    throw "Private Host PDB must not be shipped beside the EXE: $siblingPdb"
}

$sha256 = (Get-FileHash -LiteralPath $resolvedExe -Algorithm SHA256).Hash.ToLowerInvariant()
$resolvedSymbolsDirectory = (Resolve-Path -LiteralPath $PrivateSymbolsDirectory).Path
$archivedPdb = Join-Path $resolvedSymbolsDirectory "$sha256.pdb"
$archivedManifest = Join-Path $resolvedSymbolsDirectory "$sha256.json"
if (-not (Test-Path -LiteralPath $archivedPdb -PathType Leaf) -or
    (Get-Item -LiteralPath $archivedPdb).Length -le 0) {
    throw "Private Host PDB archive is missing for EXE $sha256"
}
if (-not (Test-Path -LiteralPath $archivedManifest -PathType Leaf)) {
    throw "Private Host symbol manifest is missing for EXE $sha256"
}
$symbolManifest = Get-Content -LiteralPath $archivedManifest -Raw | ConvertFrom-Json
$archivedPdbSha256 = (Get-FileHash -LiteralPath $archivedPdb -Algorithm SHA256).Hash.ToLowerInvariant()
if ($symbolManifest.executable_sha256 -ne $sha256 -or
    $symbolManifest.pdb_sha256 -ne $archivedPdbSha256 -or
    $symbolManifest.distribution -ne 'private_do_not_ship') {
    throw "Private Host symbol manifest does not close over EXE $sha256"
}

$signature = [pscustomobject]@{
    Status = 'NotRequested'
    SignerCertificate = $null
}
if ($RequireAuthenticode) {
    # The normal build gate does not require a platform certificate. Avoid
    # loading the Security module in that mode because this workstation's
    # PowerShell 7 compatibility module conflicts with Windows PowerShell's
    # extended type data. The strict switch still loads the native verifier.
    Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedExe
}
if ($RequireAuthenticode -and $signature.Status -ne 'Valid') {
    throw "VF Host Authenticode signature is required but status is $($signature.Status)"
}

$reportPath = "$resolvedExe.verify.json"
$sha256Path = "$resolvedExe.sha256"
$report = [ordered]@{
    schema = 'visionforge-host-release-artifact-v1'
    ok = $true
    generated_at = [DateTime]::UtcNow.ToString('o')
    executable = $resolvedExe
    executable_bytes = $exe.Length
    executable_sha256 = $sha256
    release_version = $releaseVersion
    windows_file_version = $versionInfo.FileVersion
    windows_product_version = $versionInfo.ProductVersion
    machine = 'x64'
    subsystem = 'windows_gui'
    mitigations = [ordered]@{
        high_entropy_va = $true
        dynamic_base_aslr = $true
        nx_compatible = $true
        control_flow_guard = $true
        control_flow_guard_function_count = $guardFunctionCount
        cet_compatible = $true
        static_msvc_runtime = $true
    }
    authenticode = [ordered]@{
        required = [bool]$RequireAuthenticode
        status = [string]$signature.Status
        signer_subject = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        } else {
            ''
        }
    }
    private_symbols = [ordered]@{
        archived = $true
        distribution = 'private_do_not_ship'
        manifest = $archivedManifest
        pdb_sha256 = $archivedPdbSha256
        sibling_pdb_absent = $true
    }
}

Write-Utf8WithoutBom $sha256Path "$sha256  $($exe.Name)`n"
Write-Utf8WithoutBom $reportPath (($report | ConvertTo-Json -Depth 6) + "`n")
Write-Host "Verified Host release artifact: $resolvedExe"
Write-Host "Host release SHA256: $sha256"
Write-Host "Host release verification report: $reportPath"
