[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$VersionFile,

    [Parameter(Mandatory = $true)]
    [string]$ReportDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedSignerCertificateSha256,

    [switch]$RequireAuthenticode,

    [switch]$RequireTimestamp
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

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

function Reject-Text {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if ($Text -match $Pattern) {
        throw "VF Host release contains forbidden $Description"
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

function Get-NormalizedDirectoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar)
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

$resolvedReportDirectory = Get-NormalizedDirectoryPath -Path $ReportDirectory
$resolvedExeDirectory = Get-NormalizedDirectoryPath -Path $exe.DirectoryName
if ([string]::Equals(
        $resolvedReportDirectory,
        $resolvedExeDirectory,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Private Host verification evidence must not be written beside the distributable EXE'
}
[System.IO.Directory]::CreateDirectory($resolvedReportDirectory) | Out-Null

$publicSidecars = @(
    "$resolvedExe.verify.json",
    "$resolvedExe.sha256",
    [System.IO.Path]::ChangeExtension($resolvedExe, '.pdb')
)
foreach ($sidecar in $publicSidecars) {
    if (Test-Path -LiteralPath $sidecar) {
        throw "Private Host evidence must not be shipped beside the EXE: $sidecar"
    }
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

# A public Release build must not expose a CodeView/PDB locator or an absolute
# build-machine path. Inspect both common encodings because PE resources and
# native string literals may be ASCII or UTF-16LE.
$exeBytes = [System.IO.File]::ReadAllBytes($resolvedExe)
$asciiImage = [System.Text.Encoding]::ASCII.GetString($exeBytes)
$unicodeImage = [System.Text.Encoding]::Unicode.GetString($exeBytes)
foreach ($imageText in @($asciiImage, $unicodeImage)) {
    Reject-Text $imageText '(?i)\.pdb(?:\x00|$)' 'residual PDB/CodeView path'
    Reject-Text $imageText '(?i)(?:[A-Z]:\\(?:[^\\\x00\r\n]+\\){2,}|\\\\[^\\\x00\r\n]+\\[^\\\x00\r\n]+\\)' 'absolute build path'
}

$expectedSignerCertificateSha256Normalized =
    $ExpectedSignerCertificateSha256.Replace(':', '').Replace(' ', '').ToLowerInvariant()
if ($expectedSignerCertificateSha256Normalized -notmatch '^[0-9a-f]{64}$') {
    throw 'ExpectedSignerCertificateSha256 must be exactly 64 hexadecimal characters'
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolvedExe
if ($RequireAuthenticode -and $signature.Status -ne 'Valid') {
    throw "VF Host Authenticode signature is required but status is $($signature.Status)"
}
if ($RequireAuthenticode) {
    if ($null -eq $signature.SignerCertificate) {
        throw 'VF Host Authenticode signature has no signer certificate'
    }
    $certificateHasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualSignerCertificateSha256 = -join (
            $certificateHasher.ComputeHash($signature.SignerCertificate.RawData) |
                ForEach-Object { $_.ToString('x2') })
    } finally {
        $certificateHasher.Dispose()
    }
    if (-not [string]::Equals(
            $actualSignerCertificateSha256,
            $expectedSignerCertificateSha256Normalized,
            [StringComparison]::Ordinal)) {
        throw "VF Host signer certificate SHA-256 mismatch: actual=$actualSignerCertificateSha256"
    }
} else {
    $actualSignerCertificateSha256 = ''
}
if ($RequireTimestamp) {
    if (-not $RequireAuthenticode) {
        throw 'RequireTimestamp cannot be used without RequireAuthenticode'
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'VF Host Authenticode signature is valid but has no trusted timestamp certificate'
    }
    $timestampEku = @($signature.TimeStamperCertificate.EnhancedKeyUsageList) |
        Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.8' }
    if ($timestampEku.Count -eq 0) {
        throw 'VF Host timestamp certificate does not declare the time-stamping EKU'
    }
}

$sha256 = (Get-FileHash -LiteralPath $resolvedExe -Algorithm SHA256).Hash.ToLowerInvariant()
$reportPath = Join-Path $resolvedReportDirectory "$sha256.verify.json"
$sha256Path = Join-Path $resolvedReportDirectory "$sha256.sha256"
$report = [ordered]@{
    schema = 'visionforge-host-release-artifact-v2'
    ok = $true
    generated_at = [DateTime]::UtcNow.ToString('o')
    executable_name = $exe.Name
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
        rtti_disabled = $true
        public_pdb_locator_absent = $true
        absolute_build_path_absent = $true
    }
    authenticode = [ordered]@{
        required = [bool]$RequireAuthenticode
        timestamp_required = [bool]$RequireTimestamp
        status = [string]$signature.Status
        expected_signer_certificate_sha256 = $expectedSignerCertificateSha256Normalized
        signer_certificate_sha256 = $actualSignerCertificateSha256
        timestamp_present = $null -ne $signature.TimeStamperCertificate
        timestamper_thumbprint = if ($signature.TimeStamperCertificate) {
            $signature.TimeStamperCertificate.Thumbprint
        } else {
            ''
        }
    }
    distribution_boundary = [ordered]@{
        sibling_pdb_absent = $true
        public_verification_sidecars_absent = $true
        evidence_location = 'private_out_of_band'
    }
}

$reportJson = ($report | ConvertTo-Json -Depth 6) + "`n"
Reject-Text $reportJson '(?i)(?:[A-Z]:\\|\\\\[^\\\r\n]+\\)' 'absolute path in verification evidence'
Write-Utf8WithoutBom $sha256Path "$sha256  $($exe.Name)`n"
Write-Utf8WithoutBom $reportPath $reportJson
Write-Host "Verified signed Host release artifact: $($exe.Name)"
Write-Host "Host release SHA256: $sha256"
Write-Host "Private verification report: $reportPath"
