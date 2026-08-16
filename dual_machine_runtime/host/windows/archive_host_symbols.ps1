[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$PdbPath,

    [Parameter(Mandatory = $true)]
    [string]$ArchiveDirectory
)

$ErrorActionPreference = 'Stop'

$resolvedExe = (Resolve-Path -LiteralPath $ExePath).Path
$resolvedPdb = (Resolve-Path -LiteralPath $PdbPath).Path
if ((Get-Item -LiteralPath $resolvedExe).Length -le 0) {
    throw "VF Host executable is empty: $resolvedExe"
}
if ((Get-Item -LiteralPath $resolvedPdb).Length -le 0) {
    throw "VF Host PDB is empty: $resolvedPdb"
}

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return ([System.BitConverter]::ToString(
            $sha256.ComputeHash($stream)
        )).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
}

$exeHash = Get-Sha256Hex -Path $resolvedExe
$archiveRoot = [System.IO.Path]::GetFullPath($ArchiveDirectory)
[System.IO.Directory]::CreateDirectory($archiveRoot) | Out-Null

$archivedPdb = Join-Path $archiveRoot ($exeHash + '.pdb')
$manifestPath = Join-Path $archiveRoot ($exeHash + '.json')
Copy-Item -LiteralPath $resolvedPdb -Destination $archivedPdb -Force

$manifest = [ordered]@{
    schema_version = 1
    executable_sha256 = $exeHash
    executable_name = [System.IO.Path]::GetFileName($resolvedExe)
    executable_bytes = (Get-Item -LiteralPath $resolvedExe).Length
    pdb_name = [System.IO.Path]::GetFileName($archivedPdb)
    pdb_sha256 = Get-Sha256Hex -Path $archivedPdb
    pdb_bytes = (Get-Item -LiteralPath $archivedPdb).Length
    archived_utc = [DateTime]::UtcNow.ToString('o')
    distribution = 'private_do_not_ship'
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "Archived private symbols: $archivedPdb"
