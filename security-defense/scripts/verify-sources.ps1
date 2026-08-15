[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$defenseRoot = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $defenseRoot 'vendor\sources.lock.json'
$lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json

$failures = [System.Collections.Generic.List[string]]::new()
foreach ($source in $lock.sources) {
    $archivePath = Join-Path $defenseRoot $source.archive
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        $failures.Add("Missing archive: $($source.name)")
        continue
    }

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $source.sha256) {
        $failures.Add("SHA-256 mismatch: $($source.name)")
        continue
    }

    Write-Output "verified=$($source.name) version=$($source.version) sha256=$actualHash"
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}
