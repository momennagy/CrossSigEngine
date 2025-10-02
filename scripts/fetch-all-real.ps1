param(
  [int]$CountPerSource = 100,
  [string]$OutDir = "..\samples\threats\real"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Write-Host "Fetching real data into $outPath …"

try {
  & "$PSScriptRoot\fetch-openphish.ps1" -Count $CountPerSource -OutDir $OutDir
} catch { Write-Warning ("OpenPhish fetch failed: " + $_.Exception.Message) }

try {
  & "$PSScriptRoot\fetch-urlhaus-csv.ps1" -Count $CountPerSource -OutDir $OutDir
} catch { Write-Warning ("URLHaus CSV fetch failed: " + $_.Exception.Message) }

try {
  & "$PSScriptRoot\fetch-feodotracker.ps1" -Count $CountPerSource -OutDir $OutDir
} catch { Write-Warning ("Feodo Tracker fetch failed: " + $_.Exception.Message) }

Write-Host "Done."
