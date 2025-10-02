param(
  [int]$Tail = 200
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Determine data dir like run-web.ps1
if ($env:CSE_DATA_DIR -and (Test-Path $env:CSE_DATA_DIR)) {
  $DataDir = $env:CSE_DATA_DIR
} else {
  $DataDir = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot '..\data'))
}

$LogDir = Join-Path $DataDir 'logs'
if (-not (Test-Path $LogDir)) {
  Write-Warning "No log directory at $LogDir"
  exit 1
}

$files = @()
$files += Get-ChildItem $LogDir -Filter 'web-*.log' -ErrorAction SilentlyContinue
$files += Get-ChildItem $LogDir -Filter 'webdll-*.log' -ErrorAction SilentlyContinue
$latest = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $latest) {
  Write-Warning "No web log files found in $LogDir"
  exit 1
}

Write-Host "Showing last $Tail lines of: $($latest.FullName)"
Get-Content -LiteralPath $latest.FullName -Tail $Tail
