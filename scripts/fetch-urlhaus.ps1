param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats\real"
)

<#
Fetch real URLs from Abuse.ch URLHaus (public feed) and generate ThreatModel JSONs.
Usage:
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-urlhaus.ps1 -Count 100 -OutDir ..\samples\threats\real
#>
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Write-Host "Fetching $Count entries from URLHaus …"
$resp = Invoke-WebRequest -Uri 'https://urlhaus.abuse.ch/downloads/csv_recent/' -UseBasicParsing -TimeoutSec 60
$lines = ($resp.Content -split "`n")
$data = ($lines | Where-Object { -not ($_ -like '#*') } | ForEach-Object { $_.TrimEnd() }) -join "`n"
if ([string]::IsNullOrWhiteSpace($data)) { throw "URLHaus feed is empty" }
$rows = $data | ConvertFrom-Csv

$i = 0
foreach ($row in $rows) {
  if ($i -ge $Count) { break }
  $url = [string]$row.url
  if ([string]::IsNullOrWhiteSpace($url)) { continue }
  $threat = if ($row.threat) { [string]$row.threat } else { 'Unknown' }
  $id = if ($row.id) { [string]$row.id } else { ([Guid]::NewGuid().ToString('N')) }
  $tags = @()
  if ($row.tags) { $tags = ($row.tags -split '[,;|]+' | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() }) }
  $hostName = $null
  try { $u = [Uri]$url; $hostName = $u.Host } catch {}

  $model = [ordered]@{
    name = "URLHaus - ${threat} [$id]"
    family = $threat
    confidence = 0.6
    sources = @('abuse.ch:URLHaus')
    file = [ordered]@{ hashes = @(); strings = @(); hex_patterns = @(); pe_features = @() }
    network = [ordered]@{ domains = @(); uris = @($url); ports = @() }
    log = [ordered]@{ windows = [ordered]@{ event_id = @(); cmdline_contains = @() } }
  }
  if ($hostName) { $model.network.domains += $hostName }
  if ($tags -and $tags.Count -gt 0) { $model.tags = $tags }

  $fileName = "urlhaus_${i+1:000}_${threat}.json" -replace "[^A-Za-z0-9._-]", "_"
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
  $i++
}

Write-Host "Saved $i files to $outPath"