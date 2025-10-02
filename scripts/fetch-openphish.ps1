param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats\real"
)

<#
Fetch real phishing URLs from OpenPhish public feed and generate ThreatModel JSON files.
Usage:
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-openphish.ps1 -Count 100 -OutDir ..\samples\threats\real
#>
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Write-Host "Fetching $Count URLs from OpenPhish …"
$resp = Invoke-WebRequest -Uri 'https://openphish.com/feed.txt' -UseBasicParsing -TimeoutSec 60
$urls = $resp.Content -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -like 'http*') }
if ($urls.Count -eq 0) { throw "OpenPhish feed is empty" }

$i = 0
foreach ($url in $urls) {
  if ($i -ge $Count) { break }
  $hostName = $null
  try { $uriObj = [Uri]$url; $hostName = $uriObj.Host } catch {}
  $id = [Guid]::NewGuid().ToString('N').Substring(0,12)
  $model = [ordered]@{
    name = "OpenPhish URL [$id]"
    family = 'Phishing'
    confidence = 0.5
    sources = @('openphish')
    file = [ordered]@{ hashes = @(); strings = @(); hex_patterns = @(); pe_features = @() }
    network = [ordered]@{ domains = @(); uris = @($url); ports = @() }
    log = [ordered]@{ windows = [ordered]@{ event_id = @(); cmdline_contains = @() } }
    tags = @('phishing','url')
  }
  if ($hostName) { $model.network.domains += $hostName }
  $idx = "{0:000}" -f ($i + 1)
  $fileName = "openphish_${idx}.json"
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
  $i++
}

Write-Host "Saved $i files to $outPath"