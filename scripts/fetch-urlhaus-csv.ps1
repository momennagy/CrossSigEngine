param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats\real"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Write-Host "Fetching $Count entries from URLHaus CSV …"
$resp = Invoke-WebRequest -Uri 'https://urlhaus.abuse.ch/downloads/csv_recent/' -UseBasicParsing -TimeoutSec 60
$lines = ($resp.Content -split "`n") | ForEach-Object { $_.TrimEnd() }

# Extract header from commented line starting with '# id,'
$headerLine = $lines | Where-Object { $_ -match '^#\s*id,' } | Select-Object -First 1
if (-not $headerLine) { throw "Could not find URLHaus header" }
$header = ($headerLine -replace '^#\s*', '')

# Data lines are non-comment
$dataLines = $lines | Where-Object { $_ -and ($_ -notmatch '^#') }
if ($dataLines.Count -eq 0) { throw "No data lines in URLHaus CSV" }

$rows = ($dataLines -join "`n") | ConvertFrom-Csv -Header ($header -split ',')

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
  try { $uriObj = [Uri]$url; $hostName = $uriObj.Host } catch {}

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

  $idx = "{0:000}" -f ($i + 1)
  $fileName = ("urlhaus_csv_${idx}_${threat}.json" -replace "[^A-Za-z0-9._-]", "_")
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
  $i++
}

Write-Host "Saved $i files to $outPath"
