param(
  [int]$Count = 100,
  [string]$OutDir = "..\\samples\\threats\\real"
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Write-Host "Fetching $Count entries from Feodo Tracker …"
$resp = Invoke-WebRequest -Uri 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv' -UseBasicParsing -TimeoutSec 60
$lines = ($resp.Content -split "`n") | ForEach-Object { $_.TrimEnd() }
$nonComment = $lines | Where-Object { $_ -and ($_ -notmatch '^#') }
if ($nonComment.Count -lt 2) { throw "No data in Feodo Tracker CSV" }
$header = $nonComment[0]
$dataOnly = $nonComment | Select-Object -Skip 1
$rows = (($dataOnly -join "`n") | ConvertFrom-Csv -Header ($header -split ','))

$i = 0
foreach ($row in $rows) {
  if ($i -ge $Count) { break }
  $ip = [string]$row.ip_address
  if ([string]::IsNullOrWhiteSpace($ip)) { continue }
  $family = if ($row.family) { [string]$row.family } else { 'Feodo' }
  $model = [ordered]@{
    name = "Feodo C2 [$ip]"
    family = $family
    confidence = 0.7
    sources = @('abuse.ch:FeodoTracker')
    file = [ordered]@{ hashes = @(); strings = @(); hex_patterns = @(); pe_features = @() }
    network = [ordered]@{ domains = @(); uris = @(); ports = @(); ips = @($ip) }
    log = [ordered]@{ windows = [ordered]@{ event_id = @(); cmdline_contains = @() } }
    tags = @('c2','ip')
  }
  $fileName = ("feodo_${i+1:000}.json")
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
  $i++
}
Write-Host "Saved $i files to $outPath"
