param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats\real"
)

<#
Fetch recent malicious URLs from Abuse.ch URLHaus JSON API and generate ThreatModel JSON files.
Usage:
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-urlhaus-json.ps1 -Count 100 -OutDir ..\samples\threats\real
#>
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

function NormalizeTags([object]$tags) {
  if ($null -eq $tags) { return @() }
  if ($tags -is [string]) { return ($tags -split '[,;|]+' | Where-Object { $_ -and $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() }) }
  try { return @($tags | ForEach-Object { [string]$_ }) } catch { return @() }
}

Write-Host "Fetching $Count entries from URLHaus JSON …"
$res = Invoke-RestMethod -Uri 'https://urlhaus-api.abuse.ch/v1/urls/recent/' -Method POST -UseBasicParsing -TimeoutSec 60
if (-not $res -or -not $res.urls) { throw "URLHaus JSON returned no data" }

$i = 0
foreach ($u in $res.urls) {
  if ($i -ge $Count) { break }
  $url = [string]$u.url
  if ([string]::IsNullOrWhiteSpace($url)) { continue }
  $threat = if ($u.threat) { [string]$u.threat } else { 'Unknown' }
  $id = if ($u.id) { [string]$u.id } else { ([Guid]::NewGuid().ToString('N')) }
  $tags = NormalizeTags $u.tags
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

  $fileName = ("urlhaus_json_${i+1:000}_${threat}.json" -replace "[^A-Za-z0-9._-]", "_")
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
  $i++
}

Write-Host "Saved $i files to $outPath"