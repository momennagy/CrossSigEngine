param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats\real"
)

<#
Fetch real IOCs from Abuse.ch ThreatFox and convert them into ThreatModel JSON files.
Usage:
  powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts\fetch-threatfox.ps1 -Count 100 -OutDir ..\samples\threats\real

Notes:
  - Requires Internet access.
  - Output files are suitable for /api/threats import; duplicates are handled by the API (Name+Family).
#>

$ErrorActionPreference = 'Stop'
try { [void][System.Net.Http.HttpClient] } catch { Add-Type -AssemblyName System.Net.Http }

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

function New-FileSafeName {
  param([string]$Name)
  $san = ($Name -replace "[^A-Za-z0-9._-]", "_")
  if ($san.Length -gt 120) { $san = $san.Substring(0,120) }
  return $san
}

Write-Host "Fetching $Count IOCs from ThreatFox …"
$body = @{ query = 'get_iocs'; limit = $Count } | ConvertTo-Json -Depth 4
$resp = Invoke-WebRequest -Uri 'https://threatfox-api.abuse.ch/api/v1/' -Method POST -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 60
$json = $resp.Content | ConvertFrom-Json
if (-not $json -or -not $json.data) { throw "ThreatFox returned no data" }

$i = 0
foreach ($d in $json.data) {
  $i++
  $mal = $d.malware
  if ([string]::IsNullOrWhiteSpace($mal)) { $mal = 'Unknown' }
  $ioc = [string]$d.ioc
  $iocType = [string]$d.ioc_type
  $id = $d.id
  $conf = 0.0
  if ($d.confidence_level) { $conf = [Math]::Round(([double]$d.confidence_level) / 100.0, 2) }
  $tags = @()
  if ($d.tags) { $tags = @($d.tags | ForEach-Object { [string]$_ } ) }

  # Prepare ThreatModel structure
  $hashes = @()
  switch -Regex ($iocType) {
    '^md5'    { $hashes += "md5:$ioc" }
    '^sha1'   { $hashes += "sha1:$ioc" }
    '^sha256' { $hashes += "sha256:$ioc" }
    '^sha512' { $hashes += "sha512:$ioc" }
  }

  $domains = @()
  $uris = @()
  if ($iocType -eq 'domain') { $domains += $ioc }
  elseif ($iocType -eq 'url') { $uris += $ioc }

  $nameSuffix = if ($ioc.Length -gt 16) { $ioc.Substring($ioc.Length-16) } else { $ioc }
  $modelName = "${mal} - ${iocType} [$nameSuffix]"

  $model = [ordered]@{
    name = $modelName
    family = $mal
    confidence = $conf
    sources = @('abuse.ch:ThreatFox')
    file = [ordered]@{
      hashes = $hashes
      strings = @()
      hex_patterns = @()
      pe_features = @()
    }
    network = [ordered]@{
      domains = $domains
      uris = $uris
      ports = @()
    }
    log = [ordered]@{
      windows = [ordered]@{ event_id = @(); cmdline_contains = @() }
    }
  }
  if ($tags.Count -gt 0) { $model.tags = $tags }

  $fileName = New-FileSafeName ("threatfox_${i:000}_${mal}_${iocType}.json")
  $outFile = Join-Path $outPath $fileName
  $model | ConvertTo-Json -Depth 8 | Out-File -FilePath $outFile -Encoding UTF8 -NoNewline
}

Write-Host "Saved $i files to $outPath"