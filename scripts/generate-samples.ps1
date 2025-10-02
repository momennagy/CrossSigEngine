param(
  [int]$Count = 100,
  [string]$OutDir = "..\samples\threats"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$target = Join-Path $repoRoot $OutDir
if (-not (Test-Path $target)) { New-Item -ItemType Directory -Path $target | Out-Null }

for ($i = 1; $i -le $Count; $i++) {
  $name = ('Demo Threat {0:000}' -f $i)
  $family = ('DemoFamily{0}' -f (($i % 10) + 1))
  $tag = ('batch{0}' -f ([int][math]::Ceiling($i/10)))
  $hex = '41 42 43'
  $str = ('marker_{0:000}' -f $i)
  $obj = [ordered]@{
    name = $name
    family = $family
    confidence = [Math]::Round((0.5 + (($i % 50) * 0.01)), 2)
    sources = @('generated')
    tags = @($tag)
    file = [ordered]@{
      hashes = @()
      strings = @($str)
      hex_patterns = @($hex)
      pe_features = @()
    }
    network = [ordered]@{
      domains = @()
      uris = @()
      ports = @()
    }
    log = [ordered]@{
      windows = [ordered]@{
        event_id = @()
        cmdline_contains = @()
      }
    }
  }
  $json = $obj | ConvertTo-Json -Depth 8
  $fileName = Join-Path $target ('demo_{0:000}.json' -f $i)
  [System.IO.File]::WriteAllText($fileName, $json)
}

Write-Host "Generated $Count samples in $target"