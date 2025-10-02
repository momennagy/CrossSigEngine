param(
  [string]$BaseUrl = "http://localhost:5050",
  [string]$Path = "..\samples\threats",
  [switch]$Recursive
)

Write-Host "Importing ThreatModel JSON from: $Path (recursive=$($Recursive.IsPresent)) to $BaseUrl ..."

try {
  $body = @{ path = (Resolve-Path $Path).Path; recursive = [bool]$Recursive; pattern = "*.json" } | ConvertTo-Json
} catch {
  Write-Error "Invalid path: $Path"; exit 1
}

try {
  $resp = Invoke-RestMethod -Uri "$BaseUrl/api/threats/import-path" -Method Post -ContentType 'application/json' -Body $body
  Write-Host "Imported: $($resp.imported) / Total: $($resp.total) (Skipped: $($resp.skipped))"
} catch {
  Write-Error $_.Exception.Message
  if ($_.ErrorDetails) { Write-Error $_.ErrorDetails }
  exit 1
}
