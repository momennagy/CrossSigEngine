param(
  [int]$Port = 5050,
  [string]$Configuration = "Release",
  [switch]$SkipBuild,
  # Optional: run a non-fatal Cuckoo sandbox smoke (requires a reachable Cuckoo API)
  [switch]$TestCuckoo,
  [string]$CuckooBaseUrl = "http://localhost:8090/api/",
  [string]$CuckooApiKey
)

# Simple end-to-end smoke test script for CrossSigEngine Web
# - Builds (unless -SkipBuild)
# - Starts the Web app on http://localhost:$Port
# - Probes health/version and exercises key API flows
# - Creates a temp file and verifies scan matches
# - Optional: exercise Sandbox endpoints (VirusTotal via VT_API_KEY; Cuckoo via -TestCuckoo and -CuckooBaseUrl)
# Requires: Windows PowerShell 5.1+

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Ensure HttpClient is available in Windows PowerShell 5.1
try { [void][System.Net.Http.HttpClient] } catch { Add-Type -AssemblyName System.Net.Http }

function Write-Log {
  param([string]$Message, [string]$Level = 'INFO')
  $ts = (Get-Date).ToString('u')
  Write-Host "[$ts][$Level] $Message"
}

function Invoke-HttpGet {
  param([string]$Url)
  try {
    $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method GET -TimeoutSec 10
    return $resp
  } catch {
    throw $_
  }
}

function Invoke-HttpPostJson {
  param([string]$Url, [string]$Json)
  try {
    $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method POST -ContentType 'application/json' -Body $Json -TimeoutSec 30
    return $resp
  } catch {
    throw $_
  }
}

function Invoke-MultipartUpload {
  param(
    [string]$Url,
    [string]$ModelJson,
    [string]$FilePath
  )
  # Use .NET HttpClient to post multipart/form-data in Windows PowerShell 5.1
  $handler = New-Object System.Net.Http.HttpClientHandler
  $client = New-Object System.Net.Http.HttpClient($handler)
  $content = New-Object System.Net.Http.MultipartFormDataContent
  $strContent = New-Object System.Net.Http.StringContent($ModelJson, [System.Text.Encoding]::UTF8, 'application/json')
  $content.Add($strContent, 'model')
  $fs = [System.IO.File]::OpenRead($FilePath)
  try {
    $fileContent = New-Object System.Net.Http.StreamContent($fs)
    $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
    $name = [System.IO.Path]::GetFileName($FilePath)
    $content.Add($fileContent, 'file', $name)
    $resp = $client.PostAsync($Url, $content).GetAwaiter().GetResult()
    $status = [int]$resp.StatusCode
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    return @{ StatusCode = $status; Content = $body }
  } finally {
    $fs.Dispose()
    $content.Dispose()
    $client.Dispose()
    $handler.Dispose()
  }
}

function Wait-For-Healthy {
  param([string]$HealthUrl, [int]$TimeoutSeconds = 60)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    try {
      $r = Invoke-HttpGet -Url $HealthUrl
      if ($r.StatusCode -eq 200) { return $true }
    } catch {}
    Start-Sleep -Seconds 1
  }
  return $false
}

# Resolve paths (repo root is the parent of scripts/)
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SlnPath = Join-Path $RepoRoot 'CrossSigEngine.sln'
$WebProj = Join-Path $RepoRoot 'CrossSigEngine.Web\CrossSigEngine.Web.csproj'
$BaseUrl = "http://localhost:$Port"
$HealthUrl = "$BaseUrl/healthz"
$VersionUrl = "$BaseUrl/version"
$IndexUrl = "$BaseUrl/"
$SwaggerUrl = "$BaseUrl/swagger"

# Build
if (-not $SkipBuild) {
  Write-Log "Building solution ($Configuration) …"
  & dotnet build "$SlnPath" -c $Configuration | Out-Host
}

# Start web app
Write-Log "Starting Web app on $BaseUrl …"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "dotnet"
$psi.Arguments = "run --project `"$WebProj`" --urls $BaseUrl"
$psi.WorkingDirectory = $RepoRoot
$psi.UseShellExecute = $true
$proc = [System.Diagnostics.Process]::Start($psi)
if (-not $proc) { throw "Failed to start web app" }
Write-Log "Web PID: $($proc.Id)"

try {
  # Health
  Write-Log "Waiting for health at $HealthUrl …"
  if (-not (Wait-For-Healthy -HealthUrl $HealthUrl -TimeoutSeconds 90)) {
    throw "Web app did not become healthy in time"
  }
  Write-Log "Health OK"

  # Index page
  $idx = Invoke-HttpGet -Url $IndexUrl
  if ($idx.StatusCode -ne 200 -or -not ($idx.Content -like '*CrossSigEngine Web*')) {
    throw "Index page content unexpected"
  }
  Write-Log "Index OK"

  # Swagger
  $swg = Invoke-HttpGet -Url $SwaggerUrl
  if ($swg.StatusCode -ne 200) { throw "Swagger not reachable" }
  Write-Log "Swagger OK"

  # Version
  $ver = Invoke-HttpGet -Url $VersionUrl
  if ($ver.StatusCode -ne 200 -or -not ($ver.Content -like '*version*')) { throw "Version endpoint unexpected" }
  Write-Log "Version OK"

  # Model JSON
  $modelObj = @{ name = 'SmokeTest'; family = 'Demo'; file = @{ strings = @('abc'); hex_patterns = @('61 62 63') } }
  $modelJson = ($modelObj | ConvertTo-Json -Depth 8 -Compress)

  # Validate
  $val = Invoke-HttpPostJson -Url "$BaseUrl/api/validate" -Json $modelJson
  if ($val.StatusCode -ne 200) { throw "Validate failed: $($val.StatusCode)" }
  Write-Log "Validate OK"

  # Generate (all)
  $gen = Invoke-HttpPostJson -Url "$BaseUrl/api/generate?family=all" -Json $modelJson
  if ($gen.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace($gen.Content)) { throw "Generate failed" }
  Write-Log "Generate OK"

  # Prepare temp file and dir
  $tempDir = Join-Path $env:TEMP ("cse-smoke-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tempDir | Out-Null
  $tempFile = Join-Path $tempDir 'sample.bin'
  [System.IO.File]::WriteAllText($tempFile, 'xyz abc uvw')

  # Scan upload
  $up = Invoke-MultipartUpload -Url "$BaseUrl/api/scan/upload" -ModelJson $modelJson -FilePath $tempFile
  if ($up.StatusCode -ne 200) { throw "Upload scan failed: $($up.StatusCode) $($up.Content)" }
  if ($up.Content -notlike '*matches*') { throw "Upload scan response missing matches" }
  Write-Log "Scan (upload) OK"

  # Scan path (use correct property casing to match DirScanRequest)
  $dsPayload = [ordered]@{
    Model = $modelJson
    Path = $tempDir
    Recursive = $false
    Parallel = 1
    MaxFileSizeBytes = 0
    FailOnMatch = $false
  }
  $dsJson = $dsPayload | ConvertTo-Json -Depth 8 -Compress
  $ds = Invoke-HttpPostJson -Url "$BaseUrl/api/scan/path" -Json $dsJson
  if ($ds.StatusCode -ne 200 -or $ds.Content -notlike '*"count":*') { throw "Dir scan failed or unexpected: $($ds.StatusCode) $($ds.Content)" }
  Write-Log "Scan (path) OK"

  # Optional sandbox test (requires VT_API_KEY)
  if ($env:VT_API_KEY) {
    Write-Log "VT_API_KEY found; running a quick sandbox URL test …"
    $sbBody = @{ provider = 'vt'; url = 'https://example.com'; apiKey = $env:VT_API_KEY } | ConvertTo-Json -Depth 4 -Compress
    $sb = Invoke-HttpPostJson -Url "$BaseUrl/api/sandbox/url" -Json $sbBody
    if ($sb.StatusCode -ne 200) { Write-Log "Sandbox URL test non-200: $($sb.StatusCode)" 'WARN' } else { Write-Log "Sandbox URL test OK" }
  } else {
    Write-Log "Skipping sandbox test (no VT_API_KEY)" 'WARN'
  }

  # Optional Cuckoo sandbox smoke (non-fatal)
  if ($TestCuckoo) {
    if (-not $CuckooBaseUrl) {
      Write-Log "-TestCuckoo set but CuckooBaseUrl is empty" 'WARN'
    } else {
      Write-Log "Running Cuckoo sandbox URL test against $CuckooBaseUrl …"
      $bodyHash = @{ provider = 'cuckoo'; url = 'https://example.com'; baseUrl = $CuckooBaseUrl }
      if ($CuckooApiKey) { $bodyHash.apiKey = $CuckooApiKey }
      $sbBody2 = $bodyHash | ConvertTo-Json -Depth 4 -Compress
      try {
        $sb2 = Invoke-HttpPostJson -Url "$BaseUrl/api/sandbox/url" -Json $sbBody2
        if ($sb2.StatusCode -ne 200) {
          Write-Log "Cuckoo sandbox URL test non-200: $($sb2.StatusCode) $($sb2.Content)" 'WARN'
        } else {
          Write-Log "Cuckoo sandbox URL test OK"
        }
      } catch {
        Write-Log ("Cuckoo sandbox URL test failed: " + $_.Exception.Message) 'WARN'
      }
    }
  }

  Write-Log "All smoke tests passed." 'SUCCESS'
  exit 0
}
catch {
  Write-Log ("SMOKE TEST FAILED: " + $_.Exception.Message) 'ERROR'
  exit 1
}
finally {
  if ($proc -and -not $proc.HasExited) {
    Write-Log "Stopping Web (PID $($proc.Id)) …"
    try { $proc.Kill() } catch {}
  }
  if ((Get-Variable -Name tempDir -Scope Script -ErrorAction SilentlyContinue) -and $tempDir -and (Test-Path $tempDir)) {
    try { Remove-Item -Recurse -Force $tempDir } catch {}
  }
}
