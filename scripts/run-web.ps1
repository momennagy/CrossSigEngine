param(
  [int]$Port = 5062,
  [string]$DataDir = "..\\data",
  [switch]$SkipBuild,
  [switch]$Detach
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$SlnPath = Join-Path $RepoRoot 'CrossSigEngine.sln'
$WebProj = Join-Path $RepoRoot 'CrossSigEngine.Web\\CrossSigEngine.Web.csproj'

# Compute data directory under repo root, create if missing, then get absolute path
$DataDirFull = Join-Path $RepoRoot $DataDir
if (-not (Test-Path $DataDirFull)) { New-Item -ItemType Directory -Path $DataDirFull | Out-Null }
$ResolvedDataDir = [System.IO.Path]::GetFullPath($DataDirFull)

if (-not $SkipBuild) {
  dotnet build "$SlnPath" -c Release | Out-Host
}

$env:CSE_DATA_DIR = $ResolvedDataDir
Write-Host "CSE_DATA_DIR = $env:CSE_DATA_DIR"

# Start the web app
# If -Detach is provided, launch via Start-Process so it keeps running after this script exits
# Otherwise run in the foreground so you can see logs; Ctrl+C to stop
if ($Detach) {
  $workingDir = Split-Path -Parent $WebProj
  $logDir = Join-Path $ResolvedDataDir 'logs'
  if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
  $logFile = Join-Path $logDir ("web-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
  $stdout = $logFile
  $stderr = $logFile + '.err'
     $argStr = "run --no-build --project `"$WebProj`" --urls `"http://localhost:$Port`""
     $proc = Start-Process -FilePath "dotnet" -WorkingDirectory $workingDir -WindowStyle Minimized -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList $argStr
  # merge stderr into main log for convenience
  if (Test-Path $stderr) { Get-Content $stderr | Add-Content $stdout; Remove-Item $stderr -ErrorAction SilentlyContinue }
  Write-Host "Web started detached on http://localhost:$Port (PID=$($proc.Id)). Log: $stdout"
  # quick health probe (best-effort)
  $ok = $false
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing "http://localhost:$Port/healthz" -TimeoutSec 2 -ErrorAction Stop
      if ($r.StatusCode -eq 200) { $ok = $true; break }
    } catch {}
    Start-Sleep -Milliseconds 250
  }
  if ($ok) { Write-Host "Health check: 200 OK" } else { Write-Warning "Health check: no response yet; see $logFile" }
} else {
  & dotnet run --no-build --project "$WebProj" --urls "http://localhost:$Port"
}
