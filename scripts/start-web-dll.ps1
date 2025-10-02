param(
  [int]$Port = 5072,
  [string]$Configuration = 'Release',
  [string]$DataDir = '..\\data'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$WebProj = Join-Path $RepoRoot 'CrossSigEngine.Web\\CrossSigEngine.Web.csproj'

# Resolve data dir and set env
$DataDirFull = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $DataDir))
if (-not (Test-Path $DataDirFull)) { New-Item -ItemType Directory -Path $DataDirFull | Out-Null }
$env:CSE_DATA_DIR = $DataDirFull
Write-Host "CSE_DATA_DIR = $env:CSE_DATA_DIR"

# Publish web project to an output folder
$publishDir = Join-Path (Split-Path -Parent $WebProj) "bin\\$Configuration\\publish-web"
dotnet publish "$WebProj" -c $Configuration -o "$publishDir" | Out-Host

$dllPath = Join-Path $publishDir 'CrossSigEngine.Web.dll'
if (-not (Test-Path $dllPath)) { throw "Web DLL not found after publish at $dllPath" }

# Logs
$logDir = Join-Path $DataDirFull 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir ("webdll-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")
$stdout = $logFile
$stderr = $logFile + '.err'

# Start detached
$workingDir = Split-Path -Parent $WebProj
$argStr = "`"$dllPath`" --urls `"http://localhost:$Port`""
$proc = Start-Process -FilePath "dotnet" -WorkingDirectory $workingDir -WindowStyle Minimized -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ArgumentList $argStr 
Write-Host "Web DLL started detached on http://localhost:$Port (PID=$($proc.Id)). Log: $stdout"

# quick health probe
$ok = $false
for ($i = 0; $i -lt 40; $i++) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing "http://localhost:$Port/healthz" -TimeoutSec 2 -ErrorAction Stop
    if ($r.StatusCode -eq 200) { $ok = $true; break }
  } catch {}
  Start-Sleep -Milliseconds 250
}
if ($ok) { Write-Host "Health check: 200 OK" } else { Write-Warning "Health check: no response yet; see $stdout" }
