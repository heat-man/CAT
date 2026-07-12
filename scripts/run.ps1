param(
    [string]$BindHost = $(if ($env:HOST) { $env:HOST } else { "127.0.0.1" }),
    [int]$Port = $(if ($env:PORT) { [int]$env:PORT } else { 8000 }),
    [string]$VenvDir = $env:VENV_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
if (-not $VenvDir) {
    $VenvDir = Join-Path $RootDir ".venv"
}

if (-not $env:CAT_AGENT_BACKEND) {
    $env:CAT_AGENT_BACKEND = "lmstudio"
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$NeedsBootstrap = $false
if (-not (Test-Path -Path $VenvPython -PathType Leaf)) {
    $NeedsBootstrap = $true
} else {
    & $VenvPython -c "import Evtx" *> $null
    if ($LASTEXITCODE -ne 0) {
        $NeedsBootstrap = $true
    }
}

if ($NeedsBootstrap) {
    & (Join-Path $PSScriptRoot "bootstrap_offline.ps1") -VenvDir $VenvDir
}

& $VenvPython (Join-Path $RootDir "run.py") --host $BindHost --port $Port
