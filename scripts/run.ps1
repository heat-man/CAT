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
    $RuntimeProbe = @"
import struct
import sys
from importlib.metadata import version
from zoneinfo import ZoneInfo
from Evtx.Evtx import Evtx
import tzdata

if sys.version_info < (3, 9) or struct.calcsize("P") * 8 != 64:
    raise SystemExit(1)
if version("hexdump") != "3.3":
    raise SystemExit(1)
if version("python-evtx") != "0.8.1":
    raise SystemExit(1)
if version("tzdata") != "2026.3":
    raise SystemExit(1)
ZoneInfo("Asia/Seoul")
"@
    & $VenvPython -c $RuntimeProbe *> $null
    $probeExitCode = $LASTEXITCODE
    if ($probeExitCode -ne 0) {
        $NeedsBootstrap = $true
    }
}

if ($NeedsBootstrap) {
    & (Join-Path $PSScriptRoot "bootstrap_offline.ps1") -VenvDir $VenvDir
}

& $VenvPython (Join-Path $RootDir "run.py") --host $BindHost --port $Port
$appExitCode = $LASTEXITCODE
if ($appExitCode -ne 0) {
    throw "CAT application exited with code $appExitCode."
}
