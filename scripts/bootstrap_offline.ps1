param(
    [string]$PythonBin = $env:PYTHON_BIN,
    [string]$VenvDir = $env:VENV_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
if (-not $VenvDir) {
    $VenvDir = Join-Path $RootDir ".venv"
}
$Wheelhouse = Join-Path $RootDir "vendor\wheels"
$Requirements = Join-Path $RootDir "requirements.offline.txt"

if (-not (Test-Path -Path $Wheelhouse -PathType Container)) {
    throw "Missing wheelhouse: $Wheelhouse"
}
if (-not (Test-Path -Path $Requirements -PathType Leaf)) {
    throw "Missing offline requirements file: $Requirements"
}

if ($PythonBin) {
    $script:PythonCommand = $PythonBin
    $script:PythonPrefixArgs = @()
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $script:PythonCommand = "py"
    $script:PythonPrefixArgs = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $script:PythonCommand = "python"
    $script:PythonPrefixArgs = @()
} else {
    throw "Python 3 was not found. Install Python 3 or set PYTHON_BIN."
}

function Invoke-SelectedPython {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $allArgs = @()
    $allArgs += $script:PythonPrefixArgs
    $allArgs += $Arguments
    & $script:PythonCommand @allArgs
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    & $Command @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

$PythonValidation = @"
import struct
import sys

bits = struct.calcsize("P") * 8
version = ".".join(str(part) for part in sys.version_info[:3])
print("Using Python {0} ({1}-bit)".format(version, bits))
if sys.version_info < (3, 9):
    raise SystemExit("CAT requires Python 3.9 or newer.")
if bits != 64:
    raise SystemExit("CAT requires 64-bit Python on Windows.")
"@
Invoke-SelectedPython -Arguments @("-c", $PythonValidation) -Description "Python version/architecture check"

$ShaFile = Join-Path $Wheelhouse "SHA256SUMS"
if (-not (Test-Path -Path $ShaFile -PathType Leaf)) {
    throw "Missing wheel checksum manifest: $ShaFile"
}

$manifestEntries = @{}
Get-Content $ShaFile | ForEach-Object {
    $line = $_.Trim()
    if ($line) {
        if (-not ($line -match "^([0-9A-Fa-f]{64})\s+(\S+)$")) {
            throw "Invalid SHA256SUMS line: $line"
        }
        $expected = $Matches[1].ToLowerInvariant()
        $fileName = $Matches[2]
        if ([System.IO.Path]::GetFileName($fileName) -ne $fileName) {
            throw "SHA256SUMS entries must contain a file name only: $fileName"
        }
        if ($fileName -notmatch "^[A-Za-z0-9][A-Za-z0-9._-]*[.]whl$") {
            throw "SHA256SUMS entries must be simple wheel file names: $fileName"
        }
        if ($manifestEntries.ContainsKey($fileName)) {
            throw "Duplicate SHA256SUMS entry: $fileName"
        }
        $target = Join-Path $Wheelhouse $fileName
        if (-not (Test-Path -Path $target -PathType Leaf)) {
            throw "Missing wheel file: $target"
        }
        $actual = (Get-FileHash -Path $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "SHA256 mismatch: $fileName"
        }
        $manifestEntries[$fileName] = $true
        Write-Host "$fileName`: OK"
    }
}

$wheelFiles = @(Get-ChildItem -Path $Wheelhouse -Filter "*.whl" -File)
if ($wheelFiles.Count -eq 0) {
    throw "No wheel files were found in: $Wheelhouse"
}
foreach ($wheelFile in $wheelFiles) {
    if (-not $manifestEntries.ContainsKey($wheelFile.Name)) {
        throw "Wheel is not covered by SHA256SUMS: $($wheelFile.Name)"
    }
}

Invoke-SelectedPython -Arguments @("-m", "venv", $VenvDir) -Description "Virtual environment creation"

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path -Path $VenvPython -PathType Leaf)) {
    throw "Virtual environment Python was not created: $VenvPython"
}

Invoke-CheckedNative -Command $VenvPython -Arguments @("-c", $PythonValidation) -Description "Virtual environment Python check"
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
$env:PIP_NO_CACHE_DIR = "1"
$env:PIP_NO_INDEX = "1"
Invoke-CheckedNative -Command $VenvPython -Arguments @(
    "-m", "pip", "install",
    "--no-index",
    "--find-links", $Wheelhouse,
    "-r", $Requirements
) -Description "Offline dependency installation"
Invoke-CheckedNative -Command $VenvPython -Arguments @("-m", "pip", "check") -Description "Installed dependency check"
Invoke-CheckedNative -Command $VenvPython -Arguments @(
    "-I",
    (Join-Path $RootDir "tests\smoke_test.py")
) -Description "CAT smoke test"

Write-Host "Offline bootstrap complete: $VenvDir"
