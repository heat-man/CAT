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
    param([string[]]$Arguments)
    $allArgs = @()
    $allArgs += $script:PythonPrefixArgs
    $allArgs += $Arguments
    & $script:PythonCommand @allArgs
}

$ShaFile = Join-Path $Wheelhouse "SHA256SUMS"
if (Test-Path -Path $ShaFile -PathType Leaf) {
    Get-Content $ShaFile | ForEach-Object {
        $line = $_.Trim()
        if ($line) {
            $parts = $line -split "\s+"
            if ($parts.Count -lt 2) {
                throw "Invalid SHA256SUMS line: $line"
            }
            $expected = $parts[0].ToLowerInvariant()
            $fileName = $parts[1]
            $target = Join-Path $Wheelhouse $fileName
            if (-not (Test-Path -Path $target -PathType Leaf)) {
                throw "Missing wheel file: $target"
            }
            $actual = (Get-FileHash -Path $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "SHA256 mismatch: $fileName"
            }
            Write-Host "$fileName`: OK"
        }
    }
}

Invoke-SelectedPython @("-m", "venv", $VenvDir)

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path -Path $VenvPython -PathType Leaf)) {
    throw "Virtual environment Python was not created: $VenvPython"
}

& $VenvPython -m pip install --no-index --find-links $Wheelhouse -r $Requirements
& $VenvPython (Join-Path $RootDir "tests\smoke_test.py")

Write-Host "Offline bootstrap complete: $VenvDir"
