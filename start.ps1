$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$pythonPath = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Creating the Python environment failed.' }
}
$requirementsHash = (Get-FileHash -LiteralPath 'requirements.txt' -Algorithm SHA256).Hash
$stampPath = Join-Path $PSScriptRoot '.venv/requirements.sha256'
$installedHash = if (Test-Path -LiteralPath $stampPath) { Get-Content -LiteralPath $stampPath -Raw } else { '' }
if ($installedHash.Trim() -ne $requirementsHash) {
    & $pythonPath -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
    Set-Content -LiteralPath $stampPath -Value $requirementsHash
}
Write-Host 'Sentinel AML is starting at http://127.0.0.1:8000'
& $pythonPath -m uvicorn app.main:app --host 127.0.0.1 --port 8000
