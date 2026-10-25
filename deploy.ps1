# PowerShell Deployment Script for SCADA Security Prototype
[CmdletBinding()]
param(
    [switch]$RunTests,
    [switch]$Headless
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectDir

Write-Host "=========================================================================" -ForegroundColor Cyan
Write-Host "  SCADA INTRUSION DETECTION & QUANTUM-SECURE COMMUNICATION SYSTEM" -ForegroundColor Cyan
Write-Host "=========================================================================" -ForegroundColor Cyan

$PythonExe = Join-Path $ProjectDir ".venv\Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "[!] Virtual environment not found at $PythonExe" -ForegroundColor Yellow
    Write-Host "[*] Creating virtual environment..." -ForegroundColor White
    python -m venv .venv
    Write-Host "[*] Installing dependencies..." -ForegroundColor White
    & (Join-Path $ProjectDir ".venv\Scripts\pip.exe") install -r requirements.txt
}

if ($RunTests) {
    Write-Host "[*] Running verification test suite..." -ForegroundColor White
    & $PythonExe -m pytest -q
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Tests failed. Deployment aborted." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] All tests passed successfully." -ForegroundColor Green
}

Write-Host "[*] Starting SCADA Security System..." -ForegroundColor Green
Write-Host "[+] Web Dashboard: http://127.0.0.1:5000/" -ForegroundColor Cyan
Write-Host "[+] Modbus TCP:   127.0.0.1:5020" -ForegroundColor Cyan
Write-Host "[*] Press Ctrl+C to terminate." -ForegroundColor Gray

if (-not $Headless) {
    Start-Process "http://127.0.0.1:5000/"
}

& $PythonExe main.py
