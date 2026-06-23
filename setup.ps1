# Firewall Policy Cleanup Assistant - Setup Script
# Run this script to install or refresh local development dependencies.

$ErrorActionPreference = "Stop"

Write-Host "=== Firewall Policy Cleanup Assistant Setup ===" -ForegroundColor Cyan

$MinPython = [version]"3.12.0"
$MinNode = [version]"20.19.0"

function Get-SemVerFromText([string]$Text) {
    if ($Text -match "(\d+)\.(\d+)\.(\d+)") {
        return [version]$Matches[0]
    }
    return $null
}

# Check Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        $parsed = Get-SemVerFromText "$ver"
        if ($parsed -and $parsed -ge $MinPython) {
            $pythonCmd = $cmd
            Write-Host "Found Python: $ver" -ForegroundColor Green
            break
        } elseif ($parsed) {
            Write-Host "Ignoring Python $parsed; PolicyInsight requires Python $MinPython or newer." -ForegroundColor Yellow
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "Python $MinPython+ not found." -ForegroundColor Yellow
    Write-Host "Downloading Python 3.12 installer..." -ForegroundColor Yellow
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" -OutFile $pythonInstaller
    Write-Host "Installing Python (this may take a minute)..." -ForegroundColor Yellow
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $pythonCmd = "python"
}

# Check Node.js and npm before frontend setup.
try {
    $nodeVerText = & node --version 2>&1
    $nodeVer = Get-SemVerFromText "$nodeVerText"
    if (-not $nodeVer -or $nodeVer -lt $MinNode) {
        throw "Node.js $MinNode+ is required. Found: $nodeVerText"
    }
    Write-Host "Found Node.js: $nodeVerText" -ForegroundColor Green
} catch {
    Write-Host "Node.js $MinNode+ is required for frontend development." -ForegroundColor Red
    Write-Host "Install the current LTS from https://nodejs.org, then rerun .\setup.ps1." -ForegroundColor Yellow
    exit 1
}

try {
    $npmVer = & npm --version 2>&1
    Write-Host "Found npm: $npmVer" -ForegroundColor Green
} catch {
    Write-Host "npm was not found. Reinstall Node.js with npm enabled, then rerun .\setup.ps1." -ForegroundColor Red
    exit 1
}

# Backend setup
Write-Host "`nSetting up backend..." -ForegroundColor Cyan

if (-not (Test-Path ".\.venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    & $pythonCmd -m venv .venv
}

Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r ".\backend\requirements.txt"

Write-Host "Running database migrations..." -ForegroundColor Yellow
Push-Location ".\backend"
& "..\.venv\Scripts\python.exe" -m alembic upgrade head
Pop-Location

# Frontend setup
Write-Host "`nSetting up frontend..." -ForegroundColor Cyan
Push-Location ".\frontend"
Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
npm ci
Pop-Location

Write-Host "`n=== Setup Complete! ===" -ForegroundColor Green
Write-Host "To start the application, run: .\start.ps1" -ForegroundColor Green
Write-Host "To add demo data, run: .\.venv\Scripts\python.exe backend\scripts\seed_demo.py" -ForegroundColor Green
