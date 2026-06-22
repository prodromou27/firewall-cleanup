# Firewall Policy Cleanup Assistant - Setup Script
# Run this script once to install all dependencies

Write-Host "=== Firewall Policy Cleanup Assistant Setup ===" -ForegroundColor Cyan

# Check Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $pythonCmd = $cmd
            Write-Host "Found Python: $ver" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "Python 3.11+ not found." -ForegroundColor Yellow
    Write-Host "Downloading Python 3.12 installer..." -ForegroundColor Yellow
    $pythonInstaller = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe" -OutFile $pythonInstaller
    Write-Host "Installing Python (this may take a minute)..." -ForegroundColor Yellow
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1" -Wait
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $pythonCmd = "python"
}

# Backend setup
Write-Host "`nSetting up backend..." -ForegroundColor Cyan

if (-not (Test-Path ".\.venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    & $pythonCmd -m venv .venv
}

Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
& ".\.venv\Scripts\pip.exe" install -r ".\backend\requirements.txt" --quiet

Write-Host "Running database migrations..." -ForegroundColor Yellow
Push-Location ".\backend"
& "..\.venv\Scripts\python.exe" -m alembic upgrade head
Pop-Location

# Frontend setup
Write-Host "`nSetting up frontend..." -ForegroundColor Cyan
Push-Location ".\frontend"
Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
npm install --silent
Pop-Location

Write-Host "`n=== Setup Complete! ===" -ForegroundColor Green
Write-Host "To start the application, run: .\start.ps1" -ForegroundColor Green
Write-Host "To add demo data, run: .\.venv\Scripts\python.exe backend\scripts\seed_demo.py" -ForegroundColor Green
