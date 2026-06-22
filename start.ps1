# PolicyInsight - Start Script
param(
    [switch]$SeedDemo
)

Write-Host "=== PolicyInsight ===" -ForegroundColor Cyan
Write-Host "Starting backend and frontend..." -ForegroundColor Yellow

$PythonExe = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = ".\backend\venv\Scripts\python.exe"
}
if (-not (Test-Path $PythonExe)) {
    Write-Host "Python environment not found. Run .\setup.ps1 first." -ForegroundColor Red
    exit 1
}

Push-Location ".\backend"
& "..\$PythonExe" -m alembic upgrade head
Pop-Location

if ($SeedDemo) {
    & $PythonExe "backend\scripts\seed_demo.py"
}

# Start backend
$backend = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "$PythonExe -m uvicorn app.main:app --reload --port 8000 --app-dir backend" -WindowStyle Normal -PassThru

# Give backend time to start
Start-Sleep -Seconds 3

# Start frontend
$frontend = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "cd frontend && npm run dev" -WindowStyle Normal -PassThru

Write-Host "`nBackend running at:  http://localhost:8000" -ForegroundColor Green
Write-Host "Frontend running at: http://localhost:3000" -ForegroundColor Green
Write-Host "API docs at:         http://localhost:8000/docs" -ForegroundColor Green
Write-Host "`nPress any key to stop both servers..." -ForegroundColor Yellow

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Cleanup
Stop-Process -Id $backend.Id -ErrorAction SilentlyContinue
Stop-Process -Id $frontend.Id -ErrorAction SilentlyContinue
Write-Host "Servers stopped." -ForegroundColor Yellow
