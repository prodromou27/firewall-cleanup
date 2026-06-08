# Firewall Policy Cleanup Assistant - Start Script

Write-Host "=== Firewall Policy Cleanup Assistant ===" -ForegroundColor Cyan
Write-Host "Starting backend and frontend..." -ForegroundColor Yellow

# Start backend
$backend = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "cd backend && venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000" -WindowStyle Normal -PassThru

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
