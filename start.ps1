# =============================================================================
# start.ps1 -- BugBounty Swarm One-Click Launcher
# =============================================================================
# Usage: .\start.ps1 in PowerShell
# =============================================================================

$ErrorActionPreference = "Continue"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host "         BUGBOUNTY SWARM -- ENTERPRISE SECURITY RESEARCH FLEET    " -ForegroundColor Cyan
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Step 1: Validate .env ---------------------------------------------------
Write-Host "[1/4] Checking .env configuration..." -ForegroundColor Yellow

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Host "  [INFO] Created .env from .env.example" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] .env file not found! Please create a .env file." -ForegroundColor Red
    }
}

$geminiKey = ""
if (Test-Path ".env") {
    $lines = Get-Content ".env"
    foreach ($line in $lines) {
        if ($line -match "^GEMINI_API_KEY=(.*)$") {
            $geminiKey = $matches[1].Trim()
        }
    }
}

if (-not $geminiKey -or $geminiKey -eq "" -or $geminiKey.StartsWith("your_")) {
    Write-Host "  [WARNING] GEMINI_API_KEY is not set in .env (falling back to emulator / offline mode)" -ForegroundColor Yellow
} else {
    $prefixLen = [Math]::Min(8, $geminiKey.Length)
    $maskedKey = $geminiKey.Substring(0, $prefixLen) + "..."
    Write-Host "  [OK] GEMINI_API_KEY found ($maskedKey)" -ForegroundColor Green
}

# --- Step 2: Kill existing processes on ports 5000, 8000, 3000, 3001 ----------
Write-Host ""
Write-Host "[2/4] Freeing local ports 5000, 8000, 3000, 3001..." -ForegroundColor Yellow

foreach ($port in @(5000, 8000, 3000, 3001)) {
    $procs = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($procs) {
        foreach ($proc in $procs) {
            try {
                Stop-Process -Id $proc.OwningProcess -Force -ErrorAction SilentlyContinue
                Write-Host "  [OK] Freed port $port (PID $($proc.OwningProcess))" -ForegroundColor Green
            } catch { }
        }
    }
}

Start-Sleep -Seconds 1

# --- Step 3: Start All Services ----------------------------------------------
Write-Host ""
# Ensure Python dependencies are installed
Write-Host "  --> Checking Python dependencies (requirements.txt)..." -ForegroundColor Yellow
python -m pip install -r "$PSScriptRoot\requirements.txt" --quiet

# Start Vuln Lab (port 5000)
Write-Host "  --> Starting Vuln Lab (http://127.0.0.1:5000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$PSScriptRoot'; cd '$PSScriptRoot'; python vuln_lab/app.py" -WindowStyle Minimized


# Start Backend (port 8000)
Write-Host "  --> Starting FastAPI Backend (http://127.0.0.1:8000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$PSScriptRoot'; cd '$PSScriptRoot'; python -m uvicorn app.main:app --port 8000 --host 0.0.0.0 --reload" -WindowStyle Minimized

# Ensure node_modules exist
if (-not (Test-Path "$PSScriptRoot\frontend\node_modules")) {
    Write-Host "  --> Installing frontend packages (npm install)..." -ForegroundColor Yellow
    Push-Location "$PSScriptRoot\frontend"
    npm install --silent
    Pop-Location
}

# Start Frontend (port 3000 / 3001)
Write-Host "  --> Starting Frontend Dashboard (http://localhost:3000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot\frontend'; npm run dev" -WindowStyle Minimized


# --- Step 4: Health Check & Open Browser -------------------------------------
Write-Host ""
Write-Host "[4/4] Waiting for services to initialize..." -ForegroundColor Yellow

$maxWait = 20
$interval = 2
$elapsed = 0
$backendReady = $false
$targetPort = 3000

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" -UseBasicParsing -TimeoutSec 1 -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $backendReady = $true }
    } catch { }


    # Check port 3000 or 3001 for frontend
    $conn3000 = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
    $conn3001 = Get-NetTCPConnection -LocalPort 3001 -State Listen -ErrorAction SilentlyContinue
    if ($conn3000) { $targetPort = 3000; if ($backendReady) { break } }
    elseif ($conn3001) { $targetPort = 3001; if ($backendReady) { break } }

    Write-Host "  Waiting... ($elapsed/${maxWait}s)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host "               BUGBOUNTY SWARM -- READY TO HUNT                  " -ForegroundColor Cyan
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host "    Backend API:     http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "    Vuln Lab:        http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "    Mission Control: http://localhost:$targetPort" -ForegroundColor Green
Write-Host "  ===============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Opening dashboard in browser..." -ForegroundColor White

Start-Sleep -Seconds 1
Start-Process "http://localhost:$targetPort"

Write-Host ""
Write-Host "  [SUCCESS] All systems active. Happy Hunting!" -ForegroundColor Green
Write-Host ""
