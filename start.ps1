# ─────────────────────────────────────────────────────────────────────────────
# start.ps1 — BugBounty Swarm One-Click Launcher
# ─────────────────────────────────────────────────────────────────────────────
# Usage: Right-click → "Run with PowerShell"  OR  .\start.ps1 in terminal
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Continue"
$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "  ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝" -ForegroundColor Cyan
Write-Host "  ██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝" -ForegroundColor Cyan
Write-Host "  ██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝" -ForegroundColor Cyan
Write-Host "  ██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║" -ForegroundColor Cyan
Write-Host "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  SWARM AI Security Research Platform — Starting all services..." -ForegroundColor White
Write-Host ""

# ─── Step 1: Validate .env ───────────────────────────────────────────────────
Write-Host "[1/4] Checking .env configuration..." -ForegroundColor Yellow

if (-not (Test-Path ".env")) {
    Write-Host "  [ERROR] .env file not found! Copy .env.example to .env and fill in GEMINI_API_KEY." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$envContent = Get-Content ".env" -Raw
$geminiKey = ($envContent -split "`n" | Where-Object { $_ -match "^GEMINI_API_KEY=" } | Select-Object -First 1) -replace "GEMINI_API_KEY=",""
$geminiKey = $geminiKey.Trim()

if (-not $geminiKey -or $geminiKey -eq "" -or $geminiKey.StartsWith("your_")) {
    Write-Host "  [WARNING] GEMINI_API_KEY is not set in .env" -ForegroundColor Red
    Write-Host "  Get your key at: https://aistudio.google.com/app/apikey" -ForegroundColor Yellow
} else {
    Write-Host "  [OK] GEMINI_API_KEY found (${geminiKey.Substring(0, [Math]::Min(8, $geminiKey.Length))}...)" -ForegroundColor Green
}

# ─── Step 2: Kill any existing processes on ports 5000, 8000, 3000 ───────────
Write-Host ""
Write-Host "[2/4] Freeing ports 5000, 8000, 3000..." -ForegroundColor Yellow

foreach ($port in @(5000, 8000, 3000)) {
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

# ─── Step 3: Start All Services ──────────────────────────────────────────────
Write-Host ""
Write-Host "[3/4] Starting services..." -ForegroundColor Yellow

# Start Vuln Lab (port 5000)
Write-Host "  --> Starting Vuln Lab (http://127.0.0.1:5000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit -Command `"cd '$PSScriptRoot'; python -m vuln_lab.app 2>&1`"" -WindowStyle Minimized

# Start Backend (port 8000)
Write-Host "  --> Starting Backend API (http://127.0.0.1:8000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit -Command `"cd '$PSScriptRoot'; python -m uvicorn app.main:app --port 8000 --host 0.0.0.0 2>&1`"" -WindowStyle Minimized

# Start Frontend (port 3000)
Write-Host "  --> Starting Frontend Dashboard (http://localhost:3000)..." -ForegroundColor Cyan
Start-Process -FilePath "powershell" -ArgumentList "-NoExit -Command `"cd '$PSScriptRoot\frontend'; npm run dev 2>&1`"" -WindowStyle Minimized

# ─── Step 4: Health Check & Open Browser ─────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Waiting for services to start (10 seconds)..." -ForegroundColor Yellow

$maxWait = 30
$interval = 2
$elapsed = 0
$backendReady = $false
$frontendReady = $false

while ($elapsed -lt $maxWait) {
    Start-Sleep -Seconds $interval
    $elapsed += $interval
    
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:8000/healthz" -TimeoutSec 1 -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $backendReady = $true }
    } catch { }
    
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 1 -ErrorAction SilentlyContinue
        if ($r.StatusCode -eq 200) { $frontendReady = $true }
    } catch { }
    
    if ($backendReady -and $frontendReady) { break }
    Write-Host "  Waiting... ($elapsed/$maxWait s)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │              BUGBOUNTY SWARM — READY TO HUNT                │" -ForegroundColor Cyan
Write-Host "  ├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan

if ($backendReady) {
    Write-Host "  │  Backend API   http://127.0.0.1:8000   [LIVE]              │" -ForegroundColor Green
} else {
    Write-Host "  │  Backend API   http://127.0.0.1:8000   [STARTING...]       │" -ForegroundColor Yellow
}

Write-Host "  │  Vuln Lab      http://127.0.0.1:5000   [STARTED]           │" -ForegroundColor Green

if ($frontendReady) {
    Write-Host "  │  Dashboard     http://localhost:3000   [LIVE]              │" -ForegroundColor Green
} else {
    Write-Host "  │  Dashboard     http://localhost:3000   [STARTING...]       │" -ForegroundColor Yellow
}

Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Opening dashboard in browser..." -ForegroundColor White

Start-Sleep -Seconds 2
Start-Process "http://localhost:3000"

Write-Host ""
Write-Host "  [DONE] Happy Hunting! The swarm is ready." -ForegroundColor Green
Write-Host "  Close this window or press Ctrl+C to keep services running in background." -ForegroundColor DarkGray
Write-Host ""
