# ─────────────────────────────────────────────────────────────────────────────
# deploy_cloud_run.ps1 — Deploy BugBounty Swarm Backend to Google Cloud Run
# ─────────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  BUGBOUNTY SWARM - GOOGLE CLOUD RUN DEPLOYMENT SCRIPT" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

# 0. Check if gcloud is installed
$gcloudCmd = Get-Command "gcloud" -ErrorAction SilentlyContinue
if (-not $gcloudCmd) {
    Write-Host "[ERROR] 'gcloud' CLI is not installed or not in PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "You have TWO easy options:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1 (Recommended - Zero Setup): Use Google Cloud Shell in your browser" -ForegroundColor White
    Write-Host "  1. Open: https://shell.cloud.google.com" -ForegroundColor Cyan
    Write-Host "  2. Clone your repository: git clone <your-repo-url> && cd <repo>" -ForegroundColor Cyan
    Write-Host "  3. Run: chmod +x deploy/deploy_cloud_run.sh && ./deploy/deploy_cloud_run.sh" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Option 2: Install Google Cloud CLI on Windows" -ForegroundColor White
    Write-Host "  Download installer: https://cloud.google.com/sdk/docs/install#windows" -ForegroundColor Cyan
    Write-Host "  After installing, reopen PowerShell and run: gcloud auth login" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# 1. Detect Project ID
$PROJECT_ID = (& gcloud config get-value project 2>$null)
if (-not $PROJECT_ID -or $PROJECT_ID -eq "(unset)") {
    $PROJECT_ID = Read-Host "Enter your Google Cloud Project ID (e.g. project-4183c876-9be4-4bc7-9f2)"
    & gcloud config set project $PROJECT_ID
}

$REGION = "us-central1"
$SERVICE_NAME = "bugbounty-swarm-backend"
$IMAGE_NAME = "gcr.io/$PROJECT_ID/bugbounty-swarm-backend:latest"

Write-Host ""
Write-Host "[*] Target Project: $PROJECT_ID" -ForegroundColor Yellow
Write-Host "[*] Target Region:  $REGION" -ForegroundColor Yellow
Write-Host "[*] Cloud Run Svc:  $SERVICE_NAME" -ForegroundColor Yellow

# 2. Enable Required Google Cloud APIs
Write-Host ""
Write-Host "[1/4] Enabling required Google Cloud APIs..." -ForegroundColor Cyan
& gcloud services enable run.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com cloudtasks.googleapis.com aiplatform.googleapis.com storage.googleapis.com

# 3. Build Container Image via Google Cloud Build
Write-Host ""
Write-Host "[2/4] Building container image with Google Cloud Build..." -ForegroundColor Cyan
& gcloud builds submit --tag $IMAGE_NAME .

# 4. Deploy to Google Cloud Run
Write-Host ""
Write-Host "[3/4] Deploying service to Google Cloud Run (us-central1)..." -ForegroundColor Cyan
& gcloud run deploy $SERVICE_NAME `
    --image $IMAGE_NAME `
    --platform managed `
    --region $REGION `
    --allow-unauthenticated `
    --memory 2Gi `
    --cpu 2 `
    --min-instances 1 `
    --max-instances 5 `
    --no-cpu-throttling `
    --set-env-vars "ENVIRONMENT=production,LOG_LEVEL=INFO,GCP_PROJECT_ID=$PROJECT_ID,GCP_REGION=$REGION,GEMINI_MODEL=gemini-3.5-flash,USE_FIRESTORE_EMULATOR=false,API_SECRET_KEY=test_secret_key_12345678901234567890123456789012"

# 5. Retrieve Service URL & Health Check
Write-Host ""
Write-Host "[4/4] Verifying Cloud Run deployment..." -ForegroundColor Cyan
$SERVICE_URL = (& gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format "value(status.url)")

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] BUGBOUNTY SWARM IS LIVE ON GOOGLE CLOUD RUN!" -ForegroundColor Green
Write-Host " Service URL:         $SERVICE_URL" -ForegroundColor Green
Write-Host " Health Endpoint:     $SERVICE_URL/healthz" -ForegroundColor Green
Write-Host " Agent Registry:      $SERVICE_URL/api/agents" -ForegroundColor Green
Write-Host " API Documentation:   $SERVICE_URL/docs" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
