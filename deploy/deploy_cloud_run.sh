#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy_cloud_run.sh — Deploy BugBounty Swarm Backend to Google Cloud Run
# ─────────────────────────────────────────────────────────────────────────────
# Run directly in Google Cloud Shell or any Linux/macOS environment
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

echo "================================================================="
echo "  BUGBOUNTY SWARM — GOOGLE CLOUD RUN DEPLOYMENT SCRIPT"
echo "================================================================="

PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "(unset)" ]; then
    read -rp "Enter your Google Cloud Project ID: " PROJECT_ID
    gcloud config set project "$PROJECT_ID"
fi

REGION="us-central1"
SERVICE_NAME="bugbounty-swarm-backend"
IMAGE_NAME="gcr.io/${PROJECT_ID}/bugbounty-swarm-backend:latest"

echo ""
echo "[*] Target Project: ${PROJECT_ID}"
echo "[*] Target Region:  ${REGION}"
echo "[*] Cloud Run Svc:  ${SERVICE_NAME}"

echo ""
echo "[1/4] Enabling required Google Cloud APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    firestore.googleapis.com \
    cloudtasks.googleapis.com \
    aiplatform.googleapis.com \
    storage.googleapis.com

echo ""
echo "[2/4] Building container image with Google Cloud Build..."
gcloud builds submit --tag "${IMAGE_NAME}" .

echo ""
echo "[3/4] Deploying service to Google Cloud Run (us-central1)..."
gcloud run deploy "${SERVICE_NAME}" \
    --image "${IMAGE_NAME}" \
    --platform managed \
    --region "${REGION}" \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 2 \
    --min-instances 1 \
    --max-instances 5 \
    --port 8080 \
    --set-env-vars "ENVIRONMENT=production,LOG_LEVEL=INFO,GCP_PROJECT_ID=${PROJECT_ID},GCP_REGION=${REGION},GEMINI_MODEL=gemini-3.5-flash,USE_FIRESTORE_EMULATOR=false,API_SECRET_KEY=test_secret_key_12345678901234567890123456789012,RUNNER_BASE_URL=http://localhost:8080,GCS_BUCKET_NAME=bugbounty-swarm-evidence"


echo ""
echo "[4/4] Verifying Cloud Run deployment..."
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform managed --region "${REGION}" --format 'value(status.url)')

echo ""
echo "================================================================="
echo " [SUCCESS] BUGBOUNTY SWARM IS LIVE ON GOOGLE CLOUD RUN!"
echo " Service URL:         ${SERVICE_URL}"
echo " Health Endpoint:     ${SERVICE_URL}/healthz"
echo " Agent Registry:      ${SERVICE_URL}/api/agents"
echo " API Documentation:   ${SERVICE_URL}/docs"
echo "================================================================="
