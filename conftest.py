"""
conftest.py
───────────
Pytest configuration and test environment initialization.
"""
import os
import sys
from pathlib import Path

# Ensure root workspace directory is in sys.path
root_dir = Path(__file__).parent.resolve()
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Set test environment variables
os.environ.setdefault("GEMINI_API_KEY", "test_gemini_api_key_placeholder")
os.environ.setdefault("API_SECRET_KEY", "test_secret_key_12345678901234567890123456789012")
os.environ.setdefault("GCP_PROJECT_ID", "demo-bugbounty")
os.environ.setdefault("GCS_BUCKET_NAME", "demo-bucket")
os.environ.setdefault("RUNNER_BASE_URL", "http://localhost:8000")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("USE_FIRESTORE_EMULATOR", "true")
