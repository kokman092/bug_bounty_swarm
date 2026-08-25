"""
app/db/storage.py
──────────────────
Cloud Storage client for large payload overflow with offline fallback.
"""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

try:
    from google.cloud import storage
    _HAS_STORAGE = True
except ImportError:
    _HAS_STORAGE = False
    storage = None  # type: ignore


@lru_cache(maxsize=1)
def get_storage_client() -> Any:
    settings = get_settings()
    if not _HAS_STORAGE:
        from unittest.mock import MagicMock
        return MagicMock()
    return storage.Client(project=settings.gcp_project_id)


def _bucket() -> Any:
    settings = get_settings()
    return get_storage_client().bucket(settings.gcs_bucket_name)


async def upload_json(path: str, data: dict | str) -> str:
    """Upload JSON data to Cloud Storage."""
    settings = get_settings()
    if not _HAS_STORAGE:
        return f"gs://{settings.gcs_bucket_name}/{path}"

    blob = _bucket().blob(path)
    content = json.dumps(data) if isinstance(data, dict) else data
    blob.upload_from_string(content, content_type="application/json")
    gcs_path = f"gs://{settings.gcs_bucket_name}/{path}"
    logger.debug("gcs_upload", path=gcs_path, size_bytes=len(content))
    return gcs_path


async def download_json(gcs_path: str) -> dict | str:
    """Download and parse JSON from a GCS path."""
    settings = get_settings()
    if not _HAS_STORAGE:
        return {}

    prefix = f"gs://{settings.gcs_bucket_name}/"
    if gcs_path.startswith(prefix):
        blob_path = gcs_path[len(prefix):]
    else:
        blob_path = gcs_path

    blob = _bucket().blob(blob_path)
    content = blob.download_as_text()
    return json.loads(content)


def evidence_path(investigation_id: str, finding_id: str) -> str:
    return f"{investigation_id}/evidence/{finding_id}.json"


def report_path(investigation_id: str) -> str:
    return f"{investigation_id}/report/markdown.txt"
