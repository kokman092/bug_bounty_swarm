"""
app/core/config.py
──────────────────
Application configuration loaded from environment variables.
Uses Pydantic Settings for validation and type safety.

NEVER import secrets directly — always use settings.attribute.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Google AI ─────────────────────────────────────────────────────────────
    gemini_api_key: str = Field("", description="Gemini API key (AI Studio or Vertex)")
    gemini_model: str = Field("gemini-3.5-flash", description="Preferred Gemini model (changeable in .env)")
    gcp_oauth_token: str | None = Field(None, description="GCP OAuth Token for Vertex AI")
    google_cloud_project: str | None = Field(None, description="GCP project for Vertex AI")
    google_application_credentials: str | None = Field(
        None, description="Path to service account JSON"
    )

    # ── Google Cloud ──────────────────────────────────────────────────────────
    gcp_project_id: str = Field(..., description="GCP project ID")
    gcp_region: str = Field("us-central1", description="GCP region")
    firestore_database: str = Field("(default)", description="Firestore database name")
    cloud_tasks_queue: str = Field("investigations", description="Cloud Tasks queue name")
    cloud_tasks_location: str = Field("us-central1", description="Cloud Tasks location")
    runner_base_url: str = Field(..., description="Base URL for Cloud Tasks to reach runner")
    gcs_bucket_name: str = Field(..., description="Cloud Storage bucket for large payloads")

    # ── Application ───────────────────────────────────────────────────────────
    api_secret_key: str = Field(..., min_length=32, description="Static API secret key")
    swarm_version: str = Field("2.0.0", description="Swarm version shown in dashboard")
    use_firebase_auth: bool = Field(False, description="Use Firebase Auth instead of API key")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field("INFO")
    environment: Literal["development", "staging", "production"] = Field("development")

    # ── Investigation Limits ──────────────────────────────────────────────────
    max_investigations_per_hour: int = Field(5, ge=1, le=100)
    max_loop_iterations: int = Field(4, ge=1, le=30)
    max_retries: int = Field(2, ge=0, le=5)
    agent_timeout_seconds: int = Field(300, ge=30, le=7200)

    # ── Local Development ─────────────────────────────────────────────────────
    use_firestore_emulator: bool = Field(False)
    firestore_emulator_host: str = Field("localhost:8080")
    allow_local_lab_targets: bool = Field(True, description="Allow localhost testing in development mode")

    # ── Burp Suite Integration ────────────────────────────────────────────────
    burp_proxy_enabled: bool = Field(False)
    burp_proxy_url: str = Field("http://127.0.0.1:8080")
    burp_api_url: str = Field("http://127.0.0.1:1337")
    burp_api_key: str = Field("")
    burp_collaborator_server: str = Field("")

    @field_validator("api_secret_key")
    @classmethod
    def secret_not_default(cls, v: str) -> str:
        if v in ("change_me_generate_a_real_secret", "your_secret_here"):
            raise ValueError(
                "api_secret_key must be set to a real secret. "
                "Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        return v

    @property
    def is_development(self) -> bool:
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached settings singleton.
    Use this function everywhere — do NOT instantiate Settings() directly.

    Example:
        from app.core.config import get_settings
        settings = get_settings()
    """
    return Settings()
