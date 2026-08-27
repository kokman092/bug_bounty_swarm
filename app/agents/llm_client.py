"""
app/agents/llm_client.py
────────────────────────
Unified Google GenAI LLM Client with multi-model fallback across Gemini 3.5 Flash,
Gemini Flash Latest, and Gemini Flash Lite.
Tracks exact token usage and latency metrics.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict
from google import genai
from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

VERTEX_MODELS_CASCADE = [
    "gemini-2.5-flash",
    "gemini-2.5-pro",
]

AISTUDIO_MODELS_CASCADE = [
    "gemini-3.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.7-flash",
    "gemini-flash-latest",
]



MODELS_CASCADE = VERTEX_MODELS_CASCADE + AISTUDIO_MODELS_CASCADE

_CLIENT_INSTANCE = None
_IS_VERTEX_MODE = False


def _get_genai_client() -> genai.Client:
    global _CLIENT_INSTANCE, _IS_VERTEX_MODE, MODELS_CASCADE
    if _CLIENT_INSTANCE is None:
        import os
        settings = get_settings()
        gemini_key = (settings.gemini_api_key or os.getenv("GEMINI_API_KEY") or "").strip()
        oauth_token = (settings.gcp_oauth_token or os.getenv("GCP_OAUTH_TOKEN") or "").strip()
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or settings.gcp_project_id or "project-4183c876-9be4-4bc7-9f2"
        region = os.getenv("GCP_REGION") or settings.gcp_region or "us-central1"

        preferred = settings.gemini_model or "gemini-3.5-flash-lite"
        all_aistudio = ["gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.6-flash", "gemini-3.7-flash", "gemini-flash-latest"]
        ordered = [preferred] + [m for m in all_aistudio if m != preferred]



        # 1. AI Studio Mode: preferred when GEMINI_API_KEY is set
        if gemini_key and len(gemini_key) > 10 and not gemini_key.startswith("your_"):
            _CLIENT_INSTANCE = genai.Client(api_key=gemini_key)
            _IS_VERTEX_MODE = False
            MODELS_CASCADE = ordered
            logger.info("llm_client_initialized_aistudio", model=preferred, key_prefix=gemini_key[:6] + "...")
        # 2. Vertex AI with OAuth token (only if key is a real token, not empty)
        elif oauth_token and len(oauth_token) > 20:
            from google.oauth2.credentials import Credentials
            creds = Credentials(token=oauth_token)
            _CLIENT_INSTANCE = genai.Client(
                vertexai=True,
                project=project_id,
                location=region,
                credentials=creds,
            )
            _IS_VERTEX_MODE = True
            MODELS_CASCADE = VERTEX_MODELS_CASCADE
            logger.info("llm_client_initialized_vertex_oauth", project=project_id, region=region)
        else:
            # 3. Native Google Cloud Vertex AI (Cloud Run / ADC)
            _CLIENT_INSTANCE = genai.Client(
                vertexai=True,
                project=project_id,
                location=region,
            )
            _IS_VERTEX_MODE = True
            MODELS_CASCADE = VERTEX_MODELS_CASCADE
            logger.info("llm_client_initialized_vertex_native", project=project_id, region=region)
    return _CLIENT_INSTANCE


# In-memory token counter for live investigation telemetry
_GLOBAL_TOKEN_METRICS = {
    "total_prompt_tokens": 0,
    "total_completion_tokens": 0,
    "total_tokens": 0,
    "call_count": 0,
}


def get_token_metrics() -> Dict[str, int]:
    """Returns total tokens consumed across all agent calls."""
    return dict(_GLOBAL_TOKEN_METRICS)


def generate_structured_content(
    contents: str,
    system_instruction: str,
    response_mime_type: str = "application/json",
    temperature: float = 0.2,
) -> str:
    """Invokes Gemini with automatic model failover, rate-limit backoff, and exact token usage tracking."""
    client = _get_genai_client()

    last_error = None
    t0 = time.perf_counter()

    for attempt in range(2):  # Two full passes over cascade with backoff
        for model_name in MODELS_CASCADE:
            try:
                resp = client.models.generate_content(
                    model=model_name,
                    contents=contents,
                    config={
                        "system_instruction": system_instruction,
                        "response_mime_type": response_mime_type,
                        "temperature": temperature,
                    },
                )
                raw_text = resp.text.strip() if resp.text else ""
                elapsed_ms = int((time.perf_counter() - t0) * 1000)

                # Record token usage from Gemini metadata
                prompt_tokens = 0
                completion_tokens = 0
                total_tokens = 0

                if hasattr(resp, "usage_metadata") and resp.usage_metadata:
                    prompt_tokens = getattr(resp.usage_metadata, "prompt_token_count", 0) or 0
                    completion_tokens = getattr(resp.usage_metadata, "candidates_token_count", 0) or 0
                    total_tokens = getattr(resp.usage_metadata, "total_token_count", 0) or (prompt_tokens + completion_tokens)
                else:
                    prompt_tokens = len(contents.split()) * 2
                    completion_tokens = len(raw_text.split()) * 2
                    total_tokens = prompt_tokens + completion_tokens

                _GLOBAL_TOKEN_METRICS["total_prompt_tokens"] += prompt_tokens
                _GLOBAL_TOKEN_METRICS["total_completion_tokens"] += completion_tokens
                _GLOBAL_TOKEN_METRICS["total_tokens"] += total_tokens
                _GLOBAL_TOKEN_METRICS["call_count"] += 1

                logger.info(
                    "llm_call_completed",
                    model=model_name,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    total_tokens=total_tokens,
                    latency_ms=elapsed_ms,
                )

                if raw_text:
                    return raw_text
            except Exception as exc:
                err_str = str(exc).lower()
                last_error = exc
                if "429" in err_str or "resource_exhausted" in err_str or "quota" in err_str:
                    logger.warning("llm_rate_limited_backing_off", model=model_name, error=str(exc)[:120])
                    time.sleep(2.0)
                elif "503" in err_str or "unavailable" in err_str or "high demand" in err_str:
                    logger.warning("llm_high_demand_backing_off", model=model_name, error=str(exc)[:120])
                    time.sleep(2.0)
                else:
                    logger.warning("llm_model_fallback_attempt", model=model_name, error=str(exc)[:120])

        # If full cascade exhausted on this attempt pass, backoff before next pass
        if attempt < 2:
            backoff_sec = 3.0 * (attempt + 1)
            time.sleep(backoff_sec)

    raise last_error or RuntimeError("All Gemini models in cascade failed to return text.")


async def agenerate_structured_content(
    contents: str,
    system_instruction: str,
    response_mime_type: str = "application/json",
    temperature: float = 0.2,
) -> str:
    """Non-blocking async wrapper that offloads LLM network calls to a worker thread."""
    import asyncio
    return await asyncio.to_thread(
        generate_structured_content,
        contents,
        system_instruction,
        response_mime_type,
        temperature,
    )
