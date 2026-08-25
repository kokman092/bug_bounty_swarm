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

MODELS_CASCADE = [
    "gemini-3.5-flash",
    "gemini-3.7-flash",
    "gemini-flash-latest",
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3.1-flash-lite",
]

_CLIENT_INSTANCE = None


def _get_genai_client() -> genai.Client:
    global _CLIENT_INSTANCE
    if _CLIENT_INSTANCE is None:
        settings = get_settings()
        _CLIENT_INSTANCE = genai.Client(api_key=settings.gemini_api_key)
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
                    time.sleep(1.5)  # Quick pause on rate limits
                else:
                    logger.warning("llm_model_fallback_attempt", model=model_name, error=str(exc)[:120])

        # If full cascade exhausted on attempt 0, wait briefly before final attempt
        if attempt == 0:
            time.sleep(3.0)

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
