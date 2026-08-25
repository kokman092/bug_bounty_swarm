"""
app/core/logging.py
────────────────────
Logging configuration supporting structlog with standard library logging fallback.

Rules:
  - If structlog is available, uses structured processors and JSON/Console renderers.
  - If structlog is not installed, falls back cleanly to stdlib logging with structured dict formatting.
  - Automatically sanitizes sensitive keys (tokens, passwords, api keys).
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

# Sensitive keys to redact
SENSITIVE_KEYS = {
    "api_key", "apikey", "api_secret", "password", "token",
    "authorization", "cookie", "set_cookie", "bearer",
    "gemini_api_key", "secret", "credential",
}


def _redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    redacted = {}
    for k, v in data.items():
        if k.lower() in SENSITIVE_KEYS:
            redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = _redact_dict(v)
        else:
            redacted[k] = v
    return redacted


try:
    import structlog
    from structlog.types import EventDict, Processor

    _HAS_STRUCTLOG = True

    def _add_service_context(
        logger: Any, method: str, event_dict: EventDict
    ) -> EventDict:
        event_dict.setdefault("service", "bugbounty-swarm")
        return event_dict

    def _sanitize_sensitive_fields(
        logger: Any, method: str, event_dict: EventDict
    ) -> EventDict:
        return _redact_dict(event_dict)

    def configure_logging(log_level: str = "INFO", is_development: bool = True) -> None:
        shared_processors: list[Processor] = [
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _add_service_context,
            _sanitize_sensitive_fields,
            structlog.processors.StackInfoRenderer(),
        ]

        if is_development:
            processors = shared_processors + [
                structlog.dev.ConsoleRenderer(colors=True)
            ]
        else:
            processors = shared_processors + [
                structlog.processors.dict_tracebacks,
                structlog.processors.JSONRenderer(),
            ]

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, log_level.upper(), logging.INFO)
            ),
            context_class=dict,
            logger_factory=structlog.PrintLoggerFactory(sys.stdout),
            cache_logger_on_first_use=True,
        )

        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=getattr(logging, log_level.upper(), logging.INFO),
        )

    def get_logger(name: str):
        return structlog.get_logger(name)

except ImportError:
    _HAS_STRUCTLOG = False

    class FallbackLogger:
        def __init__(self, logger: logging.Logger) -> None:
            self._logger = logger

        def _log(self, level: int, msg: str, **kwargs: Any) -> None:
            if not self._logger.isEnabledFor(level):
                return
            safe_kwargs = _redact_dict(kwargs)
            if safe_kwargs:
                formatted = f"{msg} | {json.dumps(safe_kwargs, default=str)}"
            else:
                formatted = msg
            self._logger.log(level, formatted)

        def debug(self, msg: str, **kwargs: Any) -> None:
            self._log(logging.DEBUG, msg, **kwargs)

        def info(self, msg: str, **kwargs: Any) -> None:
            self._log(logging.INFO, msg, **kwargs)

        def warning(self, msg: str, **kwargs: Any) -> None:
            self._log(logging.WARNING, msg, **kwargs)

        def error(self, msg: str, **kwargs: Any) -> None:
            self._log(logging.ERROR, msg, **kwargs)

        def exception(self, msg: str, **kwargs: Any) -> None:
            self._log(logging.ERROR, msg, exc_info=True, **kwargs)

    def configure_logging(log_level: str = "INFO", is_development: bool = True) -> None:
        logging.basicConfig(
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            stream=sys.stdout,
            level=getattr(logging, log_level.upper(), logging.INFO),
            force=True,
        )

    def get_logger(name: str) -> FallbackLogger:
        return FallbackLogger(logging.getLogger(name))
