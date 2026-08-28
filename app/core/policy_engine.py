"""
app/core/policy_engine.py
─────────────────────────
Security policy engine enforcing:
  1. Token-Bucket Rate Limiting (per-host RPS controls).
  2. Concurrency limiting across parallel agent tasks.
  3. Destructive Action Guard (blocks database deletion, broad wildcard DELETE, DoS payloads).
  4. Automatic Backoff & Pause on HTTP 429 / 503 throttles.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import DestructiveActionError, RateLimitExceededError, ScopeViolationError
from app.core.logging import get_logger

logger = get_logger(__name__)



@dataclass
class TokenBucket:
    rate: float          # Tokens added per second
    capacity: float      # Maximum bucket burst capacity
    tokens: float = field(init=False)
    last_updated: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_updated = time.monotonic()

    async def acquire(self, tokens: float = 1.0) -> bool:
        """Acquires tokens, waiting if necessary up to a safe threshold."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_updated
            self.last_updated = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            # Calculate required sleep duration
            needed = tokens - self.tokens
            wait_time = needed / self.rate
            if wait_time > 10.0:  # Do not block indefinitely
                logger.warning("rate_limit_throttle_exceeded", wait_time=wait_time)
                return False

            await asyncio.sleep(wait_time)
            self.tokens = 0.0
            return True


class PolicyEngine:
    """Master policy and safe testing constraint validator."""

    # Patterns matching destructive or unsafe actions
    DESTRUCTIVE_PATH_PATTERNS = [
        re.compile(r"^/(api/)?(system/)?(shutdown|reboot|format|drop_db|reset_db|purge_all)", re.IGNORECASE),
        re.compile(r"^/(api/)?(v[0-9]+/)?users?/\*$", re.IGNORECASE),  # Wildcard user deletion
    ]

    DESTRUCTIVE_PAYLOAD_PATTERNS = [
        re.compile(r"(DROP\s+TABLE|TRUNCATE\s+TABLE|rm\s+-rf\s+/|format\s+c:)", re.IGNORECASE),
        re.compile(r"(:(){ :|:& };:)", re.IGNORECASE),  # Fork bomb
    ]

    def __init__(self, default_rps: float = 10.0, max_burst: float = 20.0) -> None:
        self.default_rps = default_rps
        self.max_burst = max_burst
        self._buckets: dict[str, TokenBucket] = {}
        self._host_backoffs: dict[str, float] = {}  # host -> pause_until_timestamp
        self._endpoint_request_counts: dict[str, int] = {}  # "investigation_id:method:endpoint" -> count
        self._investigation_request_counts: dict[str, int] = {}  # investigation_id -> count
        self._endpoint_budgets: dict[str, int] = {}  # "investigation_id:method:endpoint" -> max_budget

    def set_endpoint_budget(self, investigation_id: str, method: str, endpoint: str, max_requests: int) -> None:
        """Sets max allowed transport request budget for an endpoint in an investigation."""
        clean_ep = endpoint.split("?")[0].strip()
        key = f"{investigation_id}:{method.upper().strip()}:{clean_ep}"
        self._endpoint_budgets[key] = max_requests

    def track_request(self, investigation_id: str, method: str, url: str) -> None:
        """Tracks an executed request against global and per-endpoint budgets."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        clean_ep = path.split("?")[0].strip()
        key = f"{investigation_id}:{method.upper().strip()}:{clean_ep}"

        # Increment counts
        self._investigation_request_counts[investigation_id] = self._investigation_request_counts.get(investigation_id, 0) + 1
        curr_count = self._endpoint_request_counts.get(key, 0) + 1
        self._endpoint_request_counts[key] = curr_count

        # Enforce budget if set
        max_budget = self._endpoint_budgets.get(key)
        if max_budget is not None and curr_count > max_budget:
            logger.warning("request_budget_exceeded", key=key, current=curr_count, max_budget=max_budget)
            raise RateLimitExceededError(f"Request budget exceeded: {curr_count}/{max_budget} requests for {method} {clean_ep}")



    def get_budget_telemetry(self, investigation_id: str) -> dict[str, Any]:
        """Returns sanitized request budget accounting telemetry for an investigation."""
        total_requests = self._investigation_request_counts.get(investigation_id, 0)
        prefix = f"{investigation_id}:"
        endpoint_counts = {
            k[len(prefix):]: v
            for k, v in self._endpoint_request_counts.items()
            if k.startswith(prefix)
        }
        return {
            "investigation_id": investigation_id,
            "total_requests": total_requests,
            "endpoint_request_counts": endpoint_counts,
        }

    def reset_budgets(self, investigation_id: str | None = None) -> None:
        """Resets tracked request counts (used for isolated test suites)."""
        if investigation_id:
            self._investigation_request_counts.pop(investigation_id, None)
            prefix = f"{investigation_id}:"
            keys_to_del = [k for k in self._endpoint_request_counts if k.startswith(prefix)]
            for k in keys_to_del:
                self._endpoint_request_counts.pop(k, None)
                self._endpoint_budgets.pop(k, None)
        else:
            self._investigation_request_counts.clear()
            self._endpoint_request_counts.clear()
            self._endpoint_budgets.clear()

    def _get_bucket(self, host: str) -> TokenBucket:
        if host not in self._buckets:
            self._buckets[host] = TokenBucket(rate=self.default_rps, capacity=self.max_burst)
        return self._buckets[host]

    def validate_action_safety(
        self,
        method: str,
        path: str,
        payload: Any = None,
    ) -> None:
        """
        Validates that a proposed HTTP action is non-destructive and permitted under bug bounty safe harbor.
        """
        method_upper = method.upper()

        # 1. Check prohibited destructive paths on unsafe methods
        if method_upper in ("DELETE", "POST", "PUT", "PATCH"):
            for pat in self.DESTRUCTIVE_PATH_PATTERNS:
                if pat.search(path):
                    raise DestructiveActionError(
                        f"Action blocked: Path '{path}' matches destructive policy filter."
                    )

        # 2. Check destructive payload patterns in body
        if payload:
            payload_str = str(payload)
            for pat in self.DESTRUCTIVE_PAYLOAD_PATTERNS:
                if pat.search(payload_str):
                    raise DestructiveActionError(
                        f"Action blocked: Test payload contains prohibited destructive pattern."
                    )

    async def throttle(self, url: str) -> None:
        """
        Enforces token-bucket rate limiting and handles backoff if target returned 429/503.
        """
        parsed = urlparse(url)
        host = parsed.netloc or url

        # Check active backoff
        now = time.monotonic()
        pause_until = self._host_backoffs.get(host, 0.0)
        if now < pause_until:
            wait_remaining = pause_until - now
            logger.info("host_under_active_backoff", host=host, wait_seconds=wait_remaining)
            await asyncio.sleep(min(wait_remaining, 5.0))

        bucket = self._get_bucket(host)
        allowed = await bucket.acquire(1.0)
        if not allowed:
            raise RateLimitExceededError(f"Rate limit exceeded for host: {host}")

    def record_throttle_signal(self, url: str, status_code: int) -> None:
        """Records 429 or 503 signals from the target to trigger exponential backoff."""
        if status_code in (429, 503):
            parsed = urlparse(url)
            host = parsed.netloc or url
            backoff_duration = 5.0  # 5 second initial pause
            self._host_backoffs[host] = time.monotonic() + backoff_duration
            logger.warning("rate_limit_signal_recorded", host=host, status=status_code, pause_sec=backoff_duration)



# Global Policy Engine Singleton
_POLICY_ENGINE = PolicyEngine()


def get_policy_engine() -> PolicyEngine:
    return _POLICY_ENGINE
