"""
app/core/exceptions.py
──────────────────────
Custom exception hierarchy for the BugBounty Swarm application.

Rules:
  - All application exceptions inherit from SwarmBaseException.
  - HTTP status codes live here for exceptions that map to API responses.
  - Do NOT import FastAPI here — this module has no web framework dependency.
"""
from __future__ import annotations


# ── Base ──────────────────────────────────────────────────────────────────────

class SwarmBaseException(Exception):
    """Root of the BugBounty Swarm exception hierarchy."""
    http_status: int = 500
    error_code: str = "internal_error"

    def __init__(self, message: str = "An internal error occurred") -> None:
        self.message = message
        super().__init__(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r})"


# ── Authorization & Safety ────────────────────────────────────────────────────

class TargetNotAuthorizedError(SwarmBaseException):
    """Raised when a target URL is not in the authorized_targets allow-list."""
    http_status = 403
    error_code = "target_not_authorized"

    def __init__(self, url: str, reason: str = "Target is not in the allow-list") -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"Target '{url}' not authorized: {reason}")


class PrivateIPAccessError(SwarmBaseException):
    """Raised when a tool attempts to contact a private/internal IP address."""
    http_status = 403
    error_code = "private_ip_access_blocked"

    def __init__(self, url: str, resolved_ip: str | None = None) -> None:
        self.url = url
        self.resolved_ip = resolved_ip
        detail = f" (resolved to {resolved_ip})" if resolved_ip else ""
        super().__init__(f"Access to private/internal address blocked: {url}{detail}")


class URLNormalizationError(SwarmBaseException):
    """Raised when a URL cannot be parsed or normalized."""
    http_status = 400
    error_code = "invalid_url"

    def __init__(self, url: str, reason: str = "URL could not be parsed") -> None:
        self.url = url
        super().__init__(f"Invalid URL '{url}': {reason}")


class ScopeViolationError(SwarmBaseException):
    """
    Raised at tool execution time when a requested URL is outside the
    authorized scope for this investigation.
    """
    http_status = 403
    error_code = "scope_violation"

    def __init__(self, url: str, investigation_id: str = "") -> None:
        self.url = url
        self.investigation_id = investigation_id
        super().__init__(
            f"URL '{url}' is outside the authorized scope for "
            f"investigation '{investigation_id}'" if investigation_id else f"URL '{url}' is outside authorized scope"
        )


class DestructiveActionError(SwarmBaseException):
    """Raised when an agent attempts a destructive or prohibited test action."""
    http_status = 403
    error_code = "destructive_action_blocked"

    def __init__(self, reason: str = "Action blocked by safety policy") -> None:
        super().__init__(reason)


class RateLimitExceededError(SwarmBaseException):
    """Raised when target rate limit is exceeded."""
    http_status = 429
    error_code = "rate_limit_exceeded"

    def __init__(self, message: str = "Target rate limit exceeded") -> None:
        super().__init__(message)


# ── Investigation Lifecycle ───────────────────────────────────────────────────


class InvestigationNotFoundError(SwarmBaseException):
    """
    Raised when an investigation does not exist OR the caller does not own it.
    Intentionally returns 404 (not 403) to prevent enumeration.
    """
    http_status = 404
    error_code = "investigation_not_found"

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"Investigation '{investigation_id}' not found")


class InvalidStateTransitionError(SwarmBaseException):
    """Raised when an illegal state machine transition is attempted."""
    http_status = 409
    error_code = "invalid_state_transition"

    def __init__(self, current: str, attempted: str) -> None:
        self.current = current
        self.attempted = attempted
        super().__init__(
            f"Cannot transition from '{current}' to '{attempted}'"
        )


class InvestigationAlreadyTerminalError(SwarmBaseException):
    """Raised when an operation is attempted on a terminal investigation."""
    http_status = 409
    error_code = "investigation_terminal"

    def __init__(self, investigation_id: str, status: str) -> None:
        self.investigation_id = investigation_id
        self.status = status
        super().__init__(
            f"Investigation '{investigation_id}' is in terminal state '{status}'"
        )


class InvestigationRunnerError(SwarmBaseException):
    """Raised when the investigation runner encounters an unrecoverable error."""
    http_status = 500
    error_code = "runner_error"


# ── Agent Errors ──────────────────────────────────────────────────────────────

class AgentTimeoutError(SwarmBaseException):
    """Raised when an agent step exceeds its configured timeout."""
    http_status = 504
    error_code = "agent_timeout"

    def __init__(self, agent_name: str, timeout_s: int) -> None:
        self.agent_name = agent_name
        self.timeout_s = timeout_s
        super().__init__(f"Agent '{agent_name}' timed out after {timeout_s}s")


class ModelAPIError(SwarmBaseException):
    """Raised when the Gemini model API returns an error."""
    http_status = 502
    error_code = "model_api_error"

    def __init__(self, agent_name: str, reason: str) -> None:
        self.agent_name = agent_name
        super().__init__(f"Model API error in '{agent_name}': {reason}")


class ContextTooLargeError(SwarmBaseException):
    """Raised when agent context exceeds the maximum token budget."""
    http_status = 500
    error_code = "context_too_large"

    def __init__(self, agent_name: str, estimated_tokens: int, max_tokens: int) -> None:
        self.agent_name = agent_name
        super().__init__(
            f"Agent '{agent_name}' context too large: "
            f"{estimated_tokens} estimated tokens (max {max_tokens})"
        )


# ── API Errors ────────────────────────────────────────────────────────────────

class AuthenticationError(SwarmBaseException):
    """Raised when a request is not authenticated."""
    http_status = 401
    error_code = "not_authenticated"

    def __init__(self) -> None:
        super().__init__("Authentication required")


class RateLimitError(SwarmBaseException):
    """Raised when a user exceeds their rate limit."""
    http_status = 429
    error_code = "rate_limit_exceeded"

    def __init__(self, retry_after_seconds: int = 3600) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Rate limit exceeded. Retry after {retry_after_seconds}s")
