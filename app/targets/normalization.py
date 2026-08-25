"""
app/targets/normalization.py
──────────────────────────────
URL normalization for canonical comparison.

Problem it solves:
  If authorized_targets stores "http://foo.com" and an agent requests
  "http://FOO.COM:80/", a naive string comparison would fail even though
  these are the same resource. Attackers exploit normalization gaps to
  bypass allow-lists.

Canonical form:
  scheme://lowercase_host:explicit_port/normalized_path

Examples:
  http://FOO.COM         → http://foo.com:80/
  https://foo.com:443/   → https://foo.com:443/
  http://foo.com/        → http://foo.com:80/
  http://foo.com:80      → http://foo.com:80/
  http://foo.com/a//b/   → http://foo.com:80/a/b/
  http://foo.com/a/../b  → http://foo.com:80/b

Security notes:
  - Only http and https schemes are allowed (rejects file://, ftp://, etc.)
  - Port must be a valid integer 1–65535
  - Hostname is lowercased (DNS is case-insensitive)
  - Consecutive slashes in path are collapsed
  - Path traversal (..) is resolved
"""
from __future__ import annotations

import posixpath
import re
from urllib.parse import ParseResult, urlencode, urlparse, urlunparse

from app.core.exceptions import URLNormalizationError
from app.targets.schemas import NormalizedURL

# Only these schemes are ever permitted
_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Default ports per scheme
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

# Hostname validation pattern
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$"
)


def normalize_url(raw_url: str) -> NormalizedURL:
    """
    Parse and normalize a URL to its canonical form.

    Raises URLNormalizationError if the URL is invalid or uses a
    disallowed scheme.

    Returns a NormalizedURL with all canonical components.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise URLNormalizationError(str(raw_url), "URL must be a non-empty string")

    raw_url = raw_url.strip()

    # Add scheme if missing (bare host like "foo.com")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    try:
        parsed: ParseResult = urlparse(raw_url)
    except Exception as exc:
        raise URLNormalizationError(raw_url, f"Parse error: {exc}") from exc

    # ── Scheme ────────────────────────────────────────────────────────────────
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise URLNormalizationError(
            raw_url,
            f"Scheme '{scheme}' is not allowed. Only http and https are permitted.",
        )

    # ── Hostname ──────────────────────────────────────────────────────────────
    host = parsed.hostname
    if not host:
        raise URLNormalizationError(raw_url, "URL has no hostname")

    host = host.lower()

    # Validate hostname characters (reject IP-like strings we'll catch later,
    # but ensure no invalid chars sneak through)
    # IP addresses are allowed here — private IP check happens separately
    if not _is_valid_hostname_or_ip(host):
        raise URLNormalizationError(raw_url, f"Invalid hostname: '{host}'")

    # ── Port ──────────────────────────────────────────────────────────────────
    try:
        if parsed.port is not None:
            port = parsed.port
            if not (1 <= port <= 65535):
                raise URLNormalizationError(raw_url, f"Invalid port: {port}")
        else:
            port = _DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise URLNormalizationError(raw_url, f"Invalid port in URL: {exc}")

    # ── Path ──────────────────────────────────────────────────────────────────
    path = parsed.path or "/"

    # Resolve path traversal and collapse consecutive slashes
    # posixpath.normpath collapses // and resolves ..
    path = posixpath.normpath(path)

    # normpath strips trailing slash — restore it for directory-like paths
    if (parsed.path.endswith("/") or not parsed.path) and not path.endswith("/"):
        path = path + "/"

    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path

    canonical = _build_canonical(scheme, host, port, path)

    return NormalizedURL(
        original=raw_url,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        canonical=canonical,
    )


def _build_canonical(scheme: str, host: str, port: int, path: str) -> str:
    """Build canonical URL string: scheme://host:port/path"""
    return f"{scheme}://{host}:{port}{path}"


def _is_valid_hostname_or_ip(host: str) -> bool:
    """
    Returns True if host is a valid DNS hostname or IP address.
    Does NOT check whether it's private — that's private_ip.py's job.
    """
    # IPv4 check
    parts = host.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return True
        except ValueError:
            pass

    # IPv6 check (brackets stripped by urlparse)
    if ":" in host:
        return True  # Basic IPv6 — further validation in private_ip.py

    # Hostname check
    return bool(_HOSTNAME_RE.match(host))


def are_same_origin(url_a: str, url_b: str) -> bool:
    """
    Check if two URLs have the same canonical origin (scheme + host + port).
    Used for redirect validation.
    """
    try:
        a = normalize_url(url_a)
        b = normalize_url(url_b)
        return (a.scheme == b.scheme and a.host == b.host and a.port == b.port)
    except URLNormalizationError:
        return False
