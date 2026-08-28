"""
app/discovery/response_classifier.py
────────────────────────────────────
Response Classifier & SPA Fallback Detection Engine.

Classifies HTTP responses into structured categories:
  - JSON_API: Valid JSON response from an active REST/GraphQL endpoint.
  - HTML_DOCUMENT: Regular server-rendered HTML document or landing page.
  - SPA_FALLBACK: Client-side single page app fallback serving index.html on missing/guessed routes.
  - DIRECTORY_LISTING: Server-generated directory listing index.
  - ERROR_DOCUMENT: Error pages (404, 500, nginx/apache error templates).
  - REDIRECT: HTTP 3xx redirection responses.
  - UNKNOWN: Inconclusive or unclassified responses.

Provides deterministic SPA root-page fingerprinting and similarity matching.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse


class ResponseKind(str, Enum):
    JSON_API = "JSON_API"
    HTML_DOCUMENT = "HTML_DOCUMENT"
    SPA_FALLBACK = "SPA_FALLBACK"
    DIRECTORY_LISTING = "DIRECTORY_LISTING"
    ERROR_DOCUMENT = "ERROR_DOCUMENT"
    REDIRECT = "REDIRECT"
    UNKNOWN = "UNKNOWN"


@dataclass
class SpaFingerprint:
    """Stable fingerprint of an application's root single page application response."""
    status_code: int
    content_length: int
    content_hash: str
    title: str
    app_markers: list[str] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    body_structure_hash: str = ""


@dataclass
class ResponseClassification:
    """Structured result of response classification."""
    response_kind: ResponseKind
    is_real_resource: bool
    testable_as_api: bool
    status_code: int
    content_type: str
    reason: str
    spa_similarity: float = 0.0
    detected_markers: list[str] = field(default_factory=list)
    sanitized_metadata: dict[str, Any] = field(default_factory=dict)


class ResponseClassifier:
    """Classifier for HTTP responses with deterministic SPA fallback detection."""

    # Common Single Page Application bootstrap elements & framework markers
    SPA_MARKERS = [
        re.compile(r"<app-root\b", re.IGNORECASE),             # Angular (e.g. Juice Shop)
        re.compile(r'<div\s+id=["\']root["\']', re.IGNORECASE), # React
        re.compile(r'<div\s+id=["\']app["\']', re.IGNORECASE),  # Vue / Svelte
        re.compile(r"<script[^>]+src=[\"'][^\"']*(runtime|main|polyfills|vendor|bundle)[^\"']*\.js", re.IGNORECASE),
        re.compile(r"owasp\s+juice\s+shop", re.IGNORECASE),
        re.compile(r"<base\s+href=[\"']/?[\"']", re.IGNORECASE),
    ]

    # Server directory listing markers
    DIRECTORY_MARKERS = [
        re.compile(r"<title>Index of\s+[^<]+</title>", re.IGNORECASE),
        re.compile(r"<h1>Index of\s+[^<]+</h1>", re.IGNORECASE),
        re.compile(r'<a\s+href="[^"]+">\s*Parent Directory\s*</a>', re.IGNORECASE),
        re.compile(r"<pre><a href=.*Directory Listing", re.IGNORECASE),
    ]

    # Generic server error page markers
    ERROR_MARKERS = [
        re.compile(r"<title>(404 Not Found|500 Internal Server Error|502 Bad Gateway|503 Service Unavailable)</title>", re.IGNORECASE),
        re.compile(r"<h1>(Not Found|Internal Server Error|Bad Gateway|Forbidden)</h1>", re.IGNORECASE),
        re.compile(r"<center>nginx(/[0-9.]+)?</center>", re.IGNORECASE),
        re.compile(r"<address>Apache(/[0-9.]+)?\s+Server</address>", re.IGNORECASE),
    ]

    def __init__(self, root_fingerprint: SpaFingerprint | None = None) -> None:
        self.root_fingerprint = root_fingerprint

    @classmethod
    def compute_spa_fingerprint(cls, status_code: int, headers: dict[str, str], body_text: str) -> SpaFingerprint:
        """Computes a stable fingerprint of the root application response."""
        content_hash = hashlib.sha256(body_text.encode("utf-8", errors="replace")).hexdigest()
        
        # Extract title
        title_m = re.search(r"<title\b[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
        title = title_m.group(1).strip() if title_m else ""

        # Extract app markers
        markers = []
        for pat in cls.SPA_MARKERS:
            if pat.search(body_text):
                markers.append(pat.pattern)

        # Extract script sources
        script_srcs = re.findall(r'<script\b[^>]+src=["\']([^"\']+)["\']', body_text, re.IGNORECASE)

        # Compute normalized structural tag hash (ignoring dynamic values)
        tag_tokens = re.findall(r"</?([a-zA-Z0-9_-]+)", body_text)
        structure_hash = hashlib.sha256(" ".join(tag_tokens).encode("utf-8")).hexdigest()

        return SpaFingerprint(
            status_code=status_code,
            content_length=len(body_text),
            content_hash=content_hash,
            title=title,
            app_markers=markers,
            script_srcs=script_srcs,
            body_structure_hash=structure_hash,
        )

    def classify_response(
        self,
        url_or_path: str,
        status_code: int,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> ResponseClassification:
        """
        Classifies an HTTP response into its canonical ResponseClassification.
        """
        headers = headers or {}
        ct_header = headers.get("content-type", headers.get("Content-Type", "")).lower()
        clean_path = urlparse(url_or_path).path if "://" in url_or_path else url_or_path.split("?")[0].split("#")[0]

        # 1. Check Redirects
        if status_code in (301, 302, 303, 307, 308):
            loc = headers.get("location", headers.get("Location", ""))
            return ResponseClassification(
                response_kind=ResponseKind.REDIRECT,
                is_real_resource=True,
                testable_as_api=False,
                status_code=status_code,
                content_type=ct_header,
                reason=f"HTTP redirect to {loc}",
                sanitized_metadata={"location": loc},
            )

        # 2. Check JSON API Responses
        if "application/json" in ct_header or (status_code == 200 and body_text.strip().startswith(("{", "["))):
            try:
                parsed = json.loads(body_text)
                return ResponseClassification(
                    response_kind=ResponseKind.JSON_API,
                    is_real_resource=True,
                    testable_as_api=True,
                    status_code=status_code,
                    content_type=ct_header or "application/json",
                    reason="Valid JSON content returned with API status",
                    sanitized_metadata={"json_type": type(parsed).__name__, "length": len(body_text)},
                )
            except Exception:
                pass

        # 3. Check Directory Listing
        for pat in self.DIRECTORY_MARKERS:
            if pat.search(body_text):
                return ResponseClassification(
                    response_kind=ResponseKind.DIRECTORY_LISTING,
                    is_real_resource=True,
                    testable_as_api=False,
                    status_code=status_code,
                    content_type=ct_header,
                    reason="Server directory index listing detected",
                    sanitized_metadata={"marker": pat.pattern},
                )

        # 4. Check Explicit Error Pages
        if status_code >= 400:
            return ResponseClassification(
                response_kind=ResponseKind.ERROR_DOCUMENT,
                is_real_resource=False,
                testable_as_api=False,
                status_code=status_code,
                content_type=ct_header,
                reason=f"HTTP client/server error response (status {status_code})",
                sanitized_metadata={"status_code": status_code},
            )

        # 5. Check SPA Fallback on Non-Root Routes
        is_html = "text/html" in ct_header or "<!doctype html" in body_text.lower() or "<html" in body_text.lower()
        if is_html and clean_path not in ("/", ""):
            # If we have a root fingerprint, compare similarity
            if self.root_fingerprint:
                # Direct content hash match
                curr_hash = hashlib.sha256(body_text.encode("utf-8", errors="replace")).hexdigest()
                if curr_hash == self.root_fingerprint.content_hash:
                    return ResponseClassification(
                        response_kind=ResponseKind.SPA_FALLBACK,
                        is_real_resource=False,
                        testable_as_api=False,
                        status_code=status_code,
                        content_type=ct_header,
                        reason="Response matches root SPA HTML hash exactly (SPA fallback route)",
                        spa_similarity=1.0,
                        sanitized_metadata={"fingerprint_matched": True, "path": clean_path},
                    )



                # Structure & tag comparison
                tag_tokens = re.findall(r"</?([a-zA-Z0-9_-]+)", body_text)
                structure_hash = hashlib.sha256(" ".join(tag_tokens).encode("utf-8")).hexdigest()
                if structure_hash == self.root_fingerprint.body_structure_hash:
                    return ResponseClassification(
                        response_kind=ResponseKind.SPA_FALLBACK,
                        is_real_resource=False,
                        testable_as_api=False,
                        status_code=status_code,
                        content_type=ct_header,
                        reason="Response matches root SPA HTML structure (SPA fallback route)",
                        spa_similarity=0.95,
                        sanitized_metadata={"structure_matched": True, "path": clean_path},
                    )

                # Size & Title similarity
                title_m = re.search(r"<title\b[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
                curr_title = title_m.group(1).strip() if title_m else ""
                if curr_title and curr_title == self.root_fingerprint.title:
                    size_diff = abs(len(body_text) - self.root_fingerprint.content_length)
                    if size_diff < 500:  # Negligible size difference (e.g. CSRF token or nonce)
                        return ResponseClassification(
                            response_kind=ResponseKind.SPA_FALLBACK,
                            is_real_resource=False,
                            testable_as_api=False,
                            status_code=status_code,
                            content_type=ct_header,
                            reason="Response has identical title and size to root SPA index",
                            spa_similarity=0.90,
                            sanitized_metadata={"title": curr_title, "path": clean_path},
                        )

            # Heuristic check for common SPA indicators when no root fingerprint is set
            matched_markers = [pat.pattern for pat in self.SPA_MARKERS if pat.search(body_text)]
            if len(matched_markers) >= 2:
                return ResponseClassification(
                    response_kind=ResponseKind.SPA_FALLBACK,
                    is_real_resource=False,
                    testable_as_api=False,
                    status_code=status_code,
                    content_type=ct_header,
                    reason=f"Multiple SPA bootstrap markers detected on path {clean_path}",
                    spa_similarity=0.85,
                    detected_markers=matched_markers,
                    sanitized_metadata={"markers_count": len(matched_markers), "path": clean_path},
                )

            # Standard HTML document
            return ResponseClassification(
                response_kind=ResponseKind.HTML_DOCUMENT,
                is_real_resource=True,
                testable_as_api=False,
                status_code=status_code,
                content_type=ct_header,
                reason="Server-rendered HTML page",
                sanitized_metadata={"path": clean_path},
            )

        # 6. Fallback HTML for root
        if is_html:
            return ResponseClassification(
                response_kind=ResponseKind.HTML_DOCUMENT,
                is_real_resource=True,
                testable_as_api=False,
                status_code=status_code,
                content_type=ct_header,
                reason="Root HTML landing page",
                sanitized_metadata={"path": clean_path},
            )

        return ResponseClassification(
            response_kind=ResponseKind.UNKNOWN,
            is_real_resource=False,
            testable_as_api=False,
            status_code=status_code,
            content_type=ct_header,
            reason="Inconclusive response content",
            sanitized_metadata={"path": clean_path},
        )
