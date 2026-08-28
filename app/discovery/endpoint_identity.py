"""
app/discovery/endpoint_identity.py
──────────────────────────────────
Canonical Endpoint Identity & Parameter Specification Engine.

Guarantees:
  1. Deterministic canonical endpoint identities agnostic to query parameter ordering.
  2. Strips URL fragments (#...) and separates structural path from query parameters.
  3. Redacts raw parameter values, storing only parameter metadata and parameter names.
  4. Unifies identity across HunterAgent hypothesis, HTTP requests, EvidenceCollector, and ValidationPipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass(frozen=True)
class CanonicalEndpointIdentity:
    """Canonical, query-order-independent endpoint identity."""
    scheme: str
    host: str
    port: int
    path: str
    method: str
    query_parameter_names: tuple[str, ...] = field(default_factory=tuple)
    protocol: str = "REST"

    @classmethod
    def from_url(
        cls,
        url_or_path: str,
        method: str = "GET",
        target_base_url: str = "",
        protocol: str = "REST",
    ) -> CanonicalEndpointIdentity:
        """Constructs a canonical endpoint identity from URL/path and method."""
        if "://" in url_or_path:
            full_url = url_or_path
        elif target_base_url:
            full_url = f"{target_base_url.rstrip('/')}/{url_or_path.lstrip('/')}"
        else:
            full_url = url_or_path
        parsed = urlparse(full_url)

        
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "localhost").lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed.port if parsed.port else default_port



        # Path without trailing slash (unless root /)
        clean_path = parsed.path or "/"
        if len(clean_path) > 1:
            clean_path = clean_path.rstrip("/")

        # Extract and sort unique query parameter names
        qs = parse_qs(parsed.query, keep_blank_values=True)
        sorted_param_names = tuple(sorted(list(qs.keys())))

        return cls(
            scheme=scheme,
            host=host,
            port=port,
            path=clean_path,
            method=method.upper().strip(),
            query_parameter_names=sorted_param_names,
            protocol=protocol.upper().strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes to standardized dictionary."""
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "method": self.method,
            "query_parameter_names": list(self.query_parameter_names),
            "protocol": self.protocol,
        }

    @property
    def identity_key(self) -> str:
        """Deterministic string key for hash maps and deduplication."""
        params_str = ",".join(self.query_parameter_names)
        return f"{self.scheme}://{self.host}:{self.port}{self.path}#{self.method}#{self.protocol}#{params_str}"


@dataclass
class CanonicalParameterSpec:
    """Sanitized parameter specification with zero raw sensitive value exposure."""
    name: str
    location: str          # path | query | json_body | header | cookie
    value_state: str = "test_value_redacted"
    type_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "value_state": self.value_state,
        }
