"""
app/discovery/api_mapper.py
───────────────────────────
API Mapping, Protocol Classification & Endpoint Profile Merging Engine.

Capabilities:
  1. REST: Normalization of OpenAPI / Swagger / crawled endpoints.
  2. GraphQL: Strict evidence-based classification (introspection disabled by default).
  3. WebSocket: Evidence-based handshake/upgrade classification.
  4. Unknown: Conservative fallback when evidence is inconclusive.
  5. Deterministic Merging: Provenance-preserving deduplication and profile consolidation.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from app.discovery.models import DiscoveryObservation, EndpointProfile, ParameterProfile
from app.discovery.parameter_discovery import ParameterDiscovery



class APIMapper:
    """Consolidates discovery observations into canonical EndpointProfiles."""

    @staticmethod
    def classify_protocol(
        url_or_path: str,
        headers: dict[str, str] | None = None,
        content_sample: str = "",
        is_schema_documented: bool = False,
    ) -> str:
        """
        Classifies an endpoint protocol strictly from observable evidence into tiers:
          - REST_CONFIRMED | REST_CANDIDATE
          - GRAPHQL_CONFIRMED | GRAPHQL_CANDIDATE
          - WEBSOCKET_CONFIRMED | WEBSOCKET_CANDIDATE
          - UNKNOWN
        """
        headers = headers or {}
        lower_path = url_or_path.lower()
        lower_content = content_sample.lower()

        # 1. WebSocket Evidence
        if url_or_path.startswith(("ws://", "wss://")):
            return "WEBSOCKET_CONFIRMED"
        if headers.get("upgrade", "").lower() == "websocket" or headers.get("connection", "").lower() == "upgrade":
            return "WEBSOCKET_CONFIRMED"
        if "/ws/" in lower_path or lower_path.endswith("/ws") or "/socket.io" in lower_path or "/socket" in lower_path:
            return "WEBSOCKET_CANDIDATE"

        # 2. GraphQL Evidence
        if ("query" in lower_content and ("mutation" in lower_content or "__schema" in lower_content or "data" in lower_content)) or (is_schema_documented and ("graphql" in lower_path or "gql" in lower_path)):
            return "GRAPHQL_CONFIRMED"
        if lower_path.endswith("/graphql") or "/graphql/" in lower_path or lower_path.endswith("/gql"):
            return "GRAPHQL_CANDIDATE"

        # 3. REST API Evidence
        if is_schema_documented or "application/json" in headers.get("content-type", "").lower() or "application/json" in headers.get("accept", "").lower():
            return "REST_CONFIRMED"
        if lower_path.startswith(("/api", "/v1", "/v2", "/v3", "/rest", "/oauth")) or "/api/" in lower_path:
            return "REST_CANDIDATE"

        return "UNKNOWN"


    @classmethod
    def map_openapi_spec(
        cls,
        target_url: str,
        spec_dict: dict[str, Any],
        source_location: str = "openapi.json",
    ) -> list[EndpointProfile]:
        """
        Parses an OpenAPI 3.x or Swagger 2.0 document into structured EndpointProfiles.
        """
        profiles: list[EndpointProfile] = []
        paths_obj = spec_dict.get("paths", {})
        if not isinstance(paths_obj, dict):
            return profiles

        for route_path, methods_data in paths_obj.items():
            if not isinstance(methods_data, dict):
                continue

            for method, details in methods_data.items():
                upper_method = method.upper()
                if upper_method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue

                raw_params = details.get("parameters", [])
                request_body = details.get("requestBody", {})
                params, obj_ids = ParameterDiscovery.extract_from_openapi_schema(
                    raw_params, request_body, source_location=source_location
                )

                # Path variables from route string
                path_params, path_obj_ids = ParameterDiscovery.extract_from_path(route_path, source_location=source_location)
                for p in path_params:
                    if not any(ep.identity_key == p.identity_key for ep in params):
                        params.append(p)
                for oid in path_obj_ids:
                    if oid not in obj_ids:
                        obj_ids.append(oid)

                # Check security metadata
                sec = details.get("security", spec_dict.get("security", []))
                requires_auth = bool(sec)

                obs = DiscoveryObservation(
                    source_type="openapi",
                    source_location=source_location,
                    discovered_url=route_path,
                    method=upper_method,
                    protocol="REST",
                )

                ep = EndpointProfile(
                    target=target_url,
                    endpoint=route_path,
                    method=upper_method,
                    protocol="REST",
                    parameters=params,
                    object_identifiers=obj_ids,
                    content_type="application/json" if upper_method in ("POST", "PUT", "PATCH") else None,
                    authentication_required=requires_auth,
                    discovered_from=[obs],
                )
                profiles.append(ep)

        return profiles

    @classmethod
    def merge_endpoint_profiles(
        cls, existing_profiles: list[EndpointProfile], new_profiles: list[EndpointProfile]
    ) -> list[EndpointProfile]:
        """
        Merges two lists of EndpointProfiles with identity matching and provenance retention.
        Identity Key: (normalized_target, normalized_endpoint, method, protocol)
        """
        merged_map: dict[tuple[str, str, str, str], EndpointProfile] = {}

        def make_key(ep: EndpointProfile) -> tuple[str, str, str, str]:
            norm_target = ep.target.rstrip("/").lower()
            norm_path = ep.endpoint.split("?")[0].split("#")[0].strip()
            norm_path = f"/{norm_path.lstrip('/')}"
            return (norm_target, norm_path, ep.method.upper(), ep.protocol.upper())

        for ep in existing_profiles:
            merged_map[make_key(ep)] = ep

        for new_ep in new_profiles:
            key = make_key(new_ep)
            if key not in merged_map:
                merged_map[key] = new_ep
            else:
                existing = merged_map[key]
                # Merge parameters
                existing_param_keys = {
                    (p.identity_key if isinstance(p, ParameterProfile) else f"query:{p.lower()}")
                    for p in existing.parameters
                }
                for new_p in new_ep.parameters:
                    p_key = new_p.identity_key if isinstance(new_p, ParameterProfile) else f"query:{new_p.lower()}"
                    if p_key not in existing_param_keys:
                        existing.parameters.append(new_p)
                        existing_param_keys.add(p_key)

                # Merge object identifiers
                for oid in new_ep.object_identifiers:
                    if oid not in existing.object_identifiers:
                        existing.object_identifiers.append(oid)

                # Merge provenance
                for obs in new_ep.discovered_from:
                    if obs not in existing.discovered_from:
                        existing.discovered_from.append(obs)

                # Merge auth status if newly resolved
                if existing.authentication_required is None and new_ep.authentication_required is not None:
                    existing.authentication_required = new_ep.authentication_required

                # Merge content type if newly known
                if not existing.content_type and new_ep.content_type:
                    existing.content_type = new_ep.content_type

        return list(merged_map.values())
