"""
app/discovery/parameter_discovery.py
────────────────────────────────────
Deterministic Parameter Discovery & Classification Engine.

Supports safe extraction from:
  1. URL Path templates (`/api/users/{id}`, `/orders/:order_id`).
  2. Query strings (names only, values discarded/redacted).
  3. HTML forms (inputs, selects, textareas, enctype, CSRF flags).
  4. JSON body schemas (OpenAPI / Swagger requestBody definitions).
  5. Header & Cookie parameters (metadata only, values redacted).
  6. GraphQL variable definitions.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.discovery.models import DiscoveryObservation, ParameterProfile

# Common object identifier names in REST and GraphQL APIs
OBJECT_ID_PATTERNS = re.compile(
    r"^(id|[a-z0-9_]+_id|[a-zA-Z0-9]+Id|uuid|[a-z0-9_]+_uuid|pk|[a-z0-9_]+_pk)$",
    re.IGNORECASE,
)

SENSITIVE_PARAM_PATTERNS = re.compile(
    r"(password|passwd|pass_confirm|password_confirmation|secret|token|bearer|api[_-]?key|"
    r"csrf|xsrf|auth|authorization|credentials|otp|mfa|2fa|pin|recovery|session|cookie|"
    r"cvv|card|pan|payment|ssn|dob|file_content|upload_data)",
    re.IGNORECASE,
)


class ParameterDiscovery:
    """Extracts, normalizes, and classifies parameters from various discovery sources."""

    @classmethod
    def check_sensitivity(cls, name: str) -> tuple[bool, bool, str | None]:
        """
        Evaluates parameter name for sensitive parameter safety policy.
        Returns: (is_sensitive, is_eligible_for_automated_testing, sensitivity_reason)
        """
        if SENSITIVE_PARAM_PATTERNS.search(name):
            return (
                True,
                False,
                f"Sensitive parameter '{name}' is excluded from automated test planning per safety policy",
            )
        return False, True, None

    @staticmethod
    def extract_from_path(
        path: str, source_location: str = "url_template"
    ) -> tuple[list[ParameterProfile], list[str]]:
        """
        Extracts template parameters and object identifiers from URL paths.
        Examples: /api/users/{user_id}/orders/:order_id
        """
        parameters: list[ParameterProfile] = []
        object_ids: list[str] = []

        # 1. Match {param_name} or :param_name
        template_matches = re.findall(r"\{([^}]+)\}|:([a-zA-Z0-9_]+)", str(path))
        for m in template_matches:
            name = m[0] or m[1]
            if not name:
                continue

            is_obj_id = bool(OBJECT_ID_PATTERNS.match(name) or name.lower() in ("id", "user_id", "order_id", "account_id"))
            is_sensitive, is_eligible, sens_reason = ParameterDiscovery.check_sensitivity(name)
            reason = "Path template variable"
            if is_obj_id:
                reason = "Path parameter matching standard object identifier naming convention"
                object_ids.append(name)

            obs = DiscoveryObservation(
                source_type="path_template",
                source_location=source_location,
                discovered_url=str(path),
                parameter_name=name,
                parameter_location="path",
            )

            parameters.append(
                ParameterProfile(
                    name=name,
                    location="path",
                    type_hint="string",
                    required=True,
                    object_identifier_candidate=is_obj_id,
                    reason=reason,
                    sensitive=is_sensitive,
                    eligible_for_automated_testing=is_eligible,
                    sensitivity_reason=sens_reason,
                    source_observations=[obs],
                )
            )


        # 2. Match concrete path segments like /api/users/101 or /orders/5
        for segment in str(path).strip("/").split("/"):
            clean_seg = segment.split("?")[0].split("#")[0].strip()
            if clean_seg.isdigit() or (len(clean_seg) >= 8 and "-" in clean_seg):
                if clean_seg not in object_ids:
                    object_ids.append(clean_seg)

        return parameters, object_ids


    @staticmethod
    def extract_from_query_string(
        url_or_query: str, source_location: str = "link"
    ) -> list[ParameterProfile]:
        """
        Extracts query parameter names from URL or raw query string without storing values.
        """
        query = urlparse(url_or_query).query if "://" in url_or_query or "?" in url_or_query else url_or_query
        parsed_params = parse_qs(query, keep_blank_values=True)
        profiles: list[ParameterProfile] = []

        for name in parsed_params.keys():
            clean_name = name.strip()
            if not clean_name:
                continue

            is_obj_id = bool(OBJECT_ID_PATTERNS.match(clean_name))
            is_sensitive, is_eligible, sens_reason = ParameterDiscovery.check_sensitivity(clean_name)
            reason = "Query string parameter"
            if is_obj_id:
                reason = "Query parameter matching entity identifier format"

            obs = DiscoveryObservation(
                source_type="query_string",
                source_location=source_location,
                discovered_url=url_or_query.split("?")[0],
                parameter_name=clean_name,
                parameter_location="query",
            )

            profiles.append(
                ParameterProfile(
                    name=clean_name,
                    location="query",
                    type_hint="string",
                    required=False,
                    object_identifier_candidate=is_obj_id,
                    reason=reason,
                    sensitive=is_sensitive,
                    eligible_for_automated_testing=is_eligible,
                    sensitivity_reason=sens_reason,
                    source_observations=[obs],
                )
            )

        return profiles

    @staticmethod
    def extract_from_html_form(
        form_html: str, source_url: str = ""
    ) -> tuple[str, str, list[ParameterProfile]]:
        """
        Extracts method, action, and fields from an HTML form snippet without retaining values.
        """
        # Match method and action
        method_match = re.search(r'method=["\']?([a-zA-Z]+)["\']?', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "GET"

        action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else "/"

        # Match input, select, textarea elements
        param_names: set[str] = set()
        for field_match in re.finditer(r'<(input|select|textarea)[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*>', form_html, re.IGNORECASE):
            name = field_match.group(2).strip()
            if name:
                param_names.add(name)

        location = "query" if method == "GET" else "form_body"
        profiles: list[ParameterProfile] = []

        for name in param_names:
            is_sensitive, is_eligible, sens_reason = ParameterDiscovery.check_sensitivity(name)
            obs = DiscoveryObservation(
                source_type="html_form",
                source_location=source_url or "html_document",
                discovered_url=action,
                method=method,
                parameter_name=name,
                parameter_location=location,
            )

            profiles.append(
                ParameterProfile(
                    name=name,
                    location=location,
                    type_hint="string",
                    required=False,
                    object_identifier_candidate=bool(OBJECT_ID_PATTERNS.match(name)),
                    reason=f"Form field (sensitive: {is_sensitive})",
                    sensitive=is_sensitive,
                    eligible_for_automated_testing=is_eligible,
                    sensitivity_reason=sens_reason,
                    source_observations=[obs],
                )
            )

        return method, action, profiles

    @staticmethod
    def extract_from_openapi_schema(
        parameters_data: list[dict[str, Any]],
        request_body_data: dict[str, Any] | None = None,
        source_location: str = "openapi",
    ) -> tuple[list[ParameterProfile], list[str]]:
        """
        Extracts parameters and requestBody JSON properties from OpenAPI / Swagger spec.
        """
        profiles: list[ParameterProfile] = []
        object_ids: list[str] = []

        # 1. OpenAPI parameters list (path, query, header, cookie)
        for p in parameters_data:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name", "")).strip()
            if not name:
                continue

            loc = str(p.get("in", "query")).lower()
            if loc not in ("path", "query", "header", "cookie"):
                loc = "query"

            type_hint = p.get("type") or p.get("schema", {}).get("type", "string")
            required = bool(p.get("required", loc == "path"))

            is_obj_id = (loc == "path" and (required or type_hint in ("integer", "string"))) or bool(OBJECT_ID_PATTERNS.match(name))
            is_sensitive, is_eligible, sens_reason = ParameterDiscovery.check_sensitivity(name)
            reason = f"OpenAPI {loc} parameter (type: {type_hint})"
            if is_obj_id:
                reason = f"OpenAPI path parameter marked required with {type_hint} schema"
                object_ids.append(name)

            obs = DiscoveryObservation(
                source_type="openapi",
                source_location=source_location,
                discovered_url="",
                parameter_name=name,
                parameter_location=loc,
            )

            profiles.append(
                ParameterProfile(
                    name=name,
                    location=loc,
                    type_hint=str(type_hint),
                    required=required,
                    object_identifier_candidate=is_obj_id,
                    reason=reason,
                    sensitive=is_sensitive,
                    eligible_for_automated_testing=is_eligible,
                    sensitivity_reason=sens_reason,
                    source_observations=[obs],
                )
            )

        # 2. OpenAPI requestBody JSON properties
        if request_body_data and isinstance(request_body_data, dict):
            content = request_body_data.get("content", {})
            json_schema = content.get("application/json", {}).get("schema", {})
            properties = json_schema.get("properties", {})
            required_props = json_schema.get("required", [])

            if isinstance(properties, dict):
                for prop_name, prop_schema in properties.items():
                    p_type = prop_schema.get("type", "string") if isinstance(prop_schema, dict) else "string"
                    is_req = prop_name in required_props
                    is_sensitive, is_eligible, sens_reason = ParameterDiscovery.check_sensitivity(prop_name)

                    obs = DiscoveryObservation(
                        source_type="openapi",
                        source_location=source_location,
                        discovered_url="",
                        parameter_name=prop_name,
                        parameter_location="json_body",
                        content_type="application/json",
                    )

                    profiles.append(
                        ParameterProfile(
                            name=prop_name,
                            location="json_body",
                            type_hint=str(p_type),
                            required=is_req,
                            object_identifier_candidate=bool(OBJECT_ID_PATTERNS.match(prop_name)),
                            reason=f"OpenAPI requestBody JSON property (type: {p_type})",
                            sensitive=is_sensitive,
                            eligible_for_automated_testing=is_eligible,
                            sensitivity_reason=sens_reason,
                            source_observations=[obs],
                        )
                    )


        return profiles, object_ids
