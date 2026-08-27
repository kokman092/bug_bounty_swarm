"""
app/tools/burp/history_parser.py
────────────────────────────────
Burp Suite XML & HAR History Ingestion Parser.

Parses recorded HTTP traffic exported from Burp Suite:
  - Burp XML exports (<items><item>...<request base64="true">...<response base64="true">...)
  - Standard HAR JSON exports (.har 1.2)

Extracts:
  - Endpoints, paths, HTTP methods
  - Query parameters & request body JSON structures
  - Authentication tokens & session cookies observed in traffic
  - Unique dynamic object IDs (e.g. order IDs, organization IDs, user IDs)
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET

from app.core.logging import get_logger

logger = get_logger(__name__)


def parse_burp_xml_history(xml_content: str) -> dict[str, Any]:
    """
    Parses a Burp Suite XML export string (<items><item>...</item></items>).
    Decodes base64 requests and responses into structured endpoint metadata.
    """
    endpoints: list[dict[str, Any]] = []
    observed_cookies: dict[str, set[str]] = {}
    observed_auth_headers: set[str] = set()

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        logger.error("burp_xml_parse_error", error=str(exc))
        return {
            "status": "error",
            "error": f"Invalid XML format: {exc}",
            "endpoints": [],
        }

    for item in root.findall(".//item"):
        url_elem = item.find("url")
        raw_url = url_elem.text.strip() if url_elem is not None and url_elem.text else ""
        if not raw_url:
            continue

        parsed_url = urlparse(raw_url)
        path = parsed_url.path or "/"

        method_elem = item.find("method")
        method = method_elem.text.strip().upper() if method_elem is not None and method_elem.text else "GET"

        status_elem = item.find("status")
        status_code = int(status_elem.text.strip()) if status_elem is not None and status_elem.text else 200

        # Decode base64 request if present
        req_elem = item.find("request")
        headers_dict: dict[str, str] = {}
        json_body: Any = None
        raw_body_text = ""

        if req_elem is not None and req_elem.text:
            is_b64 = req_elem.attrib.get("base64", "false").lower() == "true"
            try:
                raw_req_bytes = base64.b64decode(req_elem.text) if is_b64 else req_elem.text.encode("utf-8")
                raw_req = raw_req_bytes.decode("utf-8", errors="replace")

                parts = raw_req.split("\r\n\r\n", 1)
                if len(parts) < 2:
                    parts = raw_req.split("\n\n", 1)

                header_lines = parts[0].splitlines()
                for line in header_lines[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers_dict[k.strip().lower()] = v.strip()

                if len(parts) > 1:
                    raw_body_text = parts[1]
                    try:
                        json_body = json.loads(raw_body_text)
                    except ValueError:
                        pass
            except Exception as exc:
                logger.debug("req_decode_skip", error=str(exc))

        # Extract Cookies and Auth Headers
        cookie_hdr = headers_dict.get("cookie")
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                if "=" in pair:
                    c_name, c_val = pair.strip().split("=", 1)
                    observed_cookies.setdefault(c_name, set()).add(c_val)

        auth_hdr = headers_dict.get("authorization")
        if auth_hdr:
            observed_auth_headers.add(auth_hdr)

        # Extract Query Parameters
        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}

        endpoints.append({
            "url": raw_url,
            "path": path,
            "method": method,
            "status_code": status_code,
            "query_params": query_params,
            "headers": headers_dict,
            "json_body": json_body,
            "has_auth": bool(auth_hdr or cookie_hdr),
        })

    return {
        "status": "success",
        "format": "burp_xml",
        "total_requests": len(endpoints),
        "endpoints": endpoints,
        "observed_auth_headers": list(observed_auth_headers),
        "observed_cookies": {k: list(v) for k, v in observed_cookies.items()},
    }


def parse_har_history(har_data: dict[str, Any] | str) -> dict[str, Any]:
    """
    Parses standard HTTP Archive (HAR 1.2) data exported from Burp Suite, DevTools, or Postman.
    """
    if isinstance(har_data, str):
        try:
            har_dict = json.loads(har_data)
        except json.JSONDecodeError as exc:
            return {"status": "error", "error": f"Invalid JSON HAR: {exc}", "endpoints": []}
    else:
        har_dict = har_data

    entries = har_dict.get("log", {}).get("entries", [])
    endpoints: list[dict[str, Any]] = []
    observed_cookies: dict[str, set[str]] = {}
    observed_auth_headers: set[str] = set()

    for entry in entries:
        req = entry.get("request", {})
        raw_url = req.get("url", "")
        if not raw_url:
            continue

        parsed_url = urlparse(raw_url)
        path = parsed_url.path or "/"
        method = req.get("method", "GET").upper()

        resp = entry.get("response", {})
        status_code = resp.get("status", 200)

        # Parse request headers
        headers_dict = {}
        for h in req.get("headers", []):
            name = h.get("name", "").lower()
            val = h.get("value", "")
            if name:
                headers_dict[name] = val

        cookie_hdr = headers_dict.get("cookie")
        if cookie_hdr:
            for pair in cookie_hdr.split(";"):
                if "=" in pair:
                    c_name, c_val = pair.strip().split("=", 1)
                    observed_cookies.setdefault(c_name, set()).add(c_val)

        auth_hdr = headers_dict.get("authorization")
        if auth_hdr:
            observed_auth_headers.add(auth_hdr)

        # Parse post data body if present
        json_body = None
        post_data = req.get("postData", {})
        if post_data and post_data.get("text"):
            try:
                json_body = json.loads(post_data.get("text", ""))
            except ValueError:
                pass

        query_params = {}
        for q in req.get("queryString", []):
            query_params[q.get("name")] = q.get("value")

        endpoints.append({
            "url": raw_url,
            "path": path,
            "method": method,
            "status_code": status_code,
            "query_params": query_params,
            "headers": headers_dict,
            "json_body": json_body,
            "has_auth": bool(auth_hdr or cookie_hdr),
        })

    return {
        "status": "success",
        "format": "har_json",
        "total_requests": len(endpoints),
        "endpoints": endpoints,
        "observed_auth_headers": list(observed_auth_headers),
        "observed_cookies": {k: list(v) for k, v in observed_cookies.items()},
    }
