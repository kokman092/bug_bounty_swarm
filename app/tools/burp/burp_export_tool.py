"""
app/tools/burp/burp_export_tool.py
──────────────────────────────────
Burp XML & Standard HAR Session Exporter.

Exports agent investigation findings, PoC requests, and responses into
Burp Suite XML item format and standard HAR (HTTP Archive) format for
1-click import into Burp Suite Repeater / Intruder.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any
import xml.etree.ElementTree as ET


def export_findings_to_burp_xml(
    investigation_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
) -> str:
    """
    Generates a Burp Suite XML representation (<items>) of verified findings and PoCs.
    Can be loaded directly into Burp Suite via Target -> Import.
    """
    root = ET.Element("items", burpVersion="2024.1", exportTime=datetime.utcnow().isoformat())

    for finding in findings:
        item = ET.SubElement(root, "item")
        ET.SubElement(item, "time").text = datetime.utcnow().strftime("%a %b %d %H:%M:%S %Z %Y")
        ET.SubElement(item, "url").text = str(finding.get("endpoint") or target_url)
        ET.SubElement(item, "host").text = target_url.split("://")[-1].split("/")[0]
        ET.SubElement(item, "port").text = "443" if "https" in target_url else "80"
        ET.SubElement(item, "protocol").text = "https" if "https" in target_url else "http"
        ET.SubElement(item, "method").text = "GET"
        ET.SubElement(item, "status").text = "200"
        ET.SubElement(item, "comment").text = f"[{finding.get('severity', 'High')}] {finding.get('title', 'Vulnerability Finding')}"

        # Encode sample PoC request/response
        raw_evidence = finding.get("raw_evidence_inline", {})
        steps = raw_evidence.get("steps_executed", [])
        raw_req_str = f"GET {finding.get('endpoint', '/')} HTTP/1.1\r\nHost: {target_url}\r\n\r\n"
        raw_resp_str = f"HTTP/1.1 200 OK\r\n\r\n{json.dumps(finding.get('evidence_summary', ''))}"

        req_elem = ET.SubElement(item, "request", base64="true")
        req_elem.text = base64.b64encode(raw_req_str.encode("utf-8")).decode("utf-8")

        resp_elem = ET.SubElement(item, "response", base64="true")
        resp_elem.text = base64.b64encode(raw_resp_str.encode("utf-8")).decode("utf-8")

    return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")


def export_findings_to_har(
    investigation_id: str,
    target_url: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Generates standard HTTP Archive (HAR 1.2) format representation of findings
    for 1-click import into Burp Suite, Postman, or browser devtools.
    """
    entries = []
    for f in findings:
        entries.append({
            "startedDateTime": datetime.utcnow().isoformat() + "Z",
            "time": 50,
            "request": {
                "method": "GET",
                "url": f"{target_url.rstrip('/')}{f.get('endpoint', '/')}",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "queryString": [],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": 200,
                "statusText": "OK",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {
                    "size": len(str(f.get("evidence_summary", ""))),
                    "mimeType": "application/json",
                    "text": str(f.get("evidence_summary", "")),
                },
                "headersSize": -1,
                "bodySize": len(str(f.get("evidence_summary", ""))),
            },
            "comment": f"[{f.get('severity', 'High')}] {f.get('title', 'Vulnerability Finding')}",
        })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "BugBounty-Swarm", "version": "1.0"},
            "entries": entries,
        }
    }
