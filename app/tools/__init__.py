"""
app/tools/__init__.py
────────────────────
Centralized export of all deterministic tools for the BugBounty Swarm agents:
  - Burp Suite Integration Suite (Proxy, API, Collaborator, HAR/XML Exporters)
  - Open-Source CLI Suite (Subfinder, Katana, Httpx, Nuclei)
  - Native Security Tools (Auth Matrix, Parameter Normalizer, OpenAPI Parser, Recon Scrapers)
"""
from app.tools.auth_matrix import probe_auth_matrix
from app.tools.burp import (
    CollaboratorSession,
    check_burp_proxy_status,
    export_findings_to_burp_xml,
    export_findings_to_har,
    fetch_burp_sitemap,
    get_collaborator_session,
    trigger_burp_scan,
)
from app.tools.evidence_tools import compute_response_diff
from app.tools.external import (
    filter_discovered_targets,
    run_httpx_probe,
    run_katana,
    run_nuclei_scan,
    run_subfinder,
)
from app.tools.http_client import ScopeEnforcingHttpClient
from app.tools.http_tools import execute_authorized_probe, run_evidence_validation
from app.tools.openapi_tools import fetch_and_parse_openapi_specs
from app.tools.param_normalizer import normalize_test_path
from app.tools.recon_tools import (
    fetch_robots_txt,
    fetch_sitemap,
    probe_common_api_paths,
    scrape_links_and_forms,
)

__all__ = [
    "ScopeEnforcingHttpClient",
    "fetch_robots_txt",
    "fetch_sitemap",
    "scrape_links_and_forms",
    "probe_common_api_paths",
    "fetch_and_parse_openapi_specs",
    "normalize_test_path",
    "probe_auth_matrix",
    "compute_response_diff",
    "execute_authorized_probe",
    "run_evidence_validation",
    "run_subfinder",
    "run_katana",
    "run_httpx_probe",
    "run_nuclei_scan",
    "filter_discovered_targets",
    "check_burp_proxy_status",
    "fetch_burp_sitemap",
    "trigger_burp_scan",
    "export_findings_to_burp_xml",
    "export_findings_to_har",
    "CollaboratorSession",
    "get_collaborator_session",
]
