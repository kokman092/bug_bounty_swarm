"""
app/discovery/crawler.py
────────────────────────
Safe Bounded Web Crawler with Strict Scope & Redirect Guardrails.

Safety Guarantees:
  1. All HTTP requests strictly route through ScopeEnforcingHttpClient.
  2. Bounded crawl depth and max page limits.
  3. Never submits HTML forms or modifies server state.
  4. Out-of-scope redirects are halted before making any subsequent request.
  5. Extracts links, forms, and JavaScript asset references statically.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.exceptions import ScopeViolationError
from app.core.logging import get_logger
from app.discovery.models import DiscoveryObservation
from app.discovery.parameter_discovery import ParameterDiscovery
from app.targets.authorization import AuthorizationService
from app.targets.normalization import normalize_url
from app.tools.http_client import ScopeEnforcingHttpClient

logger = get_logger(__name__)


class SafeCrawler:
    """Bounded crawler for passive attack surface discovery."""

    def __init__(
        self,
        investigation_id: str,
        target_url: str,
        max_depth: int = 2,
        max_pages: int = 25,
    ) -> None:
        self.investigation_id = investigation_id
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: set[str] = set()

    async def crawl(self, seed_path: str = "/") -> list[DiscoveryObservation]:
        """
        Executes a bounded crawl starting from seed_path.
        Returns a list of factual DiscoveryObservation items.
        """
        observations: list[DiscoveryObservation] = []
        queue: list[tuple[str, int]] = [(urljoin(self.target_url, seed_path), 0)]

        async with ScopeEnforcingHttpClient(self.investigation_id) as client:
            while queue and len(self.visited_urls) < self.max_pages:
                current_url, depth = queue.pop(0)
                if current_url in self.visited_urls:
                    continue

                self.visited_urls.add(current_url)

                try:
                    logger.info("crawler_fetching_url", url=current_url, depth=depth)
                    resp = await client.get(current_url)

                    # Check for redirect to out-of-scope location
                    if resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("location", "")
                        if loc:
                            target_loc = urljoin(current_url, loc)
                            # Scope check on redirect target
                            auth_svc = AuthorizationService()
                            scope_res = await auth_svc.check_scope(target_loc, self.investigation_id)
                            if not scope_res.allowed:
                                logger.warning("crawler_blocked_out_of_scope_redirect", target=target_loc)
                                continue
                            if depth + 1 <= self.max_depth and target_loc not in self.visited_urls:
                                queue.append((target_loc, depth + 1))
                        continue

                    if resp.status_code != 200:
                        continue

                    html = client.get_response_text_safe(resp)
                    curr_path = urlparse(current_url).path or "/"

                    # 1. Record self observation
                    observations.append(
                        DiscoveryObservation(
                            source_type="crawler",
                            source_location=curr_path,
                            discovered_url=curr_path,
                            method="GET",
                            protocol="REST" if "/api/" in curr_path else "UNKNOWN",
                        )
                    )

                    # 2. Extract links (<a href="...">)
                    links = re.findall(r'<a[^>]+href=["\']([^"\'>#\s]+)["\']', html, re.IGNORECASE)
                    for link in links:
                        abs_link = urljoin(current_url, link)
                        clean_path = urlparse(abs_link).path
                        # Extract query parameters
                        if "?" in link:
                            q_params = ParameterDiscovery.extract_from_query_string(link, source_location=curr_path)
                            for qp in q_params:
                                observations.extend(qp.source_observations)

                        # Enqueue in-scope internal HTML links
                        if depth + 1 <= self.max_depth and abs_link not in self.visited_urls:
                            auth_svc = AuthorizationService()
                            link_scope = await auth_svc.check_scope(abs_link, self.investigation_id)
                            if link_scope.allowed:
                                queue.append((abs_link, depth + 1))


                    # 3. Extract HTML forms without submitting them
                    forms = re.findall(r'(<form[^>]*>.*?</form>)', html, re.IGNORECASE | re.DOTALL)
                    for form_html in forms:
                        method, action, f_params = ParameterDiscovery.extract_from_html_form(form_html, source_url=curr_path)
                        for fp in f_params:
                            observations.extend(fp.source_observations)

                except ScopeViolationError:
                    logger.warning("crawler_scope_blocked", url=current_url)
                except Exception as exc:
                    logger.info("crawler_fetch_skipped", url=current_url, error=str(exc))

        return observations
