"""
tests/unit/test_authorization.py
──────────────────────────────────
Unit tests for URL normalization and scope matching.

These tests are CRITICAL — they validate the security boundary.
No network calls, no Firestore — pure Python logic.

Priority: P0 — must pass before any HTTP tool can make requests.
"""
from __future__ import annotations

import pytest

from app.core.exceptions import TargetNotAuthorizedError, URLNormalizationError
from app.targets.normalization import are_same_origin, normalize_url
from app.targets.schemas import AuthorizedTarget, NormalizedURL, ScopeType


# ─────────────────────────────────────────────────────────────────────────────
# URL Normalization Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestURLNormalization:

    def test_basic_https_url(self):
        result = normalize_url("https://example.com/api")
        assert result.scheme == "https"
        assert result.host == "example.com"
        assert result.port == 443
        assert result.path == "/api"

    def test_trailing_slash_normalization(self):
        """http://foo.com/ and http://foo.com should be equivalent."""
        a = normalize_url("http://foo.com/")
        b = normalize_url("http://foo.com")
        assert a.host == b.host
        assert a.port == b.port
        assert a.scheme == b.scheme

    def test_default_http_port_explicit(self):
        """http://foo.com:80 should produce port=80."""
        result = normalize_url("http://foo.com:80/path")
        assert result.port == 80
        assert result.scheme == "http"
        assert result.host == "foo.com"

    def test_default_https_port_explicit(self):
        """https://foo.com:443 should produce port=443."""
        result = normalize_url("https://foo.com:443/path")
        assert result.port == 443

    def test_case_insensitive_hostname(self):
        """HTTP hostnames are case-insensitive — must be lowercased."""
        result = normalize_url("https://FOO.COM/api")
        assert result.host == "foo.com"

    def test_mixed_case_hostname(self):
        result = normalize_url("http://MyApp.Example.COM/path")
        assert result.host == "myapp.example.com"

    def test_non_default_port_preserved(self):
        result = normalize_url("http://foo.com:8080/api")
        assert result.port == 8080

    def test_path_traversal_resolved(self):
        """Path traversal (..) must be resolved."""
        result = normalize_url("http://foo.com/api/../admin")
        assert result.path == "/admin"

    def test_consecutive_slashes_collapsed(self):
        """Consecutive slashes in path are collapsed."""
        result = normalize_url("http://foo.com/api//v1///users")
        assert "//" not in result.path

    def test_scheme_added_if_missing(self):
        """Bare hostname gets https:// prepended."""
        result = normalize_url("example.com/path")
        assert result.scheme == "https"
        assert result.host == "example.com"

    def test_rejects_file_scheme(self):
        with pytest.raises(URLNormalizationError) as exc:
            normalize_url("file:///etc/passwd")
        assert "file" in str(exc.value).lower() or "scheme" in str(exc.value).lower()

    def test_rejects_ftp_scheme(self):
        with pytest.raises(URLNormalizationError):
            normalize_url("ftp://files.example.com/")

    def test_rejects_javascript_scheme(self):
        with pytest.raises(URLNormalizationError):
            normalize_url("javascript:alert(1)")

    def test_rejects_data_scheme(self):
        with pytest.raises(URLNormalizationError):
            normalize_url("data:text/html,<script>alert(1)</script>")

    def test_rejects_empty_url(self):
        with pytest.raises(URLNormalizationError):
            normalize_url("")

    def test_rejects_none_url(self):
        with pytest.raises((URLNormalizationError, TypeError)):
            normalize_url(None)  # type: ignore

    def test_canonical_form_structure(self):
        """Canonical URL should follow scheme://host:port/path format."""
        result = normalize_url("https://api.example.com/v1/users")
        assert result.canonical == "https://api.example.com:443/v1/users"

    def test_canonical_http_with_port(self):
        result = normalize_url("http://api.example.com:8080/v1")
        assert result.canonical == "http://api.example.com:8080/v1"

    def test_query_string_in_path(self):
        """Query string should not appear in normalized path."""
        result = normalize_url("http://foo.com/api?token=secret")
        # The path should not contain the query string
        assert "token" not in result.path
        assert "secret" not in result.path

    def test_ip_address_host(self):
        """IPv4 addresses are valid hosts (private IP check is separate)."""
        result = normalize_url("http://8.8.8.8/dns")
        assert result.host == "8.8.8.8"


class TestSameOrigin:

    def test_same_scheme_host_port(self):
        assert are_same_origin("https://foo.com", "https://foo.com/api") is True

    def test_different_scheme(self):
        assert are_same_origin("http://foo.com", "https://foo.com") is False

    def test_different_host(self):
        assert are_same_origin("https://foo.com", "https://bar.com") is False

    def test_different_port(self):
        assert are_same_origin("https://foo.com:443", "https://foo.com:8443") is False

    def test_case_insensitive(self):
        assert are_same_origin("https://FOO.COM", "https://foo.com") is True


# ─────────────────────────────────────────────────────────────────────────────
# Scope Matching Tests (AuthorizationService._matches)
# ─────────────────────────────────────────────────────────────────────────────

# Import the real service to test _matches without Firestore
from app.targets.authorization import AuthorizationService


def _make_target(
    scope_type: ScopeType,
    scope_value: str,
    url_normalized: str | None = None,
    allowed_schemes: list[str] | None = None,
) -> AuthorizedTarget:
    return AuthorizedTarget(
        target_id="test-target-1",
        url_normalized=url_normalized or scope_value,
        url_raw=scope_value,
        scope_type=scope_type,
        scope_value=scope_value,
        allowed_schemes=allowed_schemes or ["http", "https"],
        added_by="test",
    )


class TestScopeMatching:

    def setup_method(self):
        self.auth_service = AuthorizationService()

    def _check(self, url: str, target: AuthorizedTarget) -> bool:
        normalized = normalize_url(url)
        return self.auth_service._matches(normalized, target)

    # ── EXACT scope ───────────────────────────────────────────────────────────

    def test_exact_match_same_url(self):
        target = _make_target(ScopeType.EXACT, "http://vuln-lab.com:80/")
        assert self._check("http://vuln-lab.com/", target) is True

    def test_exact_match_subpath_allowed(self):
        """EXACT scope should allow subpaths of the target."""
        target = _make_target(ScopeType.EXACT, "http://vuln-lab.com:80/")
        assert self._check("http://vuln-lab.com/api/users/1", target) is True

    def test_exact_match_wrong_host(self):
        target = _make_target(ScopeType.EXACT, "http://vuln-lab.com:80/")
        assert self._check("http://attacker.com/", target) is False

    def test_exact_match_wrong_scheme(self):
        target = _make_target(
            ScopeType.EXACT, "https://vuln-lab.com:443/", allowed_schemes=["https"]
        )
        assert self._check("http://vuln-lab.com/", target) is False

    def test_exact_match_wrong_port(self):
        target = _make_target(ScopeType.EXACT, "http://vuln-lab.com:5000/")
        assert self._check("http://vuln-lab.com:8080/", target) is False

    # ── SUBDOMAIN_WILDCARD scope ──────────────────────────────────────────────

    def test_wildcard_matches_subdomain(self):
        target = _make_target(ScopeType.SUBDOMAIN_WILDCARD, "example.com")
        assert self._check("https://api.example.com/", target) is True

    def test_wildcard_matches_root_domain(self):
        target = _make_target(ScopeType.SUBDOMAIN_WILDCARD, "example.com")
        assert self._check("https://example.com/", target) is True

    def test_wildcard_does_not_match_sibling(self):
        target = _make_target(ScopeType.SUBDOMAIN_WILDCARD, "example.com")
        assert self._check("https://notexample.com/", target) is False

    def test_wildcard_does_not_match_parent_traversal(self):
        """*.example.com must NOT match malicious.example.com.attacker.com"""
        target = _make_target(ScopeType.SUBDOMAIN_WILDCARD, "example.com")
        assert self._check("https://malicious.example.com.attacker.com/", target) is False

    def test_wildcard_nested_subdomain(self):
        target = _make_target(ScopeType.SUBDOMAIN_WILDCARD, "example.com")
        assert self._check("https://a.b.example.com/", target) is True

    # ── PATH_PREFIX scope ─────────────────────────────────────────────────────

    def test_path_prefix_matches_subpath(self):
        target = _make_target(
            ScopeType.PATH_PREFIX, "/api/",
            url_normalized="http://vuln-lab.com:80/"
        )
        assert self._check("http://vuln-lab.com/api/users/1", target) is True

    def test_path_prefix_does_not_match_different_prefix(self):
        target = _make_target(
            ScopeType.PATH_PREFIX, "/api/",
            url_normalized="http://vuln-lab.com:80/"
        )
        assert self._check("http://vuln-lab.com/admin/", target) is False

    # ── Scheme restriction ────────────────────────────────────────────────────

    def test_https_only_scope_rejects_http(self):
        target = _make_target(
            ScopeType.EXACT, "https://secure.com:443/",
            allowed_schemes=["https"]
        )
        assert self._check("http://secure.com/", target) is False

    def test_both_schemes_allowed(self):
        target = _make_target(
            ScopeType.EXACT, "http://lab.com:80/",
            allowed_schemes=["http", "https"]
        )
        assert self._check("http://lab.com/", target) is True
        assert self._check("https://lab.com/", target) is True
