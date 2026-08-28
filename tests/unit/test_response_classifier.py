"""
tests/unit/test_response_classifier.py
──────────────────────────────────────
Unit tests for ResponseClassifier and SPA Fallback Detection:
  - HTTP 200 HTML fallback is not treated as file disclosure (/.env returning HTML -> SPA_FALLBACK).
  - HTTP 200 HTML fallback is not treated as OpenAPI exposure (/openapi.json returning HTML -> SPA_FALLBACK).
  - HTTP 200 HTML fallback is not treated as API success (/etc/passwd returning HTML -> SPA_FALLBACK).
  - Real JSON response is classified as JSON_API.
  - Real directory listing is classified as DIRECTORY_LISTING.
  - Error pages are classified separately as ERROR_DOCUMENT.
  - Root and unknown route fingerprints are matched deterministically.
"""
import pytest

from app.discovery.response_classifier import (
    ResponseClassifier,
    ResponseKind,
    SpaFingerprint,
)


JUICE_SHOP_SPA_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>OWASP Juice Shop</title>
  <base href="/">
  <link rel="icon" type="image/x-icon" href="assets/public/favicon_js.ico">
</head>
<body class="mat-typography mat-app-background light-theme">
  <app-root></app-root>
  <script src="runtime.js" defer></script>
  <script src="polyfills.js" defer></script>
  <script src="vendor.js" defer></script>
  <script src="main.js" defer></script>
</body>
</html>"""


class TestResponseClassifier:

    def test_root_page_computes_deterministic_fingerprint(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html"}, JUICE_SHOP_SPA_HTML
        )
        assert fp.status_code == 200
        assert fp.title == "OWASP Juice Shop"
        assert len(fp.app_markers) >= 2
        assert "main.js" in " ".join(fp.script_srcs)
        assert len(fp.content_hash) == 64

    def test_env_route_returning_spa_fallback_is_not_file_disclosure(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html"}, JUICE_SHOP_SPA_HTML
        )
        classifier = ResponseClassifier(root_fingerprint=fp)

        # Target requests /.env and server returns 200 with SPA HTML
        classification = classifier.classify_response(
            url_or_path="/.env",
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body_text=JUICE_SHOP_SPA_HTML,
        )

        assert classification.response_kind == ResponseKind.SPA_FALLBACK
        assert not classification.is_real_resource
        assert not classification.testable_as_api
        assert classification.spa_similarity >= 0.90

    def test_openapi_json_returning_spa_fallback_is_not_openapi_exposure(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html"}, JUICE_SHOP_SPA_HTML
        )
        classifier = ResponseClassifier(root_fingerprint=fp)

        classification = classifier.classify_response(
            url_or_path="/openapi.json",
            status_code=200,
            headers={"content-type": "text/html"},
            body_text=JUICE_SHOP_SPA_HTML,
        )

        assert classification.response_kind == ResponseKind.SPA_FALLBACK
        assert not classification.is_real_resource
        assert not classification.testable_as_api

    def test_etc_passwd_returning_spa_fallback_is_not_api_success(self):
        fp = ResponseClassifier.compute_spa_fingerprint(
            200, {"content-type": "text/html"}, JUICE_SHOP_SPA_HTML
        )
        classifier = ResponseClassifier(root_fingerprint=fp)

        classification = classifier.classify_response(
            url_or_path="/etc/passwd",
            status_code=200,
            headers={"content-type": "text/html"},
            body_text=JUICE_SHOP_SPA_HTML,
        )

        assert classification.response_kind == ResponseKind.SPA_FALLBACK
        assert not classification.is_real_resource
        assert not classification.testable_as_api

    def test_real_json_api_response_is_classified_as_json_api(self):
        classifier = ResponseClassifier()
        json_body = '{"status": "success", "data": [{"id": 1, "name": "Apple Juice"}]}'

        classification = classifier.classify_response(
            url_or_path="/api/Products",
            status_code=200,
            headers={"content-type": "application/json; charset=utf-8"},
            body_text=json_body,
        )

        assert classification.response_kind == ResponseKind.JSON_API
        assert classification.is_real_resource
        assert classification.testable_as_api

    def test_real_directory_listing_is_classified_correctly(self):
        classifier = ResponseClassifier()
        dir_html = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /ftp</title>
 </head>
 <body>
<h1>Index of /ftp</h1>
<pre><a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a><hr><a href="/">Parent Directory</a>                             -   
<a href="acquisitions.md">acquisitions.md</a>         2026-08-28 10:00  1.2K  
<a href="eastere.gg">eastere.gg</a>              2026-08-28 10:00  450   
</pre>
</body></html>"""

        classification = classifier.classify_response(
            url_or_path="/ftp",
            status_code=200,
            headers={"content-type": "text/html"},
            body_text=dir_html,
        )

        assert classification.response_kind == ResponseKind.DIRECTORY_LISTING
        assert classification.is_real_resource
        assert not classification.testable_as_api

    def test_error_document_classification(self):
        classifier = ResponseClassifier()
        err_html = "<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1></body></html>"

        classification = classifier.classify_response(
            url_or_path="/api/v1/user/profile",
            status_code=500,
            headers={"content-type": "text/html"},
            body_text=err_html,
        )

        assert classification.response_kind == ResponseKind.ERROR_DOCUMENT
        assert not classification.is_real_resource
        assert not classification.testable_as_api
