"""
app/discovery/__init__.py
─────────────────────────
Discovery subsystem: Parameter classification, API mapping, protocol detection, and safe crawling.
"""
from __future__ import annotations

from app.discovery.api_mapper import APIMapper
from app.discovery.crawler import SafeCrawler
from app.discovery.models import DiscoveryObservation, ParameterProfile
from app.discovery.parameter_discovery import ParameterDiscovery

__all__ = [
    "APIMapper",
    "SafeCrawler",
    "DiscoveryObservation",
    "ParameterProfile",
    "ParameterDiscovery",
]
