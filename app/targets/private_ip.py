"""
app/targets/private_ip.py
──────────────────────────
Private IP / SSRF protection.

Blocks all attempts to contact:
  - Loopback addresses (127.0.0.0/8, ::1)
  - Private RFC 1918 addresses (10.x, 172.16–31.x, 192.168.x)
  - Link-local addresses (169.254.x.x — includes AWS/GCP metadata servers)
  - IPv6 ULA (fc00::/7)
  - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
  - Multicast (224.0.0.0/4, ff00::/8)
  - "localhost" and common internal hostnames

This check is called:
  1. By AuthorizationService at investigation start.
  2. By ScopeEnforcingHttpClient before EVERY HTTP request made by agents.

DNS Rebinding Protection:
  The hostname is resolved at both check time and request time.
  If the resolved IP changes between checks (rebinding attack), the request
  is blocked.
"""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache

from app.core.exceptions import PrivateIPAccessError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Hostnames that always resolve to private/internal addresses
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    # Add more internal DNS names as needed
})

# CIDR ranges that are always private/internal
_PRIVATE_NETWORKS_V4 = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local (metadata servers)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
]

_PRIVATE_NETWORKS_V6 = [
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("fc00::/7"),          # Unique Local Addresses
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
    ipaddress.ip_network("::/128"),            # Unspecified
]


def is_private_ip(ip_str: str) -> bool:
    """
    Returns True if the given IP address string is private, loopback,
    link-local, or otherwise internal.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        # Cannot parse as IP address — not an IP, hostname check elsewhere
        return False

    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in _PRIVATE_NETWORKS_V4)
    else:
        return any(addr in net for net in _PRIVATE_NETWORKS_V6)


def resolve_host(hostname: str) -> list[str]:
    """
    Resolve a hostname to all its IP addresses.
    Returns a list of IP strings.

    Raises PrivateIPAccessError if resolution fails completely
    (treat failed resolution as a blocked host for safety).
    """
    try:
        # getaddrinfo returns (family, type, proto, canonname, sockaddr)
        results = socket.getaddrinfo(hostname, None)
        ips = list({result[4][0] for result in results})
        return ips
    except socket.gaierror as exc:
        logger.warning(
            "hostname_resolution_failed",
            hostname=hostname,
            error=str(exc),
        )
        raise PrivateIPAccessError(hostname) from exc


def validate_host_not_private(host: str) -> None:
    """
    Check that a hostname/IP is not private or internal.
    Raises PrivateIPAccessError if it is.

    Checks:
      1. Blocked hostname list (localhost, metadata.google.internal, etc.)
      2. Direct IP address check (if host looks like an IP)
      3. DNS resolution + IP check for all resolved addresses
    """
    from app.core.config import get_settings
    try:
        settings = get_settings()
        if settings.is_development and settings.allow_local_lab_targets:
            if host.lower() in {"localhost", "127.0.0.1", "vuln_lab"}:
                logger.debug("local_lab_target_permitted_in_dev", host=host)
                return
    except Exception:
        pass

    # 1. Blocked hostname list
    if host.lower() in _BLOCKED_HOSTNAMES:
        logger.warning("private_ip_blocked_hostname", host=host)
        raise PrivateIPAccessError(host)

    # 2. If host is already an IP address, check directly
    try:
        addr = ipaddress.ip_address(host)
        if is_private_ip(str(addr)):
            logger.warning("private_ip_blocked_direct", ip=host)
            raise PrivateIPAccessError(host, resolved_ip=host)
        # It's a public IP — allow
        return
    except ValueError:
        pass  # Not an IP, continue to DNS resolution

    # 3. Resolve hostname and check all resolved IPs
    resolved_ips = resolve_host(host)
    for ip in resolved_ips:
        if is_private_ip(ip):
            logger.warning(
                "private_ip_blocked_via_dns",
                host=host,
                resolved_ip=ip,
            )
            raise PrivateIPAccessError(host, resolved_ip=ip)

    logger.debug(
        "host_validated_public",
        host=host,
        resolved_ips=resolved_ips,
    )


def validate_no_dns_rebinding(host: str, previously_resolved_ips: list[str]) -> None:
    """
    DNS Rebinding protection: re-resolve the hostname and compare to the
    previously resolved IPs. If any new resolution returns a private IP
    that wasn't in the original set, block the request.

    Call this at every HTTP request time, not just at investigation start.
    """
    current_ips = resolve_host(host)

    for ip in current_ips:
        if is_private_ip(ip) and ip not in previously_resolved_ips:
            logger.warning(
                "dns_rebinding_detected",
                host=host,
                original_ips=previously_resolved_ips,
                current_ips=current_ips,
                suspicious_ip=ip,
            )
            raise PrivateIPAccessError(
                host,
                resolved_ip=ip,
            )
