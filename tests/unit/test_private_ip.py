"""
tests/unit/test_private_ip.py
───────────────────────────────
Unit tests for SSRF / private IP protection.

These tests verify that the private IP detection is comprehensive.
No network calls made — all using pre-known IP addresses.

Priority: P0 — must pass before any HTTP tool can make requests.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch

from app.core.exceptions import PrivateIPAccessError
from app.targets.private_ip import (
    is_private_ip,
    validate_host_not_private,
    validate_no_dns_rebinding,
)


# ─────────────────────────────────────────────────────────────────────────────
# is_private_ip — low-level IP classification
# ─────────────────────────────────────────────────────────────────────────────

class TestIsPrivateIP:

    # ── IPv4 Private ──────────────────────────────────────────────────────────

    def test_loopback_127_0_0_1(self):
        assert is_private_ip("127.0.0.1") is True

    def test_loopback_127_x_x_x(self):
        assert is_private_ip("127.255.255.255") is True

    def test_rfc1918_10_range(self):
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("10.255.255.255") is True

    def test_rfc1918_172_16_to_31(self):
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("172.31.255.255") is True

    def test_not_172_private_outside_range(self):
        # 172.15.x and 172.32.x are public
        assert is_private_ip("172.15.0.1") is False
        assert is_private_ip("172.32.0.1") is False

    def test_rfc1918_192_168(self):
        assert is_private_ip("192.168.0.1") is True
        assert is_private_ip("192.168.255.255") is True

    def test_link_local_169_254(self):
        """Link-local includes AWS/GCP metadata servers (169.254.169.254)."""
        assert is_private_ip("169.254.0.1") is True
        assert is_private_ip("169.254.169.254") is True  # Cloud metadata!

    def test_shared_address_space_100_64(self):
        assert is_private_ip("100.64.0.1") is True
        assert is_private_ip("100.127.255.255") is True

    def test_multicast(self):
        assert is_private_ip("224.0.0.1") is True
        assert is_private_ip("239.255.255.255") is True

    def test_broadcast(self):
        assert is_private_ip("255.255.255.255") is True

    # ── IPv4 Public ───────────────────────────────────────────────────────────

    def test_public_ip_8_8_8_8(self):
        assert is_private_ip("8.8.8.8") is False

    def test_public_ip_1_1_1_1(self):
        assert is_private_ip("1.1.1.1") is False

    def test_public_ip_github(self):
        assert is_private_ip("140.82.121.4") is False

    # ── IPv6 Private ──────────────────────────────────────────────────────────

    def test_ipv6_loopback(self):
        assert is_private_ip("::1") is True

    def test_ipv6_ula_fc00(self):
        assert is_private_ip("fc00::1") is True

    def test_ipv6_ula_fd00(self):
        assert is_private_ip("fd12:3456:789a:1::1") is True

    def test_ipv6_link_local_fe80(self):
        assert is_private_ip("fe80::1") is True

    def test_ipv6_multicast(self):
        assert is_private_ip("ff02::1") is True

    # ── IPv6 Public ───────────────────────────────────────────────────────────

    def test_ipv6_public_google(self):
        assert is_private_ip("2001:4860:4860::8888") is False

    def test_ipv6_public_cloudflare(self):
        assert is_private_ip("2606:4700:4700::1111") is False

    # ── Edge Cases ────────────────────────────────────────────────────────────

    def test_not_an_ip_returns_false(self):
        """is_private_ip only works on IPs; hostnames return False (resolved separately)."""
        assert is_private_ip("localhost") is False  # hostname, not IP
        assert is_private_ip("example.com") is False
        assert is_private_ip("not_an_ip") is False


# ─────────────────────────────────────────────────────────────────────────────
# validate_host_not_private — full host validation including DNS resolution
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateHostNotPrivate:

    def test_localhost_blocked(self):
        """'localhost' is in the blocked hostname list."""
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("localhost")

    def test_metadata_google_internal_blocked(self):
        """Google Cloud metadata hostname is blocked."""
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("metadata.google.internal")

    def test_direct_private_ip_blocked_127(self):
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("127.0.0.1")

    def test_direct_private_ip_blocked_10(self):
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("10.0.0.1")

    def test_direct_private_ip_blocked_172_16(self):
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("172.16.0.1")

    def test_direct_private_ip_blocked_192_168(self):
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("192.168.1.1")

    def test_direct_private_ip_blocked_metadata(self):
        """169.254.169.254 is the AWS/GCP metadata server — must be blocked."""
        with pytest.raises(PrivateIPAccessError):
            validate_host_not_private("169.254.169.254")

    def test_direct_public_ip_allowed(self):
        """Direct public IP addresses are allowed."""
        # Should not raise
        validate_host_not_private("8.8.8.8")

    def test_hostname_resolving_to_private_blocked(self):
        """
        Hostname that resolves to a private IP must be blocked.
        We mock socket.getaddrinfo to simulate resolution.
        """
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("192.168.1.100", 0))
            ]
            with pytest.raises(PrivateIPAccessError):
                validate_host_not_private("internal-service.internal")

    def test_hostname_resolving_to_public_allowed(self):
        """Hostname resolving to a public IP is allowed."""
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("93.184.216.34", 0))  # example.com
            ]
            # Should not raise
            validate_host_not_private("example.com")

    def test_failed_dns_resolution_blocks_request(self):
        """If DNS resolution fails, treat host as blocked (fail safe)."""
        import socket as sock
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.side_effect = sock.gaierror("Name resolution failed")
            with pytest.raises(PrivateIPAccessError):
                validate_host_not_private("nonexistent.invalid")


# ─────────────────────────────────────────────────────────────────────────────
# DNS Rebinding Detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSRebindingProtection:

    def test_same_ip_no_rebinding(self):
        """If DNS resolution returns the same IP, no rebinding detected."""
        original_ips = ["93.184.216.34"]
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("93.184.216.34", 0))
            ]
            # Should not raise
            validate_no_dns_rebinding("example.com", original_ips)

    def test_rebinding_to_private_ip_detected(self):
        """
        If DNS now resolves to a private IP that wasn't in the original set,
        this is a DNS rebinding attack — must be blocked.
        """
        original_ips = ["93.184.216.34"]  # was public
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("192.168.1.1", 0))  # now private!
            ]
            with pytest.raises(PrivateIPAccessError):
                validate_no_dns_rebinding("evil-rebinding.com", original_ips)

    def test_rebinding_to_metadata_ip_detected(self):
        """DNS rebinding to cloud metadata server (169.254.169.254) must be blocked."""
        original_ips = ["8.8.8.8"]
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("169.254.169.254", 0))
            ]
            with pytest.raises(PrivateIPAccessError):
                validate_no_dns_rebinding("rebind-to-metadata.evil.com", original_ips)

    def test_ip_change_to_public_is_allowed(self):
        """
        If DNS changes from one public IP to another public IP,
        that's not a rebinding attack — allow it.
        """
        original_ips = ["93.184.216.34"]
        with patch("app.targets.private_ip.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("104.18.0.1", 0))  # different public IP
            ]
            # Should not raise — both are public
            validate_no_dns_rebinding("example.com", original_ips)
