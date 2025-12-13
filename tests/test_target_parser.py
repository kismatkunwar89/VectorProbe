"""
Unit tests for host_discovery module (target parser).

Tests target parsing and resolution functionality for:
- IP address validation
- CIDR expansion
- DNS resolution
- Exclusion handling
- Mixed target types
"""

import pytest
from unittest.mock import patch, MagicMock
from core.host_discovery import (
    _is_ip,
    _expand_cidr,
    _resolve_dns,
    _split_csv,
    parse_and_resolve_targets,
    ResolvedTarget
)


class TestIsIPFunction:
    """Test the _is_ip helper function."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        assert _is_ip("192.168.1.1") is True
        assert _is_ip("10.0.0.1") is True
        assert _is_ip("172.16.0.1") is True
        assert _is_ip("127.0.0.1") is True
        assert _is_ip("0.0.0.0") is True
        assert _is_ip("255.255.255.255") is True

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        assert _is_ip("256.1.1.1") is False
        assert _is_ip("192.168.1") is False
        assert _is_ip("192.168.1.1.1") is False
        assert _is_ip("google.com") is False
        assert _is_ip("not-an-ip") is False
        assert _is_ip("") is False

    def test_ip_with_cidr(self):
        """Test that CIDR notation is not considered a simple IP."""
        assert _is_ip("192.168.1.0/24") is False


class TestSplitCSVFunction:
    """Test the _split_csv helper function."""

    def test_single_value(self):
        """Test splitting single value."""
        result = _split_csv("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_multiple_values(self):
        """Test splitting comma-separated values."""
        result = _split_csv("192.168.1.1,10.0.0.1,172.16.0.1")
        assert len(result) == 3
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result
        assert "172.16.0.1" in result

    def test_values_with_spaces(self):
        """Test that spaces are stripped."""
        result = _split_csv("192.168.1.1 , 10.0.0.1 , 172.16.0.1")
        assert result == ["192.168.1.1", "10.0.0.1", "172.16.0.1"]

    def test_empty_values_filtered(self):
        """Test that empty values are filtered out."""
        result = _split_csv("192.168.1.1,,10.0.0.1")
        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_empty_string(self):
        """Test empty string input."""
        result = _split_csv("")
        assert result == []


class TestExpandCIDRFunction:
    """Test the _expand_cidr function (now a generator)."""

    def test_expand_slash_30(self):
        """Test /30 expansion (2 hosts)."""
        ips = list(_expand_cidr("192.168.1.0/30"))
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_expand_slash_29(self):
        """Test /29 expansion (6 hosts)."""
        ips = list(_expand_cidr("192.168.1.0/29"))
        assert len(ips) == 6

    def test_expand_slash_24(self):
        """Test /24 expansion (254 hosts)."""
        ips = list(_expand_cidr("192.168.1.0/24"))
        assert len(ips) == 254
        assert "192.168.1.1" in ips
        assert "192.168.1.254" in ips


class TestResolveDNSFunction:
    """Test the _resolve_dns function."""

    @patch('socket.getaddrinfo')
    def test_resolve_single_ip(self, mock_getaddrinfo):
        """Test resolving DNS to single IP."""
        # Mock returns format: [(family, type, proto, canonname, sockaddr)]
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0))
        ]

        result = _resolve_dns("example.com")
        assert len(result) == 1
        assert "93.184.216.34" in result

    @patch('socket.getaddrinfo')
    def test_resolve_multiple_ips(self, mock_getaddrinfo):
        """Test resolving DNS to multiple IPs."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('5.6.7.8', 0))
        ]

        result = _resolve_dns("multi.example.com")
        assert len(result) == 2
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    @patch('socket.getaddrinfo')
    def test_resolve_removes_duplicates(self, mock_getaddrinfo):
        """Test that duplicate IPs are removed."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('1.2.3.4', 0)),
            (2, 1, 6, '', ('5.6.7.8', 0))
        ]

        result = _resolve_dns("dup.example.com")
        assert len(result) == 2
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result


class TestParseAndResolveTargets:
    """Test the main parse_and_resolve_targets function."""

    def test_single_ip_target(self):
        """Test parsing a single IP address."""
        targets, excluded_names = parse_and_resolve_targets("192.168.1.1", "", no_prompt=True)

        assert len(targets) == 1
        assert isinstance(targets[0], ResolvedTarget)
        assert targets[0].ip == "192.168.1.1"
        assert targets[0].original == "192.168.1.1"
        assert isinstance(excluded_names, list)

    def test_cidr_target(self):
        """Test parsing a CIDR range."""
        targets, _ = parse_and_resolve_targets("192.168.1.0/30", "", no_prompt=True)

        assert len(targets) == 2
        assert targets[0].ip == "192.168.1.1"
        assert targets[1].ip == "192.168.1.2"
        assert targets[0].original == "192.168.1.0/30"

    def test_multiple_ip_targets(self):
        """Test parsing comma-separated IPs."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.1,10.0.0.1,172.16.0.1",
            "",
            no_prompt=True
        )

        assert len(targets) == 3
        ips = [r.ip for r in targets]
        assert "192.168.1.1" in ips
        assert "10.0.0.1" in ips
        assert "172.16.0.1" in ips

    def test_exclude_single_ip(self):
        """Test excluding a single IP from CIDR range."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.0/30",
            "192.168.1.1",
            no_prompt=True
        )

        assert len(targets) == 1
        assert targets[0].ip == "192.168.1.2"

    def test_exclude_cidr_range(self):
        """Test excluding a CIDR range."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.0/29",
            "192.168.1.0/30",
            no_prompt=True
        )

        # /29 = 6 hosts, /30 = 2 hosts
        # Should have 4 hosts remaining
        assert len(targets) == 4

        excluded_ips = ["192.168.1.1", "192.168.1.2"]
        result_ips = [r.ip for r in targets]

        for excluded in excluded_ips:
            assert excluded not in result_ips

    def test_mixed_targets(self):
        """Test mixing IPs and CIDR ranges."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.1,10.0.0.0/30",
            "",
            no_prompt=True
        )

        # 1 direct IP + 2 from /30
        assert len(targets) >= 3

        result_ips = [r.ip for r in targets]
        assert "192.168.1.1" in result_ips

    @patch('core.host_discovery._resolve_dns')
    def test_dns_target_with_prompt_disabled(self, mock_resolve):
        """Test DNS resolution with --no-prompt."""
        mock_resolve.return_value = ["93.184.216.34"]

        targets, _ = parse_and_resolve_targets(
            "example.com",
            "",
            no_prompt=True
        )

        assert len(targets) == 1
        assert targets[0].ip == "93.184.216.34"
        assert targets[0].hostname == "example.com"
        mock_resolve.assert_called_once_with("example.com")

    def test_empty_targets(self):
        """Test with empty target string."""
        targets, _ = parse_and_resolve_targets("", "", no_prompt=True)
        assert len(targets) == 0

    def test_duplicate_removal(self):
        """Test that duplicate targets are removed."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.1,192.168.1.1",
            "",
            no_prompt=True
        )

        # Should only have one entry
        assert len(targets) == 1
        assert targets[0].ip == "192.168.1.1"

    def test_resolved_target_dataclass(self):
        """Test ResolvedTarget dataclass structure."""
        targets, _ = parse_and_resolve_targets("192.168.1.1", "", no_prompt=True)

        target = targets[0]
        assert hasattr(target, 'original')
        assert hasattr(target, 'ip')
        assert hasattr(target, 'hostname')
        assert target.hostname is None  # Direct IP has no hostname


class TestExclusionLogic:
    """Test complex exclusion scenarios."""

    def test_exclude_from_multiple_ranges(self):
        """Test excluding IPs from multiple CIDR ranges."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.0/29,10.0.0.0/29",
            "192.168.1.1,10.0.0.1",
            no_prompt=True
        )

        result_ips = [r.ip for r in targets]
        assert "192.168.1.1" not in result_ips
        assert "10.0.0.1" not in result_ips

    def test_exclude_entire_range(self):
        """Test that excluding entire range leaves nothing."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.0/30",
            "192.168.1.0/30",
            no_prompt=True
        )

        assert len(targets) == 0

    def test_overlapping_targets_and_exclusions(self):
        """Test overlapping target and exclusion ranges."""
        targets, _ = parse_and_resolve_targets(
            "192.168.1.0/28",
            "192.168.1.0/29",
            no_prompt=True
        )

        # /28 = 14 hosts, /29 = 6 hosts
        # Should have 8 hosts remaining
        assert len(targets) == 8


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_whitespace_handling(self):
        """Test that whitespace is handled correctly."""
        targets, _ = parse_and_resolve_targets(
            " 192.168.1.1 , 10.0.0.1 ",
            " 192.168.1.1 ",
            no_prompt=True
        )

        assert len(targets) == 1
        assert targets[0].ip == "10.0.0.1"

    def test_large_cidr_range_performance(self):
        """Test that large CIDR ranges don't hang (generator efficiency)."""
        import time

        start = time.time()
        targets, _ = parse_and_resolve_targets(
            "10.0.0.0/24",
            "",
            no_prompt=True
        )
        elapsed = time.time() - start

        # Should complete reasonably fast even for 254 hosts
        assert len(targets) == 254
        assert elapsed < 2.0  # Should take less than 2 seconds
