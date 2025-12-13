"""
Unit tests for generator functions.

Tests generator implementations for:
- CIDR expansion
- Memory efficiency
- Lazy evaluation
"""

import pytest
from core.host_discovery import _expand_cidr


class TestCIDRExpansionGenerator:
    """Test the _expand_cidr generator function."""

    def test_small_cidr_range(self):
        """Test expanding a small CIDR range (/30 = 2 hosts)."""
        ips = list(_expand_cidr("192.168.1.0/30"))

        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips
        # Network (.0) and broadcast (.3) should be excluded
        assert "192.168.1.0" not in ips
        assert "192.168.1.3" not in ips

    def test_medium_cidr_range(self):
        """Test expanding a /28 range (14 hosts)."""
        ips = list(_expand_cidr("10.0.0.0/28"))

        assert len(ips) == 14  # 2^4 - 2 (network and broadcast)
        assert "10.0.0.1" in ips
        assert "10.0.0.14" in ips
        assert "10.0.0.0" not in ips  # Network address
        assert "10.0.0.15" not in ips  # Broadcast address

    def test_generator_returns_strings(self):
        """Test that generator yields string IP addresses."""
        for ip in _expand_cidr("172.16.0.0/29"):
            assert isinstance(ip, str)

    def test_generator_is_iterable(self):
        """Test that result is a generator (iterable)."""
        result = _expand_cidr("192.168.1.0/30")

        # Generators have __iter__ and __next__
        assert hasattr(result, '__iter__')
        assert hasattr(result, '__next__')

    def test_generator_lazy_evaluation(self):
        """Test that generator doesn't compute all values immediately."""
        # This would create 65,534 IPs if evaluated eagerly
        gen = _expand_cidr("10.0.0.0/16")

        # Generator should be created instantly (lazy)
        # Get first IP without loading all 65k
        first_ip = next(gen)
        assert first_ip == "10.0.0.1"

    def test_generator_can_be_consumed_multiple_ways(self):
        """Test different ways to consume the generator."""
        # As list
        ips_list = list(_expand_cidr("192.168.100.0/30"))
        assert len(ips_list) == 2

        # In for loop
        count = 0
        for ip in _expand_cidr("192.168.100.0/30"):
            count += 1
        assert count == 2

        # With set (for deduplication)
        ips_set = set(_expand_cidr("192.168.100.0/30"))
        assert len(ips_set) == 2

    def test_single_host_cidr(self):
        """Test /32 CIDR (single host)."""
        ips = list(_expand_cidr("192.168.1.1/32"))

        # /32 means single host - Python's ipaddress treats it as one usable host
        assert len(ips) == 1
        assert ips[0] == "192.168.1.1"

    def test_class_c_network(self):
        """Test standard Class C network (/24 = 254 hosts)."""
        ips = list(_expand_cidr("192.168.1.0/24"))

        assert len(ips) == 254
        assert "192.168.1.1" in ips
        assert "192.168.1.254" in ips
        assert "192.168.1.0" not in ips  # Network
        assert "192.168.1.255" not in ips  # Broadcast

    def test_generator_with_update(self):
        """Test that set.update() works with generator."""
        # This is how it's used in host_discovery.py line 122
        excluded_ips = set()
        excluded_ips.update(_expand_cidr("192.168.1.0/30"))

        assert len(excluded_ips) == 2
        assert "192.168.1.1" in excluded_ips
        assert "192.168.1.2" in excluded_ips

    def test_generator_in_for_loop(self):
        """Test generator in for loop (how it's used in host_discovery.py line 153)."""
        collected = []

        for ip in _expand_cidr("10.0.0.0/29"):
            collected.append(ip)

        assert len(collected) == 6  # 2^3 - 2 = 6 hosts
        assert all(isinstance(ip, str) for ip in collected)

    def test_private_network_ranges(self):
        """Test with different private IP ranges."""
        # Class A private
        class_a = list(_expand_cidr("10.0.0.0/29"))
        assert len(class_a) == 6

        # Class B private
        class_b = list(_expand_cidr("172.16.0.0/29"))
        assert len(class_b) == 6

        # Class C private
        class_c = list(_expand_cidr("192.168.0.0/29"))
        assert len(class_c) == 6


class TestGeneratorPerformance:
    """Test generator memory efficiency."""

    def test_large_range_doesnt_hang(self):
        """Test that creating generator for large range is instant."""
        import time

        start = time.time()
        gen = _expand_cidr("10.0.0.0/16")  # 65,534 hosts
        creation_time = time.time() - start

        # Generator creation should be near-instant (< 0.01 seconds)
        assert creation_time < 0.01

        # Actually getting first value should also be fast
        first_ip = next(gen)
        assert first_ip == "10.0.0.1"

    def test_generator_memory_efficiency(self):
        """Test that generator doesn't load everything into memory."""
        # Create generator for huge range
        gen = _expand_cidr("10.0.0.0/16")

        # Get just first 10 IPs without loading all 65k
        first_ten = [next(gen) for _ in range(10)]

        assert len(first_ten) == 10
        assert first_ten[0] == "10.0.0.1"
        assert first_ten[9] == "10.0.0.10"
