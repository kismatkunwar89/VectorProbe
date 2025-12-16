"""
Unit tests for custom decorators.

Tests the decorator utilities for:
- IP validation
- Retry logic
- Timing
- Call logging
"""

import pytest
import time
from utils.decorators import validate_ip, retry, timing, log_calls


class TestValidateIPDecorator:
    """Test the @validate_ip decorator."""

    def test_valid_ip_passes(self):
        """Test that valid IPs pass validation."""
        class MockHandler:
            @validate_ip
            def scan(self, ip: str):
                return f"Scanned {ip}"

        handler = MockHandler()
        result = handler.scan("192.168.1.1")
        assert result == "Scanned 192.168.1.1"

    def test_invalid_ip_raises_error(self):
        """Test that invalid IPs raise ValueError."""
        class MockHandler:
            @validate_ip
            def scan(self, ip: str):
                return f"Scanned {ip}"

        handler = MockHandler()
        with pytest.raises(ValueError, match="Invalid IP address"):
            handler.scan("not.an.ip")

    def test_malformed_ip_raises_error(self):
        """Test that malformed IPs raise ValueError."""
        class MockHandler:
            @validate_ip
            def scan(self, ip: str):
                return f"Scanned {ip}"

        handler = MockHandler()
        with pytest.raises(ValueError, match="Invalid IP address"):
            handler.scan("999.999.999.999")

    def test_valid_ipv4_addresses(self):
        """Test various valid IPv4 formats."""
        class MockHandler:
            @validate_ip
            def scan(self, ip: str):
                return True

        handler = MockHandler()
        valid_ips = [
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255"
        ]

        for ip in valid_ips:
            assert handler.scan(ip) is True


class TestRetryDecorator:
    """Test the @retry decorator."""

    def test_succeeds_on_first_attempt(self):
        """Test function that succeeds immediately."""
        call_count = {'count': 0}

        @retry(max_attempts=3, delay=0.1)
        def always_succeeds():
            call_count['count'] += 1
            return "success"

        result = always_succeeds()
        assert result == "success"
        assert call_count['count'] == 1

    def test_succeeds_after_retries(self):
        """Test function that fails then succeeds."""
        call_count = {'count': 0}

        @retry(max_attempts=3, delay=0.1)
        def fails_twice():
            call_count['count'] += 1
            if call_count['count'] < 3:
                raise Exception("Temporary failure")
            return "success"

        result = fails_twice()
        assert result == "success"
        assert call_count['count'] == 3

    def test_all_attempts_fail(self):
        """Test function that fails all attempts."""
        call_count = {'count': 0}

        @retry(max_attempts=3, delay=0.1)
        def always_fails():
            call_count['count'] += 1
            raise Exception("Permanent failure")

        with pytest.raises(Exception, match="Permanent failure"):
            always_fails()

        assert call_count['count'] == 3

    def test_custom_retry_count(self):
        """Test custom retry attempt count."""
        call_count = {'count': 0}

        @retry(max_attempts=5, delay=0.05)
        def fails_four_times():
            call_count['count'] += 1
            if call_count['count'] < 5:
                raise Exception("Retry me")
            return "finally succeeded"

        result = fails_four_times()
        assert result == "finally succeeded"
        assert call_count['count'] == 5


class TestTimingDecorator:
    """Test the @timing decorator."""

    def test_timing_decorator_works(self):
        """Test that timing decorator doesn't break functionality."""
        @timing
        def simple_function():
            return "result"

        result = simple_function()
        assert result == "result"

    def test_timing_with_delay(self):
        """Test timing decorator with a delayed function."""
        @timing
        def slow_function():
            time.sleep(0.1)
            return "done"

        result = slow_function()
        assert result == "done"

    def test_timing_preserves_return_value(self):
        """Test that timing decorator preserves return values."""
        @timing
        def returns_dict():
            return {"key": "value", "number": 42}

        result = returns_dict()
        assert result == {"key": "value", "number": 42}


class TestLogCallsDecorator:
    """Test the @log_calls decorator."""

    def test_log_calls_preserves_functionality(self):
        """Test that log_calls decorator doesn't break function."""
        @log_calls
        def add_numbers(a, b):
            return a + b

        result = add_numbers(5, 3)
        assert result == 8

    def test_log_calls_with_kwargs(self):
        """Test log_calls with keyword arguments."""
        @log_calls
        def greet(name, greeting="Hello"):
            return f"{greeting}, {name}!"

        result = greet("Alice", greeting="Hi")
        assert result == "Hi, Alice!"


class TestDecoratorStacking:
    """Test stacking multiple decorators."""

    def test_validate_and_timing_together(self):
        """Test @validate_ip and @timing stacked."""
        class MockHandler:
            @validate_ip
            @timing
            def scan(self, ip: str):
                return f"Scanned {ip}"

        handler = MockHandler()
        result = handler.scan("10.0.0.1")
        assert result == "Scanned 10.0.0.1"

    def test_stacked_decorators_validation_fails(self):
        """Test that validation still works when stacked."""
        class MockHandler:
            @validate_ip
            @timing
            def scan(self, ip: str):
                return f"Scanned {ip}"

        handler = MockHandler()
        with pytest.raises(ValueError, match="Invalid IP address"):
            handler.scan("invalid")
