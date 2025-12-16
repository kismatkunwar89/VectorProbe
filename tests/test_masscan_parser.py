"""
Unit tests for masscan_parser module.

Tests the MasscanParser class which parses masscan greppable format output.
"""

import pytest
from src.parsers.masscan_parser import MasscanParser


@pytest.fixture
def masscan_fixture_path():
    """Return path to the masscan sample fixture file."""
    return "tests/fixtures/masscan_sample.txt"


@pytest.fixture
def masscan_sample_content():
    """Return raw masscan sample content."""
    return """# masscan version 1.0.5; options: -p0-65535 --rate=1000000
Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp, 3389/open/tcp, 8080/open/tcp, 22/open/tcp, 23/open/tcp, 135/open/tcp, 139/open/tcp
Host: 192.168.1.101 Ports: 22/open/tcp, 23/open/tcp
Host: 192.168.1.102 Ports: 445/open/tcp
Host: 192.168.1.103 Ports:
Host: 192.168.1.104 Ports: 80/open/tcp, 443/open/tcp, 8443/open/tcp, 3000/open/tcp, 5000/open/tcp, 9000/open/tcp, 27017/open/tcp, 6379/open/tcp"""


class TestMasscanParserBasicParsing:
    """Test basic parsing functionality with fixture data."""

    def test_parse_valid_fixture_file(self, masscan_fixture_path):
        """Test parsing a valid masscan fixture file."""
        with open(masscan_fixture_path, 'r') as f:
            content = f.read()

        parser = MasscanParser(content)
        hosts = parser.parse()

        assert len(hosts) >= 4
        assert hosts[0]['host'] == '192.168.1.100'

    def test_parse_sample_content(self, masscan_sample_content):
        """Test parsing masscan sample content from string."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()

        assert hosts is not None
        assert isinstance(hosts, list)
        assert len(hosts) > 0

    def test_parse_returns_list(self, masscan_sample_content):
        """Test that parse returns a list."""
        parser = MasscanParser(masscan_sample_content)
        result = parser.parse()
        assert isinstance(result, list)

    def test_parsed_hosts_have_structure(self, masscan_sample_content):
        """Test that parsed hosts have correct structure."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        assert all('host' in h for h in hosts)
        assert all('ports' in h for h in hosts)


class TestMasscanParserHostExtraction:
    """Test host IP extraction from masscan output."""

    def test_extract_single_host(self):
        """Test extraction of single host."""
        content = "Host: 192.168.1.100 Ports: 80/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts) == 1
        assert hosts[0]['host'] == "192.168.1.100"

    def test_extract_multiple_hosts(self, masscan_sample_content):
        """Test extraction of multiple hosts from sample."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        assert len(hosts) >= 4
        host_ips = [h['host'] for h in hosts]
        assert "192.168.1.100" in host_ips
        assert "192.168.1.101" in host_ips
        assert "192.168.1.102" in host_ips

    def test_extract_all_sample_hosts(self, masscan_sample_content):
        """Test extraction of all hosts from sample fixture."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        expected_hosts = ["192.168.1.100", "192.168.1.101",
                          "192.168.1.102", "192.168.1.103", "192.168.1.104"]
        extracted_ips = [h['host'] for h in hosts]
        for expected_host in expected_hosts:
            assert expected_host in extracted_ips

    def test_host_ip_format_validation(self, masscan_sample_content):
        """Test that extracted hosts have valid IP format."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        for host in hosts:
            ip_parts = host['host'].split('.')
            assert len(ip_parts) == 4
            for part in ip_parts:
                assert 0 <= int(part) <= 255


class TestMasscanParserPortExtraction:
    """Test port, state, and protocol extraction."""

    def test_extract_ports_from_host(self):
        """Test extraction of ports from a single host."""
        content = "Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp, 22/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts) == 1
        assert len(hosts[0]['ports']) == 3

    def test_port_numbers_extracted_correctly(self):
        """Test that port numbers are extracted correctly."""
        content = "Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp, 3389/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        ports = [p['port'] for p in hosts[0]['ports']]
        assert 80 in ports
        assert 443 in ports
        assert 3389 in ports

    def test_port_state_extracted_correctly(self):
        """Test that port states are extracted correctly."""
        content = "Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        for port in hosts[0]['ports']:
            assert port['state'] == "open"

    def test_protocol_extracted_correctly(self):
        """Test that protocol is extracted correctly (should be tcp)."""
        content = "Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        for port in hosts[0]['ports']:
            assert port['protocol'] == "tcp"

    def test_multiple_ports_with_correct_attributes(self):
        """Test that multiple ports have correct attributes."""
        content = "Host: 192.168.1.100 Ports: 22/open/tcp, 80/open/tcp, 443/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts[0]['ports']) == 3

        for port in hosts[0]['ports']:
            assert isinstance(port, dict)
            assert port['port'] in [22, 80, 443]
            assert port['state'] == "open"
            assert port['protocol'] == "tcp"

    def test_extract_many_ports(self):
        """Test extraction of many ports from a single host."""
        content = "Host: 192.168.1.104 Ports: 80/open/tcp, 443/open/tcp, 8443/open/tcp, 3000/open/tcp, 5000/open/tcp, 9000/open/tcp, 27017/open/tcp, 6379/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts[0]['ports']) == 8


class TestMasscanParserEdgeCases:
    """Test edge cases and error handling."""

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        parser = MasscanParser("")
        result = parser.parse()
        assert result is not None
        assert isinstance(result, list)
        assert len(result) == 0

    def test_parse_none_string(self):
        """Test parsing None-like empty content."""
        parser = MasscanParser("")
        result = parser.parse()
        assert len(result) == 0

    def test_parse_only_comments(self):
        """Test parsing content with only comments."""
        content = "# masscan version 1.0.5; options: -p0-65535 --rate=1000000"
        parser = MasscanParser(content)
        result = parser.parse()
        assert len(result) == 0

    def test_host_with_empty_ports(self):
        """Test parsing host with empty ports section."""
        content = "Host: 192.168.1.103 Ports:"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts) == 1
        assert len(hosts[0]['ports']) == 0

    def test_single_port_on_host(self):
        """Test host with only one port."""
        content = "Host: 192.168.1.102 Ports: 445/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts[0]['ports']) == 1
        assert hosts[0]['ports'][0]['port'] == 445

    def test_malformed_host_line_ignored(self):
        """Test that malformed lines are handled gracefully."""
        content = """Host: 192.168.1.100 Ports: 80/open/tcp
InvalidHostLine
Host: 192.168.1.101 Ports: 22/open/tcp"""
        parser = MasscanParser(content)
        hosts = parser.parse()
        # Should successfully parse the valid lines and ignore invalid
        assert len(hosts) >= 2

    def test_whitespace_handling(self):
        """Test handling of extra whitespace."""
        content = "Host: 192.168.1.100  Ports:  80/open/tcp,  443/open/tcp"
        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts) == 1
        assert len(hosts[0]['ports']) >= 1

    def test_line_with_only_host_keyword(self):
        """Test handling of incomplete host line."""
        content = """Host: 192.168.1.100 Ports: 80/open/tcp
Host:
Host: 192.168.1.101 Ports: 22/open/tcp"""
        parser = MasscanParser(content)
        hosts = parser.parse()
        valid_ips = [h['host'] for h in hosts if h['host']]
        assert "192.168.1.100" in valid_ips
        assert "192.168.1.101" in valid_ips


class TestMasscanParserMultipleHosts:
    """Test parsing multiple hosts with varying configurations."""

    def test_multiple_hosts_different_port_counts(self, masscan_sample_content):
        """Test parsing hosts with different numbers of ports."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        port_counts = [len(h['ports']) for h in hosts]
        # Should have hosts with different port counts
        assert max(port_counts) > min(port_counts)

    def test_host_with_many_ports(self, masscan_sample_content):
        """Test host with many common ports."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        # Find host 192.168.1.100 which should have 8 ports
        host_100 = next(
            (h for h in hosts if h['host'] == "192.168.1.100"), None)
        assert host_100 is not None
        assert len(host_100['ports']) == 8

    def test_host_with_few_ports(self, masscan_sample_content):
        """Test host with only 2 ports."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        # Find host 192.168.1.101 which should have 2 ports
        host_101 = next(
            (h for h in hosts if h['host'] == "192.168.1.101"), None)
        assert host_101 is not None
        assert len(host_101['ports']) == 2

    def test_host_with_single_port(self, masscan_sample_content):
        """Test host with single port."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        # Find host 192.168.1.102 which should have 1 port
        host_102 = next(
            (h for h in hosts if h['host'] == "192.168.1.102"), None)
        assert host_102 is not None
        assert len(host_102['ports']) == 1

    def test_host_with_no_ports(self, masscan_sample_content):
        """Test host with no open ports."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        # Find host 192.168.1.103 which should have no ports
        host_103 = next(
            (h for h in hosts if h['host'] == "192.168.1.103"), None)
        assert host_103 is not None
        assert len(host_103['ports']) == 0

    def test_all_hosts_properly_parsed(self, masscan_sample_content):
        """Test that all hosts are properly parsed with correct structure."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        for host in hosts:
            assert host['host'] is not None
            assert len(host['host']) > 0
            assert 'ports' in host
            assert isinstance(host['ports'], list)

    def test_all_services_have_required_fields(self, masscan_sample_content):
        """Test that all services have required fields."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        for host in hosts:
            for port in host['ports']:
                assert 'port' in port
                assert 'state' in port
                assert 'protocol' in port
                assert port['port'] is not None
                assert port['port'] > 0
                assert port['port'] <= 65535

    def test_common_ports_extracted(self, masscan_sample_content):
        """Test that common network ports are properly extracted."""
        parser = MasscanParser(masscan_sample_content)
        hosts = parser.parse()
        all_ports = set()
        for host in hosts:
            for port in host['ports']:
                all_ports.add(port['port'])

        # Should contain some common ports from the sample
        common_ports = {22, 80, 443}
        assert common_ports.issubset(all_ports)

    def test_parse_fixture_file_complete(self, masscan_fixture_path):
        """Test complete parsing of fixture file."""
        with open(masscan_fixture_path, 'r') as f:
            content = f.read()

        parser = MasscanParser(content)
        hosts = parser.parse()
        assert len(hosts) == 5  # Should have 5 hosts from sample

        # Verify host count and uniqueness
        host_ips = [h['host'] for h in hosts]
        assert len(host_ips) == 5
        assert len(set(host_ips)) == 5  # All unique IPs
