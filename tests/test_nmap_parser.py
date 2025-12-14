"""
Unit tests for nmap_parser module.

Tests the NmapParser class which parses nmap text output.
"""

import pytest
from parsers.nmap_parser import NmapParser


class TestNmapParserBasicParsing:
    """Test basic parsing functionality with fixture data."""

    def test_parse_valid_text_fixture(self):
        """Test parsing a valid nmap text output from fixture file."""
        with open('tests/fixtures/nmap_sample.txt', 'r') as f:
            text_content = f.read()

        parser = NmapParser(text_content)
        parser.parse()

        assert len(parser.hosts) == 2
        assert parser.hosts[0]['host'] == '192.168.1.100'
        assert parser.hosts[1]['host'] == '192.168.1.101'

    def test_parse_single_host(self):
        """Test parsing output for a single host."""
        nmap_output = """Host: 10.0.0.1
Ports: 80/open/tcp
OS details: Ubuntu Linux"""

        parser = NmapParser(nmap_output)
        parser.parse()

        assert len(parser.hosts) == 1
        assert parser.hosts[0]['host'] == '10.0.0.1'


class TestNmapParserHostExtraction:
    """Test extraction of host information."""

    def test_extract_host_ip(self):
        """Test extracting IP address from host line."""
        nmap_output = "Host: 192.168.100.50\nPorts: 22/open/tcp"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert parser.hosts[0]['host'] == '192.168.100.50'

    def test_extract_multiple_hosts(self):
        """Test extracting multiple hosts from output."""
        nmap_output = """Host: 10.0.0.1
Ports: 22/open/tcp

Host: 10.0.0.2
Ports: 80/open/tcp

Host: 10.0.0.3
Ports: 443/open/tcp"""

        parser = NmapParser(nmap_output)
        parser.parse()

        assert len(parser.hosts) == 3
        assert parser.hosts[0]['host'] == '10.0.0.1'
        assert parser.hosts[1]['host'] == '10.0.0.2'
        assert parser.hosts[2]['host'] == '10.0.0.3'


class TestNmapParserPortParsing:
    """Test parsing of port information."""

    def test_parse_single_port(self):
        """Test parsing a single port."""
        nmap_output = "Host: 10.0.0.1\nPorts: 80/open/tcp"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert 'ports' in parser.hosts[0]
        assert parser.hosts[0]['ports'] == ['80/open/tcp']

    def test_parse_multiple_ports(self):
        """Test parsing multiple comma-separated ports."""
        nmap_output = "Host: 10.0.0.1\nPorts: 22/open/tcp, 80/open/tcp, 443/open/tcp"

        parser = NmapParser(nmap_output)
        parser.parse()

        ports = parser.hosts[0]['ports']
        assert len(ports) == 3
        assert '22/open/tcp' in ports
        assert '80/open/tcp' in ports
        assert '443/open/tcp' in ports

    def test_parse_common_web_ports(self):
        """Test parsing common web service ports."""
        with open('tests/fixtures/nmap_sample.txt', 'r') as f:
            text_content = f.read()

        parser = NmapParser(text_content)
        parser.parse()

        # First host (Linux) should have web ports
        linux_ports = parser.hosts[0]['ports']
        assert '80/open/tcp' in linux_ports
        assert '443/open/tcp' in linux_ports

    def test_parse_windows_ports(self):
        """Test parsing common Windows service ports."""
        with open('tests/fixtures/nmap_sample.txt', 'r') as f:
            text_content = f.read()

        parser = NmapParser(text_content)
        parser.parse()

        # Second host (Windows) should have RDP and SMB
        windows_ports = parser.hosts[1]['ports']
        assert '3389/open/tcp' in windows_ports
        assert '445/open/tcp' in windows_ports


class TestNmapParserOSDetection:
    """Test parsing of OS detection information."""

    def test_parse_linux_os(self):
        """Test parsing Linux OS detection."""
        nmap_output = "Host: 10.0.0.1\nOS details: Linux 5.4"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert 'os' in parser.hosts[0]
        assert parser.hosts[0]['os'] == 'Linux 5.4'

    def test_parse_windows_os(self):
        """Test parsing Windows OS detection."""
        nmap_output = "Host: 10.0.0.2\nOS details: Windows Server 2019"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert parser.hosts[0]['os'] == 'Windows Server 2019'

    def test_parse_os_from_fixture(self):
        """Test parsing OS information from fixture."""
        with open('tests/fixtures/nmap_sample.txt', 'r') as f:
            text_content = f.read()

        parser = NmapParser(text_content)
        parser.parse()

        assert parser.hosts[0]['os'] == 'Linux 5.4'
        assert parser.hosts[1]['os'] == 'Windows Server 2019'


class TestNmapParserMultipleHosts:
    """Test parsing output containing multiple hosts."""

    def test_parse_fixture_multiple_hosts(self):
        """Test parsing fixture with multiple hosts."""
        with open('tests/fixtures/nmap_sample.txt', 'r') as f:
            text_content = f.read()

        parser = NmapParser(text_content)
        parser.parse()

        # Verify we have 2 hosts
        assert len(parser.hosts) == 2

        # Verify first host details
        host1 = parser.hosts[0]
        assert host1['host'] == '192.168.1.100'
        assert len(host1['ports']) == 3
        assert host1['os'] == 'Linux 5.4'

        # Verify second host details
        host2 = parser.hosts[1]
        assert host2['host'] == '192.168.1.101'
        assert len(host2['ports']) == 2
        assert host2['os'] == 'Windows Server 2019'


class TestNmapParserRealOutput:
    """Test parsing of actual Nmap normal output."""

    def test_parse_real_normal_output(self):
        """Ensure real Nmap output is parsed correctly."""
        nmap_output = """# Nmap 7.95 scan initiated Sun Dec 14 13:08:43 2025 as: /usr/lib/nmap/nmap -sS -sV -sC -O -Pn -oN - 10.248.1.1
Nmap scan report for demo-host (10.0.0.5)
Host is up (0.00018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Debian 3 (protocol 2.0)
53/tcp open  domain  dnsmasq 2.90
| dns-nsid:
|_  bind.version: dnsmasq-2.90
MAC Address: F0:DB:30:76:EE:EB (Yottabyte)

Nmap scan report for 10.248.1.1
Host is up (0.00018s latency).
PORT   STATE SERVICE VERSION
443/tcp open  https   Apache httpd 2.4.58
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 2 IP addresses (2 hosts up) scanned in 7.42 seconds
"""

        parser = NmapParser(nmap_output)
        parser.parse()

        assert len(parser.hosts) == 2
        first_host = parser.hosts[0]
        second_host = parser.hosts[1]

        assert first_host['ip'] == '10.0.0.5'
        assert '22/tcp/open/ssh' in first_host['ports']
        assert '53/tcp/open/domain' in first_host['ports']

        assert second_host['host'] == '10.248.1.1'
        assert second_host['ip'] == '10.248.1.1'
        assert second_host['ports'] == ['443/tcp/open/https']


class TestNmapParserEdgeCases:
    """Test edge cases and error conditions."""

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        parser = NmapParser("")
        parser.parse()

        # Should return empty list or handle gracefully
        assert isinstance(parser.hosts, list)

    def test_parse_host_without_ports(self):
        """Test parsing a host with no port information."""
        nmap_output = "Host: 10.0.0.1"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert len(parser.hosts) == 1
        assert parser.hosts[0]['host'] == '10.0.0.1'
        # Ports key might not exist or be empty
        if 'ports' in parser.hosts[0]:
            assert isinstance(parser.hosts[0]['ports'], list)

    def test_parse_host_without_os(self):
        """Test parsing a host with no OS information."""
        nmap_output = "Host: 10.0.0.1\nPorts: 80/open/tcp"

        parser = NmapParser(nmap_output)
        parser.parse()

        assert parser.hosts[0]['host'] == '10.0.0.1'
        assert parser.hosts[0]['ports'] == ['80/open/tcp']
        # OS key might not exist or be None
        if 'os' in parser.hosts[0]:
            assert parser.hosts[0]['os'] is None or isinstance(parser.hosts[0]['os'], str)

    def test_parse_malformed_input(self):
        """Test parsing malformed input that doesn't match expected format."""
        nmap_output = "This is not valid nmap output\nRandom text here"

        parser = NmapParser(nmap_output)
        parser.parse()

        # Should handle gracefully without crashing
        assert isinstance(parser.hosts, list)

    def test_parse_whitespace_only(self):
        """Test parsing output with only whitespace."""
        nmap_output = "   \n\n   \t\t   \n"

        parser = NmapParser(nmap_output)
        parser.parse()

        # Should handle gracefully
        assert isinstance(parser.hosts, list)
