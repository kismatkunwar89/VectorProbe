#!/usr/bin/env python3
"""
Unit tests for the HostResult model.

These tests verify that the HostResult class correctly stores
and formats host information.
"""

import pytest
from models.host_result import HostResult


class TestHostResultCreation:
    """Tests for creating HostResult instances."""

    def test_create_host_with_ip_only(self):
        """Test creating a host with just an IP address."""
        host = HostResult("192.168.1.100")

        assert host.ip_address == "192.168.1.100"
        assert host.hostname is None
        assert host.domain is None
        assert host.os_type is None
        assert host.services == []

    def test_create_host_with_all_fields(self):
        """Test creating a host with all optional fields."""
        host = HostResult(
            ip_address="192.168.1.100",
            hostname="server1.local",
            domain="CORP.LOCAL",
            os_type="Windows Server 2019"
        )

        assert host.ip_address == "192.168.1.100"
        assert host.hostname == "server1.local"
        assert host.domain == "CORP.LOCAL"
        assert host.os_type == "Windows Server 2019"


class TestHostResultServices:
    """Tests for adding services to a host."""

    def test_add_single_service(self):
        """Test adding a single service to a host."""
        host = HostResult("192.168.1.100")
        host.add_service("HTTP", 80, "TCP")

        assert len(host.services) == 1
        assert host.services[0]['service_name'] == "HTTP"
        assert host.services[0]['port'] == 80
        assert host.services[0]['protocol'] == "TCP"

    def test_add_multiple_services(self):
        """Test adding multiple services to a host."""
        host = HostResult("192.168.1.100")
        host.add_service("HTTP", 80, "TCP")
        host.add_service("HTTPS", 443, "TCP")
        host.add_service("SSH", 22, "TCP")

        assert len(host.services) == 3
        assert host.services[1]['service_name'] == "HTTPS"


class TestHostResultWindowsInfo:
    """Tests for Windows-specific information."""

    def test_set_windows_info(self):
        """Test setting Windows-specific information."""
        host = HostResult("192.168.1.100")
        host.set_windows_info(
            netbios_name="SERVER1",
            workgroup="WORKGROUP",
            smb_version="3.1.1"
        )

        assert host.windows_info['netbios_name'] == "SERVER1"
        assert host.windows_info['workgroup'] == "WORKGROUP"
        assert host.windows_info['smb_version'] == "3.1.1"

    def test_invalid_windows_info_ignored(self):
        """Test that invalid Windows info fields are ignored."""
        host = HostResult("192.168.1.100")
        host.set_windows_info(
            netbios_name="SERVER1",
            invalid_field="should be ignored"
        )

        assert host.windows_info['netbios_name'] == "SERVER1"
        assert 'invalid_field' not in host.windows_info


class TestHostResultUnverifiedInfo:
    """Tests for unverified information."""

    def test_add_unverified_info(self):
        """Test adding unverified information."""
        host = HostResult("192.168.1.100")
        host.add_unverified_info("Likely running Windows Server 2019")

        assert len(host.unverified_info) == 1
        assert host.unverified_info[0] == "Likely running Windows Server 2019"


class TestHostResultCommandOutputs:
    """Tests for command outputs."""

    def test_add_command_output(self):
        """Test adding command output."""
        host = HostResult("192.168.1.100")
        host.add_command_output(
            command="nmap -sV 192.168.1.100",
            output="Starting Nmap..."
        )

        assert len(host.command_outputs) == 1
        assert host.command_outputs[0]['command'] == "nmap -sV 192.168.1.100"
        assert host.command_outputs[0]['output'] == "Starting Nmap..."


class TestHostResultMarkdown:
    """Tests for Markdown generation."""

    def test_to_markdown_basic(self):
        """Test basic Markdown generation."""
        host = HostResult("192.168.1.100", hostname="server1.local")
        markdown = host.to_markdown()

        assert "## Host: 192.168.1.100" in markdown
        assert "192.168.1.100" in markdown
        assert "server1.local" in markdown
        assert "### Verified Information" in markdown

    def test_to_markdown_with_services(self):
        """Test Markdown generation with services."""
        host = HostResult("192.168.1.100")
        host.add_service("HTTP", 80, "TCP")
        markdown = host.to_markdown()

        assert "HTTP" in markdown
        assert "80" in markdown
