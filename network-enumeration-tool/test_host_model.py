#!/usr/bin/env python3
"""
Quick test of the HostResult model to see if it works correctly.
"""

# Import our HostResult class
from src.models.host_result import HostResult

# Create a test host
print("Creating a test host...")
host = HostResult(
    ip_address="192.168.1.100",
    hostname="server1.example.com",
    os_type="Windows Server 2019"
)

# Add some services
print("Adding services...")
host.add_service("HTTP", 80, "TCP")
host.add_service("HTTPS", 443, "TCP")
host.add_service("SMB", 445, "TCP")

# Add Windows-specific info
print("Adding Windows info...")
host.set_windows_info(
    netbios_name="SERVER1",
    workgroup="WORKGROUP",
    smb_version="3.1.1"
)

# Add unverified information
print("Adding unverified info...")
host.add_unverified_info("Likely running IIS 10.0 based on HTTP headers")
host.add_unverified_info("OS version appears to be Windows Server 2019 or newer")

# Add command output
print("Adding command output...")
host.add_command_output(
    command="nmap -sV 192.168.1.100",
    output="""Starting Nmap 7.93
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
443/tcp open  https   Microsoft IIS httpd 10.0
445/tcp open  smb     Microsoft Windows SMB"""
)

# Generate markdown report
print("\n" + "="*60)
print("GENERATED MARKDOWN REPORT:")
print("="*60 + "\n")
print(host.to_markdown())
