#!/usr/bin/env python3
"""
Test orchestration - Demonstrates complete workflow with fixture data.
This allows testing without real Masscan/Nmap tools.
"""

from parsers.masscan_parser import MasscanParser
from parsers.nmap_parser import NmapParser
from models.host_result import HostResult
from models.enumeration_result import EnumerationResult
from report.report_generator import generate_report
from datetime import datetime
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))


def test_orchestration():
    """Test complete orchestration with fixture data."""

    print("\n" + "="*70)
    print("VECTORPROBE ORCHESTRATION TEST")
    print("="*70)

    # ============================================================
    # STAGE 1: Load and parse Masscan fixture
    # ============================================================
    print("\n[*] STAGE 1: Parsing Masscan Output")
    print("-" * 70)

    with open('tests/fixtures/masscan_sample.txt', 'r') as f:
        masscan_output = f.read()

    masscan_parser = MasscanParser(masscan_output)
    masscan_hosts = masscan_parser.parse()

    print(f"[+] Masscan discovered {len(masscan_hosts)} hosts")
    for host_info in masscan_hosts:
        ip = host_info.get('ip', 'Unknown')
        services = host_info.get('services', [])
        port_count = len(services)
        if port_count > 0:
            ports = [str(s.get('port')) for s in services]
            print(
                f"    Host: {ip} → Ports: {', '.join(ports)} ({port_count} open)")
        else:
            print(f"    Host: {ip} → [No open ports]")

    # Extract IPs for Nmap scan
    discovered_ips = [h.get('ip') for h in masscan_hosts if h.get('ip')]
    print(f"[+] Will run Nmap on {len(discovered_ips)} discovered hosts")

    # ============================================================
    # STAGE 2: Load and parse Nmap fixture
    # ============================================================
    print("\n[*] STAGE 2: Parsing Nmap Output")
    print("-" * 70)

    with open('tests/fixtures/nmap_sample.txt', 'r') as f:
        nmap_output = f.read()

    nmap_parser = NmapParser(nmap_output)
    nmap_parser.parse()
    nmap_hosts = nmap_parser.hosts

    print(f"[+] Nmap discovered {len(nmap_hosts)} hosts")
    for host_data in nmap_hosts:
        ip = host_data.get('host', 'Unknown')
        os_info = host_data.get('os', 'Unknown OS')
        ports = host_data.get('ports', [])

        print(f"    Host: {ip}")
        print(f"      OS: {os_info}")
        print(f"      Services:")
        for port in ports:
            print(f"        └─ {port}")

    # ============================================================
    # STAGE 3: Populate HostResult models
    # ============================================================
    print("\n[*] STAGE 3: Populating Data Models")
    print("-" * 70)

    enumeration_result = EnumerationResult()

    for host_data in nmap_hosts:
        ip = host_data.get('host', 'Unknown')
        os_type = host_data.get('os', 'Unknown')
        ports = host_data.get('ports', [])

        # Create HostResult
        host = HostResult(ip_address=ip, os_type=os_type)

        # Add services
        for port_str in ports:
            parts = port_str.split('/')
            if len(parts) >= 3:
                port_num = int(parts[0])
                state = parts[1]
                protocol = parts[2]
                service_name = f"service-{port_num}"
                host.add_service(service_name, port_num, protocol)

        # Add to result
        enumeration_result.add_host(ip, {
            'ip_address': ip,
            'hostname': host.hostname,
            'domain': host.domain,
            'os_type': os_type,
            'services': [s['service_name'] for s in host.services],
            'unverified_info': host.unverified_info,
            'command_outputs': host.command_outputs
        })

        print(
            f"[+] Created HostResult for {ip} with {len(host.services)} services")

    # ============================================================
    # STAGE 4: Generate Report
    # ============================================================
    print("\n[*] STAGE 4: Generating Report")
    print("-" * 70)

    output_file = "test_orchestration_report.md"
    try:
        generate_report(enumeration_result.hosts, output_file)
        print(f"[✓] Report generated: {output_file}")

        # Show report preview
        with open(output_file, 'r') as f:
            report_content = f.read()

        print(f"\n[+] Report Preview (first 600 chars):")
        print("-" * 70)
        print(report_content[:600])
        print("...")
        print("-" * 70)

    except Exception as e:
        print(f"[!] Report generation failed: {e}")
        import traceback
        traceback.print_exc()

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "="*70)
    print("[✓] ORCHESTRATION TEST COMPLETE")
    print("="*70)
    print(f"  Masscan Hosts: {len(masscan_hosts)}")
    print(f"  Nmap Hosts: {len(nmap_hosts)}")
    print(f"  Data Models: {len(enumeration_result.hosts)}")
    print(f"  Report: {output_file}")
    print("="*70 + "\n")


if __name__ == "__main__":
    test_orchestration()
