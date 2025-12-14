#!/usr/bin/env python3
"""
Network Enumeration Tool - Main Entry Point

This is where the program starts. It sets up logging, parses command-line
arguments, and kicks off the enumeration process.
"""

import logging
import sys
from datetime import datetime
from utils.logger import setup_logging
from utils.banner import print_banner
from cli.argument_parser import parse_args
from handlers.nmap_handler import NmapHandler
from handlers.smb_handler import SMBHandler
from handlers.netbios_handler import NetBIOSHandler
from parsers.nmap_parser import NmapParser
from parsers.smb_parser import SMBParser
from parsers.netbios_parser import NetBIOSParser
from models.host_result import HostResult
from models.enumeration_result import EnumerationResult
from report.report_generator import generate_report
from core.host_discovery import parse_and_resolve_targets
from handlers.vulnerability_handler import VulnerabilityHandler
from parsers.vulnerability_parser import (
    parse_searchsploit_json,
    extract_search_keywords
)
from utils.query_builder import build_searchsploit_query

MAX_EXPLOITS_PER_SERVICE = 5


def extract_live_hosts(nmap_output: str) -> list:
    """Extract live host IPs from nmap -sn greppable output.

    Args:
        nmap_output: Raw nmap -sn -oG output

    Returns:
        List of live host IP addresses
    """
    live_hosts = []
    for line in nmap_output.split('\n'):
        if line.startswith('Host:') and 'Status: Up' in line:
            # Extract IP from "Host: 192.168.1.1 () Status: Up"
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1]
                live_hosts.append(ip)
    return live_hosts


def display_nmap_results(hosts_data):
    """Display formatted Nmap results."""
    print("\n" + "="*60)
    print("[*] STAGE 1: DEEP SCAN (Nmap)")
    print("="*60)
    if not hosts_data:
        print("[!] No hosts discovered")
        return

    for host_info in hosts_data:
        ip = host_info.get('ip') or host_info.get('host', 'Unknown')
        ports = host_info.get('services') or host_info.get('ports', [])
        os_info = host_info.get('os', 'Unknown OS')

        print(f"\n  Host: {ip}")
        if os_info and os_info != 'Unknown OS':
            print(f"    OS: {os_info}")

        if ports:
            print(f"    Services:")
            for port in ports:
                if isinstance(port, dict):
                    port_num = port.get('port', '?')
                    state = port.get('state', 'unknown')
                    protocol = port.get('protocol', 'tcp')
                    print(f"      └─ {port_num}/{protocol} ({state})")
                else:
                    print(f"      └─ {port}")
        else:
            print(f"    Services: [None detected]")


def populate_host_results(nmap_hosts):
    """Convert Nmap parser output to HostResult objects."""
    enumeration_result = EnumerationResult()
    vuln_handler = VulnerabilityHandler(timeout_sec=15)
    search_cache = {}
    searchsploit_available = True

    for host_data in nmap_hosts:
        ip = host_data.get('ip') or host_data.get('host')
        os_type = host_data.get('os', 'Unknown')
        hostname = host_data.get('hostname')
        domain = host_data.get('domain')

        # Create HostResult
        host = HostResult(
            ip_address=ip,
            hostname=hostname,
            domain=domain,
            os_type=os_type
        )

        # Add services from Nmap output
        ports = host_data.get('services') or host_data.get('ports', [])
        for port in ports:
            port_num = None
            protocol = 'tcp'
            state = None
            product = None
            version = None
            service_name = None

            if isinstance(port, dict):
                port_num = port.get('port')
                protocol = port.get('protocol', 'tcp')
                state = port.get('state')
                product = port.get('product') or port.get('service')
                version = port.get('version') or port.get('extrainfo')
                service_name = (
                    port.get('name')
                    or port.get('service')
                    or (f"port-{port_num}" if port_num else None)
                )
            else:
                parts = str(port).split('/')
                # Expect "22/tcp/open/ssh"
                if len(parts) >= 4:
                    port_num, protocol, state, service_name = parts[:4]
                elif len(parts) >= 3:
                    port_num, protocol, state = parts[:3]
                else:
                    continue

            if not port_num:
                continue

            try:
                port_int = int(str(port_num).strip())
            except (ValueError, TypeError):
                continue

            service_label = service_name or f"service-{port_int}"

            # Build search query from service label + fingerprint fields
            fingerprint = " ".join(
                [str(value).strip() for value in [product, version] if value])

            query_string = build_searchsploit_query(service_label, fingerprint)
            keyword_basis = " ".join(
                [value for value in [service_label, fingerprint] if value])
            keywords = extract_search_keywords(keyword_basis)

            should_lookup = bool(query_string and keywords)
            if should_lookup and not fingerprint and service_label:
                normalized_label = service_label.lower()
                unique_keywords = set(keywords)
                if len(unique_keywords) == 1 and normalized_label in unique_keywords:
                    should_lookup = False
            exploits = []
            if should_lookup and searchsploit_available:
                cache_key = (query_string.lower(), tuple(keywords))
                if cache_key in search_cache:
                    exploits = search_cache[cache_key]
                else:
                    try:
                        ss_result = vuln_handler.run_searchsploit_json(
                            query_string)
                        if ss_result.exit_code == 0:
                            exploits = parse_searchsploit_json(
                                ss_result.raw_json,
                                query=query_string,
                                keywords=keywords
                            )
                        search_cache[cache_key] = exploits
                    except RuntimeError:
                        searchsploit_available = False
                        search_cache[cache_key] = []
                    except Exception:
                        search_cache[cache_key] = []

            if exploits:
                exploits = exploits[:MAX_EXPLOITS_PER_SERVICE]

            host.add_service(
                service_name=service_label,
                port=port_int,
                protocol=protocol,
                state=state,
                product=product,
                version=version,
                exploits=exploits
            )

        # Add host to enumeration result
        enumeration_result.add_host(ip, {
            'ip_address': ip,
            'hostname': host.hostname,
            'domain': host.domain,
            'os_type': os_type,
            'services': host.services,
            'unverified_info': host.unverified_info,
            'command_outputs': host.command_outputs
        })

    return enumeration_result


def main():
    """
    Main function - the starting point of our program.

    This function:
    1. Displays the ASCII banner
    2. Sets up logging
    3. Parses command-line arguments
    4. Executes the scanning workflow (Host Discovery, then Nmap)
    5. Populates data models
    6. Generates report
    """
    # Display the ASCII art banner
    print_banner(version="1.0.0")

    # Set up logging (INFO level means we see INFO, WARNING, ERROR, CRITICAL)
    logger = setup_logging(logging.INFO)

    # Log initialization
    logger.info("Initialization complete - Ready for enumeration")

    # Parse command-line arguments
    args = parse_args()
    logger.info(
        f"Arguments parsed: targets={args.targets}, exclude={args.exclude}")

    nmap_targets = args.targets
    scan_mode = "standard"
    command_outputs = []  # Track all executed commands

    # ============================================================
    # STAGE 0: Target Resolution and Exclusion Processing
    # ============================================================
    logger.info("[*] Resolving targets and processing exclusions...")
    try:
        resolved_targets, dns_targets = parse_and_resolve_targets(
            targets=args.targets,
            exclude=args.exclude,
            no_prompt=args.no_prompt
        )

        logger.info(
            f"[+] Resolved {len(resolved_targets)} target hosts after exclusions")

        # Convert resolved targets back to comma-separated string for nmap
        if resolved_targets:
            resolved_ips = [target.ip for target in resolved_targets]
            nmap_targets = ",".join(resolved_ips)
            logger.info(f"[+] Final target list: {len(resolved_ips)} hosts")
        else:
            logger.warning(
                "[!] No targets remaining after exclusion processing")
            return

    except Exception as e:
        logger.error(f"[!] Target resolution error: {e}")
        logger.info("[*] Proceeding with raw targets (exclusions not applied)")
        nmap_targets = args.targets

    # ============================================================
    # STAGE 1: Host Discovery (Optimized Approach)
    # ============================================================
    live_hosts = []

    # Check if original targets had CIDR ranges that would benefit from host discovery
    has_cidr = "/" in args.targets
    # Also check if we have many resolved targets (indicating CIDR expansion)
    many_targets = len(nmap_targets.split(',')) > 10

    if has_cidr or many_targets:
        logger.info(
            "[*] CIDR range detected - performing host discovery first")
        try:
            nmap = NmapHandler(timeout_sec=300)

            logger.info(f"[*] Running host discovery on: {nmap_targets}")
            discovery_result = nmap.host_discovery(targets=nmap_targets)

            if discovery_result.exit_code == 0 and discovery_result.stdout:
                # Track command output
                command_outputs.append({
                    'tool': 'Nmap Host Discovery',
                    'command': discovery_result.command,
                    'output': discovery_result.stdout
                })

                # Extract live hosts
                live_hosts = extract_live_hosts(discovery_result.stdout)
                logger.info(
                    f"[+] Host discovery found {len(live_hosts)} live hosts")

                if live_hosts:
                    nmap_targets = ",".join(live_hosts)
                    logger.info(
                        f"[+] Narrowed scan scope to {len(live_hosts)} live hosts")
                    scan_mode = "host-discovery+nmap"
                else:
                    logger.warning(
                        "[!] No live hosts found - proceeding with original targets")

            elif discovery_result.stderr:
                logger.warning(
                    f"[!] Host discovery stderr: {discovery_result.stderr}")

        except Exception as e:
            logger.error(f"[!] Host discovery error: {e}")
            logger.info("[*] Proceeding with original target list")

    # ============================================================
    # STAGE 2: Deep Scan (Nmap)
    # ============================================================
    nmap_hosts = []
    try:
        logger.info(f"[*] Running Nmap scan on targets: {nmap_targets}")

        # Initialize Nmap handler
        nmap = NmapHandler(timeout_sec=600)

        # Run Nmap
        logger.info(f"[+] Starting Nmap scan...")
        result = nmap.scan_targets(targets=nmap_targets)

        logger.info(f"[+] Nmap exit code: {result.exit_code}")

        if result.exit_code == 0 and result.stdout:
            # Track command output
            command_outputs.append({
                'tool': 'Nmap',
                'command': result.command,
                'output': result.stdout
            })

            # Debug: Log first 500 chars of Nmap output
            logger.info(
                f"[DEBUG] Nmap stdout (first 500 chars):\n{result.stdout[:500]}")
            logger.info(
                f"[DEBUG] Nmap stdout length: {len(result.stdout)} chars")

            # Parse Nmap output
            parser = NmapParser(result.stdout)
            parser.parse()
            nmap_hosts = parser.hosts
            logger.info(
                f"[+] Nmap discovered {len(nmap_hosts)} hosts with services")
            logger.info(f"[DEBUG] Parser returned hosts: {nmap_hosts}")

            # Display Nmap results
            display_nmap_results(nmap_hosts)
        elif result.stderr:
            logger.warning(f"[!] Nmap stderr: {result.stderr}")

    except RuntimeError as e:
        logger.error(f"[!] Nmap error: {e}")
    except TimeoutError as e:
        logger.error(f"[!] Nmap timeout: {e}")

    # ============================================================
    # STAGE 3: Populate Data Models
    # ============================================================
    logger.info("[*] Populating data models from scan results...")
    enumeration_result = populate_host_results(nmap_hosts)
    logger.info(
        f"[+] Created data models for {len(enumeration_result.hosts)} hosts")

    # ============================================================
    # STAGE 3.5: SMB Enumeration (if port 445 detected)
    # ============================================================
    smb_results = {}
    smb_hosts = []

    # Identify hosts with SMB port 445
    for host_data in nmap_hosts:
        ports = host_data.get('services') or host_data.get('ports', [])
        for port in ports:
            if isinstance(port, dict) and port.get('port') == 445:
                ip = host_data.get('ip') or host_data.get('host')
                if ip:
                    smb_hosts.append(ip)
                break

    if smb_hosts:
        logger.info(f"[*] {len(smb_hosts)} hosts with SMB (port 445) detected")
        try:
            smb = SMBHandler(timeout_sec=120)
            for ip in smb_hosts:
                try:
                    logger.info(f"[*] Running SMB enumeration on {ip}...")
                    result = smb.enumerate_target(ip)
                    if result.exit_code == 0:
                        # Track command output
                        command_outputs.append({
                            'tool': 'Enum4linux-ng',
                            'command': result.command,
                            'output': result.stdout,
                            'target': ip
                        })

                        parser = SMBParser()
                        smb_results[ip] = parser.parse(result.stdout)
                        logger.info(f"[+] SMB enumeration successful for {ip}")
                    elif result.stderr:
                        logger.warning(
                            f"[!] SMB enumeration stderr for {ip}: {result.stderr}")
                except (RuntimeError, TimeoutError) as e:
                    logger.warning(f"[!] SMB enumeration failed for {ip}: {e}")
        except RuntimeError as e:
            logger.error(f"[!] SMB tool unavailable: {e}")
    else:
        logger.info("[*] No SMB targets detected (port 445 not found)")

    # ============================================================
    # STAGE 3.6: NetBIOS Enumeration (if port 139 detected)
    # ============================================================
    netbios_results = {}
    netbios_hosts = []

    # Identify hosts with NetBIOS port 139
    for host_data in nmap_hosts:
        ports = host_data.get('services') or host_data.get('ports', [])
        for port in ports:
            if isinstance(port, dict) and port.get('port') == 139:
                ip = host_data.get('ip') or host_data.get('host')
                if ip:
                    netbios_hosts.append(ip)
                break

    if netbios_hosts:
        logger.info(
            f"[*] {len(netbios_hosts)} hosts with NetBIOS (port 139) detected")
        for ip in netbios_hosts:
            try:
                logger.info(f"[*] Running NetBIOS enumeration on {ip}...")
                netbios = NetBIOSHandler(target=ip)
                output = netbios.enumerate_netbios()

                if output and output.strip():
                    # Track command output
                    command_outputs.append({
                        'tool': 'nmblookup',
                        'command': f'nmblookup -M {ip}',
                        'output': output,
                        'target': ip
                    })

                    parser = NetBIOSParser()
                    netbios_results[ip] = parser.parse(output)
                    logger.info(f"[+] NetBIOS enumeration successful for {ip}")
                else:
                    logger.warning(
                        f"[!] NetBIOS enumeration returned empty output for {ip}")
            except Exception as e:
                logger.warning(f"[!] NetBIOS enumeration failed for {ip}: {e}")
    else:
        logger.info("[*] No NetBIOS targets detected (port 139 not found)")

    # ============================================================
    # STAGE 4: Generate Report
    # ============================================================
    logger.info("[*] Generating report...")

    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_file = f"vectorprobe_report_{timestamp}.md"

    try:
        # Generate and save report
        generate_report(enumeration_result.hosts, output_file,
                        smb_results, command_outputs, netbios_results)
        logger.info(f"[+] Report saved to: {output_file}")

        # Display success message
        print("\n" + "="*60)
        print("[✓] SCAN COMPLETE")
        print("="*60)
        print(f"  Scan Mode: {scan_mode}")
        print(f"  Hosts Discovered: {len(enumeration_result.hosts)}")
        print(f"  Report: {output_file}")
        print("="*60 + "\n")

    except Exception as e:
        logger.error(f"[!] Report generation failed: {e}")

    logger.info("[✓] Enumeration workflow complete")


if __name__ == "__main__":
    main()
