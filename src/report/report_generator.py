import os
from collections import Counter
from datetime import datetime


def _normalize_service_entry(service):
    """Return a consistent structure for report rendering."""
    if isinstance(service, dict):
        port = service.get('port', '-')
        protocol = service.get('protocol', '-')
        name = service.get('service_name') or f"port-{port}"
        product = service.get('product')
        version = service.get('version')
        fingerprint = " ".join(
            [str(value).strip() for value in [product, version] if value])
        exploits = service.get('exploits') or []
    else:
        port = '-'
        protocol = '-'
        name = str(service)
        fingerprint = ''
        exploits = []

    protocol_str = str(protocol).lower()
    display = name
    if port not in (None, '-') and protocol_str:
        display = f"{name} ({port}/{protocol_str})"

    return {
        'name': name,
        'port': port if port is not None else '-',
        'protocol': protocol_str or '-',
        'fingerprint': fingerprint or 'Unknown',
        'exploits': exploits,
        'display': display,
        'exploit_summary': f"{len(exploits)} found" if exploits else 'None'
    }


def _service_display_list(services):
    entries = [_normalize_service_entry(s) for s in services]
    return [entry['display'] for entry in entries]


def _generate_scan_summary(enumeration_results):
    """Generates a cross-host summary of ports and operating systems."""
    if not enumeration_results:
        return ""

    port_counter = Counter()
    os_counter = Counter()

    for result in enumeration_results.values():
        os_type = result.get('os_type', 'Unknown')
        os_counter[os_type] += 1
        for service in result.get('services', []):
            if isinstance(service, dict) and 'port' in service:
                port_display = f"{service['port']}/{service.get('protocol', 'tcp')}"
                port_counter[port_display] += 1

    summary = "### Scan Summary\n\n"
    summary += f"A total of **{len(enumeration_results)}** hosts were discovered.\n\n"

    # Common Ports Table
    if port_counter:
        summary += "**Common Open Ports (Top 10):**\n\n"
        summary += "| Port/Protocol | Count |\n"
        summary += "|---------------|-------|\n"
        for port, count in port_counter.most_common(10):
            summary += f"| {port} | {count} |\n"
        summary += "\n"

    # Operating Systems Table
    if os_counter:
        summary += "**Discovered Operating Systems:**\n\n"
        summary += "| Operating System | Count |\n"
        summary += "|------------------|-------|\n"
        for os, count in os_counter.most_common():
            summary += f"| {os} | {count} |\n"
        summary += "\n"

    return summary


def _format_ad_section(smb_data, netbios_data):
    """Formats an Active Directory Information section from SMB and NetBIOS data."""
    if not smb_data and not netbios_data:
        return ""

    domain = smb_data.get('domain')
    workgroup = netbios_data.get('workgroup')
    domain_sid = smb_data.get('domain_sid')
    netbios_computer_name = None
    if netbios_data.get('names'):
        # Find the primary computer name
        for name in netbios_data['names']:
            if name.endswith('<00>'):
                netbios_computer_name = name.split('<')[0].strip()
                break

    shares = smb_data.get('shares', [])
    is_dc = any(share.get('name') in ('SYSVOL', 'NETLOGON') for share in shares)

    # Only render the section if we have meaningful AD-related info
    if not domain and not workgroup and not is_dc:
        return ""

    output = "#### Active Directory Information (Unauthenticated)\n\n"
    output += "| Attribute | Value |\n"
    output += "|-----------|-------|\n"
    if domain:
        output += f"| Domain | {domain} |\n"
    elif workgroup:
        output += f"| Workgroup | {workgroup} |\n"

    if netbios_computer_name:
        output += f"| NetBIOS Computer Name | {netbios_computer_name} |\n"

    if domain_sid:
        output += f"| Domain SID | {domain_sid} |\n"

    if is_dc:
        output += f"| Probable Role | **Domain Controller** (SYSVOL/NETLOGON shares detected) |\n"
    else:
        output += f"| Probable Role | Member Server / Workstation |\n"

    output += "\n"
    return output


def format_smb_section(smb_data):
    """
    Format SMB enumeration data as Markdown section.

    Args:
        smb_data (dict): SMB enumeration results with domain, users, shares, etc.

    Returns:
        str: Formatted Markdown section
    """
    if not smb_data:
        return ""

    output = "#### SMB Enumeration\n\n"

    # OS info
    os_info = smb_data.get("os_info")
    if os_info:
        output += f"**OS:** {os_info}\n\n"

    # Null session
    null_session = smb_data.get("null_session", False)
    output += f"**Null Sessions:** {'ALLOWED ⚠️' if null_session else 'Disabled'}\n\n"

    # Users
    users = smb_data.get("users", [])
    if users:
        output += "**Users:**\n"
        for user in users:
            output += f"- {user}\n"
        output += "\n"

    # Shares
    shares = smb_data.get("shares", [])
    if shares:
        output += "**Shares:**\n"
        output += "| Name | Type | Comment |\n"
        output += "|------|------|----------|\n"
        for share in shares:
            name = share.get("name", "?")
            share_type = share.get("type", "?")
            comment = share.get("comment", "")
            output += f"| {name} | {share_type} | {comment} |\n"
        output += "\n"

    # Groups
    groups = smb_data.get("groups", [])
    if groups:
        output += "**Groups:**\n"
        for group in groups:
            output += f"- {group}\n"
        output += "\n"

    return output


def format_topology_section(enumeration_results):
    """
    Format network topology as Markdown table organized by subnet.

    Args:
        enumeration_results (dict): Dictionary of host enumeration results.

    Returns:
        str: Formatted Markdown network topology section
    """
    if not enumeration_results:
        return ""

    output = "## Network Topology\n\n"

    # Group hosts by subnet
    subnets = {}
    for ip, data in enumeration_results.items():
        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        if subnet not in subnets:
            subnets[subnet] = []
        subnets[subnet].append((ip, data))

    # Render each subnet
    for subnet in sorted(subnets.keys()):
        output += f"### {subnet}\n\n"
        output += "| IP | Hostname | OS | Services | Status |\n"
        output += "|-------|----------|----|---------|---------|\n"

        for ip, data in sorted(subnets[subnet], key=lambda x: x[0]):
            os_type = data.get('os_type', 'Unknown')
            hostname = data.get('hostname', 'N/A')
            services = data.get('services', [])

            normalized_services = _service_display_list(services)
            if normalized_services:
                service_str = ', '.join(normalized_services[:3])
                if len(normalized_services) > 3:
                    service_str += f"... (+{len(normalized_services) - 3})"
                status = "🟢 Online"
            else:
                service_str = "None"
                status = "🔴 Offline"

            output += f"| {ip} | {hostname} | {os_type} | {service_str} | {status} |\n"

        output += "\n"

    return output


def generate_report(enumeration_results, output_file, smb_results=None, command_outputs=None, netbios_results=None):
    """
    Generates a Markdown report based on the enumeration results.

    Args:
        enumeration_results (dict): A dictionary containing enumeration results for each host.
        output_file (str): The path to the output file where the report will be saved.
        smb_results (dict): Optional SMB enumeration results keyed by IP address.
        command_outputs (list): Optional list of executed commands and their outputs.
        netbios_results (dict): Optional NetBIOS enumeration results keyed by IP address.
    """
    with open(output_file, 'w') as file:
        file.write("# Network Enumeration Report\n\n")
        file.write(f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

        file.write("## Summary\n\n")
        summary_section = _generate_scan_summary(enumeration_results)
        file.write(summary_section)

        if enumeration_results:
            topology_section = format_topology_section(enumeration_results)
            file.write(topology_section)

        file.write("## Discovered Hosts\n\n")

        for host_ip, result in enumeration_results.items():
            file.write(f"### Host: {host_ip}\n\n")

            # Section 1: Verified Information
            file.write("#### Verified Information\n\n")
            file.write("| Property | Value |\n")
            file.write("|----------|-------|\n")
            file.write(f"| IP Address | {result.get('ip_address', 'N/A')} |\n")
            file.write(f"| Hostname | {result.get('hostname', 'Unknown')} |\n")
            file.write(f"| OS Type | {result.get('os_type', 'Unknown')} |\n\n")

            host_smb_data = smb_results.get(host_ip, {}) if smb_results else {}
            host_netbios_data = netbios_results.get(host_ip, {}) if netbios_results else {}

            ad_section = _format_ad_section(host_smb_data, host_netbios_data)
            if ad_section:
                file.write(ad_section)

            services = result.get('services', [])
            normalized_services = [_normalize_service_entry(s) for s in services]
            if normalized_services:
                file.write("**Active Services:**\n\n")
                file.write("| Port | Protocol | Service | Fingerprint | Exploits |\n")
                file.write("|------|----------|---------|-------------|----------|\n")
                for service in normalized_services:
                    file.write(
                        f"| {service['port']} | {service['protocol']} | {service['name']} | {service['fingerprint']} | {service['exploit_summary']} |\n")
                file.write("\n")

            # Windows-Specific Info (SMB/NetBIOS)
            if host_smb_data:
                file.write(format_smb_section(host_smb_data))
            if host_netbios_data and any(host_netbios_data.values()):
                file.write("#### NetBIOS Enumeration\n\n")
                if host_netbios_data.get('names'):
                    file.write("**NetBIOS Names:**\n")
                    for name in host_netbios_data['names']:
                        file.write(f"- {name}\n")
                    file.write("\n")

            # Section 2: Unverified Information
            file.write("#### Unverified Information\n\n")
            unverified = result.get('unverified_info', [])
            if unverified:
                for info in unverified:
                    file.write(f"- {info}\n")
            else:
                file.write("No unverified information to display.\n")
            file.write("\n")
            
            # Potential Exploits subsection
            displayed_exploits = set()
            exploits_output = ""
            for service in normalized_services:
                exploits = service['exploits']
                if not exploits:
                    continue
                
                unique_exploits = []
                for exploit in exploits:
                    edb_id = exploit.get('edb_id')
                    exploit_key = edb_id if edb_id else exploit.get('path')
                    if exploit_key not in displayed_exploits:
                        unique_exploits.append(exploit)
                        displayed_exploits.add(exploit_key)

                if unique_exploits:
                    product = service.get('product') or service.get('service_name') or service['name']
                    port = service.get('port', '?')
                    exploits_output += f"**For Service '{product}' on port {port}:**\n"
                    for exploit in unique_exploits:
                        title = exploit.get('title') or 'Unnamed exploit'
                        edb_id = exploit.get('edb_id')
                        descriptor = f"- {title}" + (f" (EDB-{edb_id})" if edb_id else "")
                        exploits_output += f"{descriptor}\n"
                    exploits_output += "\n"
            
            if exploits_output:
                file.write("**Potential Vulnerabilities:**\n\n")
                file.write(exploits_output)

            # Section 3: Command Outputs
            file.write("#### Command Outputs\n\n")
            host_commands = [cmd for cmd in (command_outputs or []) if cmd.get('target') == host_ip]
            if host_commands:
                for cmd_info in host_commands:
                    file.write(f"**Command:** `{cmd_info.get('command', '')}`\n")
                    file.write("```\n")
                    output = cmd_info.get('output', '')
                    file.write(output[:5000])
                    if len(output) > 5000:
                        file.write(f"\n... (output truncated) ...\n")
                    file.write("```\n\n")
            else:
                file.write("No specific commands were run against this host.\n\n")

            file.write("---\n\n")

        # Footer
        file.write("## Notes\n\n")
        file.write("This report was generated by VectorProbe Network Enumeration Tool.\n")
        file.write("For more information, see the project documentation.\n")
