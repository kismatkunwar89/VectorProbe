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
    is_dc = any(share.get('name') in ('SYSVOL', 'NETLOGON')
                for share in shares)

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


def _format_ad_enumeration_section(ad_data, smb_data, netbios_data):
    """Format comprehensive Active Directory enumeration section for Domain Controllers."""
    if not ad_data:
        return ""

    from parsers.ad_parser import ADParser
    parser = ADParser()

    ldap = ad_data.get('ldap', {})
    smb_security = ad_data.get('smb_security', {})
    netbios = ad_data.get('netbios', {})
    dns_srv = ad_data.get('dns_srv', {})
    kerberos = ad_data.get('kerberos', {})
    limitations = ad_data.get('limitations', [])

    output = "#### Active Directory Enumeration (Unauthenticated)\n\n"

    # Subsection: AD Identity & Roles
    output += "**AD Identity & Roles**\n\n"
    output += "| Attribute | Value |\n"
    output += "|-----------|-------|\n"

    # Extract domain info
    domain_dns = None
    if ldap.get('defaultNamingContext'):
        dn = ldap['defaultNamingContext']
        dc_parts = [part.split('=')[1]
                    for part in dn.split(',') if part.startswith('DC=')]
        if dc_parts:
            domain_dns = '.'.join(dc_parts)

    domain_netbios = netbios.get('domain') or smb_data.get('domain')
    forest = None
    if ldap.get('rootDomainNamingContext'):
        dn = ldap['rootDomainNamingContext']
        dc_parts = [part.split('=')[1]
                    for part in dn.split(',') if part.startswith('DC=')]
        if dc_parts:
            forest = '.'.join(dc_parts)

    if domain_dns:
        output += f"| Domain (DNS) | {domain_dns} |\n"
    if domain_netbios:
        output += f"| Domain (NetBIOS) | {domain_netbios} |\n"
    if forest and forest != domain_dns:
        output += f"| Forest | {forest} |\n"

    dc_hostname = ldap.get('dnsHostName') or netbios.get('computer_name')
    if dc_hostname:
        output += f"| DC Hostname | {dc_hostname} |\n"

    dc_fqdn = ldap.get('dnsHostName')
    if dc_fqdn:
        output += f"| DC FQDN | {dc_fqdn} |\n"
        
    if not dc_hostname and dc_fqdn:
        dc_hostname = dc_fqdn.split('.')[0]

    site = ldap.get('site')
    if site:
        output += f"| AD Site | {site} |\n"

    gc_ready = ldap.get('isGlobalCatalogReady')
    if gc_ready:
        output += f"| Global Catalog | {gc_ready} |\n"

    # DC Role from NetBIOS
    dc_roles = []
    if netbios.get('is_dc'):
        dc_roles.append('Domain Controller')
    if netbios.get('is_domain_master'):
        dc_roles.append('Domain Master Browser')
    if dc_roles:
        output += f"| DC Role | {', '.join(dc_roles)} |\n"

    output += "\n"

    # Subsection: Functional Levels
    if ldap.get('domainFunctionality') is not None:
        output += "**Functional Levels**\n\n"
        output += "| Level Type | Value |\n"
        output += "|------------|-------|\n"

        domain_fl = ldap.get('domainFunctionality')
        if domain_fl is not None:
            interpreted = parser.interpret_functional_level(domain_fl)
            output += f"| Domain Functional Level | {domain_fl} ({interpreted}) |\n"

        forest_fl = ldap.get('forestFunctionality')
        if forest_fl is not None:
            interpreted = parser.interpret_functional_level(forest_fl)
            output += f"| Forest Functional Level | {forest_fl} ({interpreted}) |\n"

        dc_fl = ldap.get('domainControllerFunctionality')
        if dc_fl is not None:
            interpreted = parser.interpret_functional_level(dc_fl)
            output += f"| DC Functional Level | {dc_fl} ({interpreted}) |\n"

        output += "\n"

    # Subsection: Naming Contexts
    naming_contexts = ldap.get('namingContexts', [])
    if naming_contexts:
        output += "**Naming Contexts**\n\n"
        for ctx in naming_contexts:
            output += f"- {ctx}\n"
        output += "\n"

    # Subsection: LDAP Capabilities
    ldap_versions = ldap.get('supportedLDAPVersion', [])
    sasl_mechs = ldap.get('supportedSASLMechanisms', [])
    if ldap_versions or sasl_mechs:
        output += "**LDAP Capabilities**\n\n"
        if ldap_versions:
            output += f"- Supported LDAP Versions: {', '.join(ldap_versions)}\n"
        if sasl_mechs:
            output += f"- Supported SASL Mechanisms: {', '.join(sasl_mechs)}\n"

        sync_status = ldap.get('isSynchronized')
        if sync_status:
            output += f"- Synchronization Status: {sync_status}\n"

        output += "\n"

    # Subsection: SMB Security Posture
    if smb_security:
        output += "**SMB Security Posture**\n\n"

        msg_signing = smb_security.get('message_signing')
        smb2_signing = smb_security.get('smb2_message_signing')
        smb2_version = smb_security.get('smb2_version')

        if msg_signing:
            output += f"- SMB 1.0 Message Signing: {msg_signing}\n"
        if smb2_signing:
            version_str = f" (SMB {smb2_version})" if smb2_version else ""
            output += f"- SMB 2.0/3.0 Message Signing{version_str}: {smb2_signing}\n"

        auth_level = smb_security.get('authentication_level')
        if auth_level:
            output += f"- Authentication Level: {auth_level}\n"

        interpretation = smb_security.get('interpretation')
        if interpretation:
            output += f"\n*{interpretation}*\n"

        output += "\n"

    # Subsection: NetBIOS Information
    if netbios:
        output += "**NetBIOS Information**\n\n"

        computer = netbios.get('computer_name')
        if computer:
            output += f"- NetBIOS Computer Name: {computer}\n"

        domain = netbios.get('domain')
        if domain:
            output += f"- NetBIOS Domain: {domain}\n"

        groups = netbios.get('groups', [])
        if groups:
            output += f"- NetBIOS Groups: {', '.join(groups)}\n"

        mac = netbios.get('mac_address')
        if mac:
            output += f"- MAC Address: {mac}\n"

        output += "\n"

    # Subsection: DNS SRV Records (if attempted)
    if dns_srv and (dns_srv.get('found') or dns_srv.get('interpretation')):
        output += "**DNS SRV Records**\n\n"
        interpretation = dns_srv.get('interpretation')
        if interpretation:
            output += f"*{interpretation}*\n\n"

    # Footer with methodology
    output += "*All Active Directory information was obtained without authentication using LDAP Base DSE (authoritative), Nmap LDAP RootDSE (secondary), SMB security mode enumeration, NetBIOS role identification, and DNS SRV record queries.*\n\n"

    # Limitations note
    if limitations:
        output += "**Limitations:** "
        output += "Some enumeration steps could not be completed: "
        output += "; ".join(set(limitations))
        output += "\n\n"

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


def generate_report(enumeration_results, output_file, smb_results=None, command_outputs=None, netbios_results=None, ad_results=None):
    """
    Generates a Markdown report based on the enumeration results.

    Args:
        enumeration_results (dict): A dictionary containing enumeration results for each host.
        output_file (str): The path to the output file where the report will be saved.
        smb_results (dict): Optional SMB enumeration results keyed by IP address.
        command_outputs (list): Optional list of executed commands and their outputs.
        netbios_results (dict): Optional NetBIOS enumeration results keyed by IP address.
        ad_results (dict): Optional Active Directory enumeration results keyed by IP address.
    """
    with open(output_file, 'w') as file:
        file.write("# Network Enumeration Report\n\n")
        file.write(
            f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

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
            host_netbios_data = netbios_results.get(
                host_ip, {}) if netbios_results else {}
            host_ad_data = ad_results.get(host_ip, {}) if ad_results else {}

            # Show comprehensive AD section if we have full AD enumeration (DC-only)
            # Otherwise show basic AD section from SMB/NetBIOS
            if host_ad_data:
                ad_section = _format_ad_enumeration_section(
                    host_ad_data, host_smb_data, host_netbios_data)
                if ad_section:
                    file.write(ad_section)
            else:
                ad_section = _format_ad_section(
                    host_smb_data, host_netbios_data)
                if ad_section:
                    file.write(ad_section)

            services = result.get('services', [])
            normalized_services = [
                _normalize_service_entry(s) for s in services]
            if normalized_services:
                file.write("**Active Services:**\n\n")
                file.write(
                    "| Port | Protocol | Service | Fingerprint | Exploits |\n")
                file.write(
                    "|------|----------|---------|-------------|----------|\n")
                for service in normalized_services:
                    file.write(
                        f"| {service['port']} | {service['protocol']} | {service['name']} | {service['fingerprint']} | {service['exploit_summary']} |\n")
                file.write("\n")

            # Windows-Specific Info (SMB/NetBIOS)
            # Skip if already covered in comprehensive AD section
            if host_smb_data and not host_ad_data:
                file.write(format_smb_section(host_smb_data))
            elif host_smb_data and host_ad_data:
                # Show only additional SMB info not in AD section (users, groups)
                users = host_smb_data.get("users", [])
                groups = host_smb_data.get("groups", [])
                if users or groups:
                    file.write("#### Additional SMB Enumeration\n\n")
                    if users:
                        file.write("**Users:**\n")
                        for user in users:
                            file.write(f"- {user}\n")
                        file.write("\n")
                    if groups:
                        file.write("**Groups:**\n")
                        for group in groups:
                            file.write(f"- {group}\n")
                        file.write("\n")
            # NetBIOS section only if not a DC (non-DC Windows hosts)
            if host_netbios_data and any(host_netbios_data.values()) and not host_ad_data:
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
                    product = service.get('product') or service.get(
                        'service_name') or service['name']
                    port = service.get('port', '?')
                    exploits_output += f"**For Service '{product}' on port {port}:**\n"
                    for exploit in unique_exploits:
                        title = exploit.get('title') or 'Unnamed exploit'
                        edb_id = exploit.get('edb_id')
                        descriptor = f"- {title}" + \
                            (f" (EDB-{edb_id})" if edb_id else "")
                        exploits_output += f"{descriptor}\n"
                    exploits_output += "\n"

            if exploits_output:
                file.write("**Potential Vulnerabilities:**\n\n")
                file.write(exploits_output)

            # Section 3: Command Outputs
            file.write("#### Command Outputs\n\n")
            host_commands = [cmd for cmd in (
                command_outputs or []) if cmd.get('target') == host_ip]
            if host_commands:
                for cmd_info in host_commands:
                    file.write(
                        f"**Command:** `{cmd_info.get('command', '')}`\n")
                    file.write("```\n")
                    output = cmd_info.get('output', '')
                    file.write(output[:5000])
                    if len(output) > 5000:
                        file.write(f"\n... (output truncated) ...\n")
                    file.write("```\n\n")
            else:
                file.write(
                    "No specific commands were run against this host.\n\n")

            file.write("---\n\n")

        # Footer
        file.write("## Notes\n\n")
        file.write(
            "This report was generated by VectorProbe Network Enumeration Tool.\n")
        file.write("For more information, see the project documentation.\n")
