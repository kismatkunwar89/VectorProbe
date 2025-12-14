import os
from datetime import datetime


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

    # Domain info
    domain = smb_data.get("domain")
    if domain:
        output += f"**Domain:** {domain}\n\n"

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
        # Extract subnet (first 3 octets)
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

            # Format services (show first 3, truncate if more)
            if services:
                service_str = ', '.join(services[:3])
                if len(services) > 3:
                    service_str += f"... (+{len(services) - 3})"
                status = "🟢 Online"
            else:
                service_str = "None"
                status = "🔴 Offline"

            output += f"| {ip} | {hostname} | {os_type} | {service_str} | {status} |\n"

        output += "\n"

    return output


def generate_report(enumeration_results, output_file, smb_results=None, command_outputs=None):
    """
    Generates a Markdown report based on the enumeration results.

    Args:
        enumeration_results (dict): A dictionary containing enumeration results for each host.
        output_file (str): The path to the output file where the report will be saved.
        smb_results (dict): Optional SMB enumeration results keyed by IP address.
        command_outputs (list): Optional list of executed commands and their outputs.
    """
    with open(output_file, 'w') as file:
        # Write header
        file.write("# Network Enumeration Report\n\n")
        file.write(
            f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

        # Write summary
        file.write("## Summary\n\n")
        file.write(f"- **Total Hosts:** {len(enumeration_results)}\n")
        file.write(f"- **Scan Type:** Masscan + Nmap\n")
        if smb_results:
            file.write(f"- **SMB Enumeration:** Enabled\n")
        file.write("\n")

        # Write network topology
        if enumeration_results:
            topology_section = format_topology_section(enumeration_results)
            file.write(topology_section)

        # Write detailed host information
        file.write("## Discovered Hosts\n\n")

        for host_ip, result in enumeration_results.items():
            file.write(f"### Host: {host_ip}\n\n")

            # Basic info
            file.write("#### Basic Information\n\n")
            file.write("| Property | Value |\n")
            file.write("|----------|-------|\n")
            file.write(f"| IP Address | {result.get('ip_address', 'N/A')} |\n")
            file.write(f"| Hostname | {result.get('hostname', 'Unknown')} |\n")
            file.write(f"| Domain | {result.get('domain', 'N/A')} |\n")
            file.write(f"| OS Type | {result.get('os_type', 'Unknown')} |\n\n")

            # Services
            file.write("#### Active Services\n\n")
            services = result.get('services', [])
            if services:
                file.write("| Service |\n")
                file.write("|----------|\n")
                for service in services:
                    file.write(f"| {service} |\n")
            else:
                file.write("No services detected.\n")
            file.write("\n")

            # SMB results if available
            if smb_results and host_ip in smb_results:
                smb_section = format_smb_section(smb_results[host_ip])
                file.write(smb_section)

            # Unverified info
            unverified = result.get('unverified_info', [])
            if unverified:
                file.write("#### Unverified Information\n\n")
                for info in unverified:
                    file.write(f"- {info}\n")
                file.write("\n")

            file.write("---\n\n")

        # Command outputs section
        if command_outputs:
            file.write("## Command Outputs\n\n")
            file.write(
                "All commands executed during the enumeration process:\n\n")

            for idx, cmd_info in enumerate(command_outputs, 1):
                tool = cmd_info.get('tool', 'Unknown')
                command = cmd_info.get('command', '')
                output = cmd_info.get('output', '')
                target = cmd_info.get('target', '')

                # Write command info
                if target:
                    file.write(f"### {idx}. {tool} - Target: {target}\n\n")
                else:
                    file.write(f"### {idx}. {tool}\n\n")

                file.write(f"**Command:** `{command}`\n\n")
                file.write("**Output:**\n\n")
                file.write("```\n")
                # Limit output to 5000 chars per command
                file.write(output[:5000])
                if len(output) > 5000:
                    file.write(
                        f"\n... (output truncated, {len(output)} total characters) ...\n")
                file.write("\n```\n\n")

        # Footer
        file.write("## Notes\n\n")
        file.write(
            "This report was generated by VectorProbe Network Enumeration Tool.\n")
        file.write("For more information, see the project documentation.\n")
