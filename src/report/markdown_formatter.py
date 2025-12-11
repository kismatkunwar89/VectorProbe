class MarkdownFormatter:
    def __init__(self):
        pass

    def format_verified_info(self, host_info):
        """Format verified information into a Markdown table."""
        table_header = "| IP Address | Hostname | Domain | Active Services | OS Type | Windows Info |\n"
        table_header += "|------------|----------|--------|-----------------|---------|---------------|\n"
        table_rows = ""
        
        for service in host_info['active_services']:
            table_rows += f"| {host_info['ip_address']} | {host_info['hostname']} | {host_info.get('domain', 'N/A')} | {service['name']} (Port: {service['port']}, Protocol: {service['protocol']}) | {host_info['os_type']} | {host_info.get('windows_info', 'N/A')} |\n"
        
        return table_header + table_rows

    def format_unverified_info(self, unverified_info):
        """Format unverified information into a Markdown section."""
        section = "## Unverified Information\n"
        for info in unverified_info:
            section += f"- {info}\n"
        return section

    def format_command_outputs(self, command_outputs):
        """Format command outputs into a Markdown section."""
        section = "## Command Outputs\n"
        for command, output in command_outputs.items():
            section += f"**Command:** `{command}`\n