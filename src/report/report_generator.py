import os
from datetime import datetime

def generate_report(enumeration_results, output_file):
    """
    Generates a Markdown report based on the enumeration results.

    Args:
        enumeration_results (dict): A dictionary containing enumeration results for each host.
        output_file (str): The path to the output file where the report will be saved.
    """
    with open(output_file, 'w') as file:
        file.write("# Network Enumeration Report\n")
        file.write(f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

        for host, result in enumeration_results.items():
            file.write(f"## Host: {host}\n")
            file.write("### Verified Information\n")
            file.write("| IP Address | Hostname | Domain | Active Services | Operating System |\n")
            file.write("|------------|----------|--------|----------------|------------------|\n")
            file.write(f"| {result['ip_address']} | {result['hostname']} | {result.get('domain', 'N/A')} | {', '.join(result['services'])} | {result['os_type']} |\n\n")

            file.write("### Unverified Information\n")
            file.write(f"{result.get('unverified_info', 'N/A')}\n\n")

            file.write("### Command Outputs\n")
            for command, output in result['command_outputs'].items():
                file.write(f"**Command:** `{command}`\n")
                file.write("