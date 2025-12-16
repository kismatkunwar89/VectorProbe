# src/parsers/netbios_parser.py

class NetBIOSParser:
    """Parser for NetBIOS enumeration output (nmblookup)."""

    def parse(self, output: str) -> dict:
        """
        Parses the output from a NetBIOS enumeration command.

        Args:
            output (str): The raw output from the NetBIOS enumeration command.

        Returns:
            dict: A dictionary containing parsed NetBIOS information.
        """
        netbios_info = {
            'names': [],
            'addresses': [],
            'workgroup': None,
            'raw_output': output
        }

        lines = output.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse nmblookup output: "NAME <00> - <GROUP> IP_ADDR"
            # or "IP_ADDR NAME<00>"
            if '<' in line and '>' in line:
                parts = line.split()
                if len(parts) >= 1:
                    # Extract NetBIOS name
                    name = None
                    name_part = parts[0]
                    if '<' in name_part:
                        name = name_part.split('<')[0]
                        if name:
                            netbios_info['names'].append(name)

                    # Extract IP addresses
                    for part in parts:
                        if '.' in part and part.replace('.', '').isdigit():
                            if part not in netbios_info['addresses']:
                                netbios_info['addresses'].append(part)

                    # Check for workgroup indicator
                    if '<GROUP>' in line or '<00>' in line:
                        if name and not netbios_info['workgroup']:
                            netbios_info['workgroup'] = name

        return netbios_info


def format_netbios_info(netbios_info):
    """
    Formats the parsed NetBIOS information for display or reporting.

    Args:
        netbios_info (dict): The parsed NetBIOS information.

    Returns:
        str: A formatted string representation of the NetBIOS information.
    """
    formatted_info = []
    for name, details in netbios_info.items():
        formatted_info.append(f"Name: {name}, Details: {', '.join(details)}")

    return "\n".join(formatted_info)
