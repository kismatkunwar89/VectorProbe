# src/parsers/netbios_parser.py

def parse_netbios_output(output):
    """
    Parses the output from a NetBIOS enumeration command.

    Args:
        output (str): The raw output from the NetBIOS enumeration command.

    Returns:
        dict: A dictionary containing parsed NetBIOS information.
    """
    netbios_info = {}
    lines = output.splitlines()
    
    for line in lines:
        if line.strip():  # Skip empty lines
            parts = line.split()
            if len(parts) >= 2:
                netbios_info[parts[0]] = parts[1:]  # Store the rest of the line as a list

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