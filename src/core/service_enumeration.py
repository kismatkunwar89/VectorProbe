import subprocess
import socket
from typing import List, Dict, Any

def enumerate_services(host: str) -> Dict[str, Any]:
    """
    Enumerate services running on a given host.

    Args:
        host (str): The IP address or hostname of the target host.

    Returns:
        Dict[str, Any]: A dictionary containing service information.
    """
    services = {}
    try:
        # Example command to use for service enumeration (using nmap)
        command = ["nmap", "-sV", host]
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Process the output to extract service information
        services['host'] = host
        services['output'] = result.stdout

        # Here you can add more parsing logic to extract specific service details
        # For now, we just return the raw output
    except subprocess.CalledProcessError as e:
        services['error'] = str(e)
    except Exception as e:
        services['error'] = f"An unexpected error occurred: {str(e)}"

    return services

def check_port(host: str, port: int) -> bool:
    """
    Check if a specific port is open on the given host.

    Args:
        host (str): The IP address or hostname of the target host.
        port (int): The port number to check.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((host, port))
        return result == 0