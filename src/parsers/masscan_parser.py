"""
masscan_parser.py

Responsible for:
- Parsing Masscan greppable format output (-oG)
- Extracting host and port information
- Converting output into structured data

NOTE:
- This does NOT execute Masscan (that's in src/handlers/).
- This module only PARSES Masscan output.
"""

import re
from typing import List, Dict, Optional


class MasscanParser:
    """
    Parse Masscan greppable format output.

    Masscan greppable format looks like:
        # masscan version 1.0.5; options: -p0-65535 --rate=1000000
        Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp, 3389/open/tcp
        Host: 192.168.1.101 Ports: 22/open/tcp, 23/open/tcp

    This parser extracts:
    - Host IP addresses
    - Open ports with protocol and state
    """

    def __init__(self, masscan_output: str):
        """
        Initialize the Masscan parser.

        Args:
            masscan_output: Raw output from Masscan in greppable format
        """
        self.masscan_output = masscan_output
        self.hosts: List[Dict] = []

    def parse(self) -> List[Dict]:
        """
        Parse the Masscan output and populate self.hosts.

        Returns:
            List of dicts with structure:
            {
                'host': '192.168.1.100',
                'ports': [
                    {'port': 80, 'state': 'open', 'protocol': 'tcp'},
                    {'port': 443, 'state': 'open', 'protocol': 'tcp'},
                ]
            }

        Note:
            - Skips comment lines (starting with '#')
            - Handles malformed lines gracefully
        """
        self.hosts = []

        if not self.masscan_output or not self.masscan_output.strip():
            return self.hosts

        for line in self.masscan_output.strip().split('\n'):
            # Skip empty lines and comments
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse each host line
            host_info = self._parse_host_line(line)
            if host_info:
                self.hosts.append(host_info)

        return self.hosts

    def _parse_host_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single Masscan host line.

        Format: "Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp"

        Args:
            line: A single line from Masscan output

        Returns:
            Dict with 'host' and 'ports' keys, or None if line is malformed
        """
        # Check if this is a host line
        if not line.startswith("Host:"):
            return None

        try:
            # Extract host IP using regex
            host_ip = self._parse_host(line)
            if not host_ip:
                return None

            # Extract ports string
            ports_match = re.search(r'Ports:\s*(.+)$', line)
            if not ports_match:
                # Host has no open ports
                return {
                    'host': host_ip,
                    'ports': []
                }

            ports_str = ports_match.group(1)
            ports = self._parse_ports(ports_str)

            return {
                'host': host_ip,
                'ports': ports
            }

        except Exception:
            # Gracefully handle malformed lines
            return None

    def _parse_host(self, line: str) -> Optional[str]:
        """
        Extract the host IP address from a host line.

        Args:
            line: A Masscan host line

        Returns:
            IP address string, or None if not found
        """
        match = re.search(r'Host:\s+(\S+)', line)
        if match:
            return match.group(1)
        return None

    def _parse_ports(self, ports_str: str) -> List[Dict]:
        """
        Extract port information from the Ports section.

        Format: "80/open/tcp, 443/open/tcp, 3389/open/tcp"
        Returns: [{'port': 80, 'state': 'open', 'protocol': 'tcp'}, ...]

        Args:
            ports_str: The Ports section as a string

        Returns:
            List of port dictionaries
        """
        ports = []

        if not ports_str or not ports_str.strip():
            return ports

        # Split by comma to get individual port entries
        port_entries = ports_str.split(',')

        for entry in port_entries:
            entry = entry.strip()
            if not entry:
                continue

            # Format: port/state/protocol
            # Example: 80/open/tcp
            parts = entry.split('/')
            if len(parts) >= 3:
                try:
                    port_num = int(parts[0].strip())
                    state = parts[1].strip()
                    protocol = parts[2].strip()

                    ports.append({
                        'port': port_num,
                        'state': state,
                        'protocol': protocol
                    })
                except (ValueError, IndexError):
                    # Skip malformed port entries
                    continue

        return ports


# ---------------------------------------------------------------------------
# Standalone testing (safe to delete later)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    """
    This is ONLY to test this file by itself.

    Run:
      python src/parsers/masscan_parser.py
    """

    # Example Masscan output (greppable format)
    sample_output = """# masscan version 1.0.5; options: -p0-65535 --rate=1000000
Host: 192.168.1.100 Ports: 80/open/tcp, 443/open/tcp, 3389/open/tcp
Host: 192.168.1.101 Ports: 22/open/tcp, 23/open/tcp
Host: 192.168.1.102 Ports: 
Host: 192.168.1.103 Ports: 8080/open/tcp
"""

    parser = MasscanParser(sample_output)
    hosts = parser.parse()

    print(f"Parsed {len(hosts)} hosts:\n")
    for host_info in hosts:
        print(f"Host: {host_info['host']}")
        print(f"  Ports ({len(host_info['ports'])} open):")
        for port in host_info['ports']:
            print(f"    {port['port']}/{port['state']}/{port['protocol']}")
        print()

    # Test edge cases
    print("\n--- Edge case tests ---")

    empty_output = ""
    parser_empty = MasscanParser(empty_output)
    print(f"Empty output: {parser_empty.parse()}")

    malformed_output = "This is not valid masscan output"
    parser_malformed = MasscanParser(malformed_output)
    print(f"Malformed output: {parser_malformed.parse()}")

    host_no_ports = "Host: 10.0.0.1 Ports: "
    parser_no_ports = MasscanParser(host_no_ports)
    result = parser_no_ports.parse()
    print(f"Host with no ports: {result}")
