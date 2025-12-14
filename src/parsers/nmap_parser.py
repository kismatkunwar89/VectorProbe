import re


class NmapParser:
    def __init__(self, nmap_output):
        self.nmap_output = nmap_output
        self.hosts = []

    def parse(self):
        """Parse both real Nmap output and custom format"""
        # Check if this is custom format (has "Host:" lines) or real Nmap output
        if 'Host:' in self.nmap_output and not 'Starting Nmap' in self.nmap_output:
            self._parse_custom_format()
        else:
            self._parse_real_nmap_format()

    def _parse_custom_format(self):
        """Parse custom simplified format (for backward compatibility with tests)"""
        host_blocks = self.nmap_output.strip().split('\n\n')
        for block in host_blocks:
            host_info = self._parse_host_block(block)
            if host_info and host_info.get('host'):
                self.hosts.append(host_info)

    def _parse_real_nmap_format(self):
        """Parse real Nmap normal output format (-oN -)"""
        lines = self.nmap_output.strip().split('\n')

        current_host = None

        for line in lines:
            # Skip empty lines and comment lines
            if not line.strip() or line.startswith('#') or line.startswith('Starting') or line.startswith('Nmap'):
                continue

            # Detect host line: "Nmap scan report for 192.168.1.1"
            if 'Nmap scan report for' in line:
                if current_host is not None and current_host.get('host'):
                    self.hosts.append(current_host)

                # Extract IP
                match = re.search(r'for\s+([0-9a-f:.]+)', line)
                if match:
                    current_host = {
                        'host': match.group(1),
                        'ports': [],
                        'os': 'Unknown'
                    }

            # Detect port lines: "22/tcp  open   ssh"
            elif current_host and '/' in line and ('tcp' in line or 'udp' in line):
                parts = line.split()
                if len(parts) >= 2:
                    port_protocol = parts[0]  # e.g., "22/tcp"
                    state = parts[1]  # e.g., "open"
                    service = parts[2] if len(parts) > 2 else 'unknown'

                    if state == 'open' or state == 'filtered':
                        current_host['ports'].append(
                            f"{port_protocol}/{state}/{service}")

            # Detect OS line: "OS details: Linux 5.4"
            elif current_host and 'OS details:' in line:
                match = re.search(r'OS details:\s+(.+)', line)
                if match:
                    current_host['os'] = match.group(1).strip()

        # Don't forget the last host
        if current_host is not None and current_host.get('host'):
            self.hosts.append(current_host)

    def _parse_host_block(self, block):
        host_info = {}
        lines = block.splitlines()
        for line in lines:
            if line.startswith('Host:'):
                host_info['host'] = self._extract_host(line)
            elif line.startswith('Ports:'):
                host_info['ports'] = self._extract_ports(line)
            elif line.startswith('OS details:'):
                host_info['os'] = self._extract_os(line)
        return host_info

    def _extract_host(self, line):
        match = re.search(r'Host:\s+(\S+)', line)
        return match.group(1) if match else None

    def _extract_ports(self, line):
        match = re.search(r'Ports:\s+(.+)', line)
        return match.group(1).split(', ') if match else []

    def _extract_os(self, line):
        match = re.search(r'OS details:\s+(.+)', line)
        return match.group(1) if match else None
