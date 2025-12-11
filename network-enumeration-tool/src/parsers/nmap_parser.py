import re

class NmapParser:
    def __init__(self, nmap_output):
        self.nmap_output = nmap_output
        self.hosts = []

    def parse(self):
        host_blocks = self.nmap_output.strip().split('\n\n')
        for block in host_blocks:
            host_info = self._parse_host_block(block)
            if host_info:
                self.hosts.append(host_info)

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