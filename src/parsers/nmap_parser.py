import re
import logging

logger = logging.getLogger(__name__)


class NmapParser:
    def __init__(self, nmap_output):
        self.nmap_output = nmap_output
        self.hosts = []

    def parse(self):
        """Parse both real Nmap output and custom format"""
        # Prefer the real Nmap parser whenever we see genuine output
        # (identified by the "Nmap scan report for" banner).
        if 'Nmap scan report for' in self.nmap_output:
            logger.info("[PARSER] Detected REAL NMAP format")
            self._parse_real_nmap_format()
        elif 'Host:' in self.nmap_output:
            logger.info("[PARSER] Detected CUSTOM format")
            self._parse_custom_format()
        else:
            # Default to the real parser when unsure so we still harvest data
            logger.info("[PARSER] Defaulting to REAL NMAP format")
            self._parse_real_nmap_format()
        logger.info(f"[PARSER] Total hosts found: {len(self.hosts)}")

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
        logger.info(f"[PARSER] Processing {len(lines)} lines of Nmap output")
        logger.info(f"[PARSER] First 200 chars of output:\n{self.nmap_output[:200]}")

        current_host = None

        for i, raw_line in enumerate(lines):
            line = raw_line.rstrip('\n')
            stripped = line.strip()

            # Skip empty lines and comment lines
            if not stripped or stripped.startswith('#'):
                logger.debug(
                    f"[PARSER] Line {i}: SKIPPED (empty/comment): {line[:60]}")
                continue

            # Detect host line: "Nmap scan report for 192.168.1.1"
            if 'scan report for' in stripped.lower():
                logger.info(f"[PARSER] *** FOUND HOST LINE at {i}: {stripped[:80]}")
                if current_host is not None and current_host.get('host'):
                    self.hosts.append(current_host)
                    logger.info(
                        f"[PARSER] Added host: {current_host['host']} with {len(current_host['ports'])} ports")

                # Extract IP
                match = re.search(r'[Nn]map scan report for\s+(.+)', stripped)
                if match:
                    host_text = match.group(1).strip()
                    ip_value = None

                    # Handle "hostname (IP)" output
                    if host_text.endswith(')') and '(' in host_text:
                        ip_candidate = host_text[host_text.rfind('(') + 1:-1]
                        if re.fullmatch(r'[0-9a-fA-F:.]+', ip_candidate):
                            ip_value = ip_candidate
                            host_text = ip_candidate

                    elif re.fullmatch(r'[0-9a-fA-F:.]+', host_text):
                        ip_value = host_text

                    current_host = {
                        'host': host_text,
                        'ip': ip_value or host_text,
                        'ports': [],
                        'os': 'Unknown'
                    }
                    logger.info(f"[PARSER] Found host: {current_host['host']}")

                continue

            # Skip other Nmap header lines (only after host detection)
            if any(stripped.lower().startswith(skip.lower()) for skip in ['Starting Nmap', 'Nmap done', 'Not shown:', 'Host is up', 'MAC Address:',
                                                                          'Network Distance:', 'No exact OS', 'OS and Service', 'TCP/IP fingerprint:',
                                                                          'OS:', 'SEQ(', 'OPS(', 'WIN(', 'ECN(', 'T1(', 'T2(', 'T3(', 'T4(', 'T5(',
                                                                          'T6(', 'T7(', 'U1(', 'IE(']):
                logger.debug(
                    f"[PARSER] Line {i}: SKIPPED (header): {line[:60]}")
                continue

            # Detect port lines: "22/tcp  open   ssh"
            # Port lines start with a digit (the port number)
            elif current_host and stripped and stripped[0].isdigit() and '/' in line and ('tcp' in line or 'udp' in line):
                parts = stripped.split()
                if len(parts) >= 2:
                    port_protocol = parts[0]  # e.g., "22/tcp"
                    state = parts[1]  # e.g., "open"
                    service = parts[2] if len(parts) > 2 else 'unknown'

                    logger.info(
                        f"[PARSER] ✓ PORT found on line {i}: {port_protocol} {state} {service}")

                    if state == 'open' or state == 'filtered':
                        current_host['ports'].append(
                            f"{port_protocol}/{state}/{service}")
                        logger.info(
                            f"[PARSER] ✓ Added port: {port_protocol}/{state}/{service}")

            # Skip lines starting with pipe (| from NSE scripts output)
            elif stripped.startswith('|'):
                logger.debug(f"[PARSER] Line {i}: SKIPPED (NSE script output)")
                continue

            # Detect OS line: "OS details: Linux 5.4" (case-insensitive)
            elif current_host and 'os details:' in stripped.lower():
                match = re.search(r'OS details:\s+(.+)', stripped)
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
