import re
import logging

logger = logging.getLogger(__name__)


class NmapParser:
    def __init__(self, nmap_output):
        self.nmap_output = nmap_output
        self.hosts = []

    def parse(self):
        """Parse both real Nmap output and custom format"""
        output_lower = self.nmap_output.lower()

        if 'nmap scan report for' in output_lower:
            logger.info("[PARSER] Detected REAL NMAP format")
            self._parse_real_nmap_format()
        elif re.search(r'^\s*Host:', self.nmap_output, re.MULTILINE):
            logger.info("[PARSER] Detected CUSTOM format")
            self._parse_custom_format()
        else:
            logger.info("[PARSER] Unable to auto-detect format, defaulting to REAL NMAP parser")
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
        logger.info(
            f"[PARSER] First 200 chars of output:\n{self.nmap_output[:200]}")

        current_host = None
        nse_lines = []  # Collect NSE script output for metadata extraction

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
                logger.info(
                    f"[PARSER] *** FOUND HOST LINE at {i}: {stripped[:80]}")
                if current_host is not None and current_host.get('host'):
                    # Extract metadata from NSE scripts before saving host
                    self._extract_and_apply_metadata(current_host, nse_lines)
                    self.hosts.append(current_host)
                    logger.info(
                        f"[PARSER] Added host: {current_host['host']} with {len(current_host['ports'])} ports")

                # Reset NSE lines for new host
                nse_lines = []

                # Extract IP
                match = re.search(r'[Nn]map scan report for\s+(.+)', stripped)
                if match:
                    host_text = match.group(1).strip()
                    logger.info(f"[PARSER] Extracted host text: '{host_text}'")
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
                        'services': [],
                        'os': 'Unknown',
                        'hostname': None,
                        'domain': None
                    }
                    logger.info(f"[PARSER] Found host: {current_host['host']}")
                else:
                    logger.warning(
                        f"[PARSER] Failed to extract host from: {stripped[:80]}")

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
                parts = re.split(r'\s+', stripped, maxsplit=3)
                if len(parts) >= 2:
                    port_protocol = parts[0]  # e.g., "22/tcp"
                    state = parts[1]  # e.g., "open"
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version_info = parts[3] if len(parts) == 4 else ''

                    logger.info(
                        f"[PARSER] ✓ PORT found on line {i}: {port_protocol} {state} {service}")

                    if state.lower() in ('open', 'filtered'):
                        current_host['ports'].append(
                            f"{port_protocol}/{state}/{service}")
                        logger.info(
                            f"[PARSER] ✓ Added port: {port_protocol}/{state}/{service}")

                        service_entry = self._create_service_entry(
                            port_protocol,
                            state,
                            service,
                            version_info
                        )
                        if service_entry:
                            current_host.setdefault('services', [])
                            current_host['services'].append(service_entry)

            # Collect NSE script output (lines starting with |)
            elif stripped.startswith('|'):
                nse_lines.append(line)
                logger.debug(f"[PARSER] Line {i}: COLLECTED NSE script output")
                continue

            # Parse Service Info line for hostname
            elif current_host and 'service info:' in stripped.lower():
                match = re.search(r'Service Info:.*Host:\s+([^;]+)', stripped, re.IGNORECASE)
                if match and not current_host.get('hostname'):
                    current_host['hostname'] = match.group(1).strip()
                    logger.info(f"[PARSER] Extracted hostname from Service Info: {current_host['hostname']}")
                continue

            # Detect OS line: "OS details: Linux 5.4" (case-insensitive)
            elif current_host and 'os details:' in stripped.lower():
                match = re.search(r'OS details:\s+(.+)', stripped)
                if match:
                    current_host['os'] = match.group(1).strip()

        # Don't forget the last host - extract metadata first
        if current_host is not None and current_host.get('host'):
            self._extract_and_apply_metadata(current_host, nse_lines)
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

    def _extract_nse_metadata(self, nse_lines):
        """
        Extract metadata from NSE script output generically.
        Looks for patterns like:
          |   field_name: field_value
          |_  field_name: field_value
        """
        metadata = {}

        for line in nse_lines:
            # Match indented key-value pairs in NSE output
            # Pattern: |   Key: Value or |_  Key: Value
            match = re.match(r'^\s*\|[_ ]\s+([A-Za-z_]+(?:[A-Za-z_\s]+)?):\s*(.+)$', line)
            if match:
                key = match.group(1).strip().lower().replace(' ', '_')
                value = match.group(2).strip()
                metadata[key] = value

        logger.debug(f"[PARSER] Extracted NSE metadata: {list(metadata.keys())}")
        return metadata

    def _extract_and_apply_metadata(self, host, nse_lines):
        """Extract metadata from NSE scripts and apply to host dictionary."""
        if not nse_lines:
            return

        nse_metadata = self._extract_nse_metadata(nse_lines)

        # Try multiple common field names for hostname (in order of preference)
        hostname_fields = ['netbios_computer_name', 'dns_computer_name',
                          'computer_name', 'hostname', 'fqdn']
        for field in hostname_fields:
            if field in nse_metadata and not host.get('hostname'):
                # Extract just the hostname part (before first dot)
                hostname_value = nse_metadata[field].split('.')[0]
                host['hostname'] = hostname_value
                logger.info(f"[PARSER] Extracted hostname from NSE ({field}): {hostname_value}")
                break

        # Try multiple common field names for domain
        domain_fields = ['dns_domain_name', 'domain_name', 'dns_tree_name', 'forest_name']
        for field in domain_fields:
            if field in nse_metadata and not host.get('domain'):
                host['domain'] = nse_metadata[field]
                logger.info(f"[PARSER] Extracted domain from NSE ({field}): {nse_metadata[field]}")
                break

    def _create_service_entry(self, port_protocol, state, service_name, version_info):
        """Return structured service metadata for a discovered port."""
        if '/' not in port_protocol:
            return None

        port_str, protocol = port_protocol.split('/', 1)
        protocol = protocol.lower().strip()
        port_num = None
        try:
            port_num = int(port_str)
        except ValueError:
            logger.debug(
                f"[PARSER] Unable to parse port number from: {port_protocol}")

        product = None
        version = None
        extrainfo = None
        if version_info:
            product, version, extrainfo = self._split_product_version(version_info)

        service_entry = {
            'port': port_num if port_num is not None else port_str,
            'protocol': protocol or 'tcp',
            'state': state.lower(),
            'name': service_name,
            'service': service_name,
            'service_name': service_name
        }

        if product:
            service_entry['product'] = product
        if version:
            service_entry['version'] = version
        if extrainfo:
            service_entry['extrainfo'] = extrainfo
        if version_info and not product:
            service_entry['product'] = version_info.strip()

        return service_entry

    def _split_product_version(self, version_info):
        """Split an Nmap VERSION column into (product, version, extrainfo)."""
        cleaned = version_info.strip()
        if not cleaned:
            return None, None, None

        match = re.search(r'(\d+(?:\.\d+)+|\d+)', cleaned)
        if match:
            product = cleaned[:match.start()].strip()
            version = match.group(1)
            extra = cleaned[match.end():].strip()
            extra = extra.strip('-:,() ')
            return product or None, version, extra or None

        return cleaned, None, None
