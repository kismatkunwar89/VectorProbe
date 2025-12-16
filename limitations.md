# Limitations

## Network Scanning
- Hosts behind firewalls or blocking ICMP may not be discovered
- Large CIDR ranges (e.g., /16) can take significant time to scan
- Requires root/sudo for SYN scans and OS detection

## OS Detection
- May be inaccurate for hardened systems or custom configurations
- Some hosts may not respond to fingerprinting probes

## Service Enumeration
- Services on non-standard ports may not be identified correctly
- Version detection depends on service banner responses

## Active Directory
- **Unauthenticated only**: Cannot enumerate users, groups, or password policies
- Requires `ldapsearch`, `dig`, and `nmblookup` to be installed
- `.local` domains cannot be resolved via external DNS servers
- DC detection relies on open ports (389, 636, 88) and SMB shares

## Vulnerability Correlation
- Searchsploit integration is a proof-of-concept implementation
- Query matching can produce false positives due to generic service names
- Can be improved with better filtering and CVE correlation

## Testing Coverage
- Tool tested on limited number of hosts due to time constraints
- Some edge cases may produce false positives or unexpected results
- Additional testing recommended for production use

## External Dependencies
- Requires: `nmap`, `searchsploit`
- Optional: `enum4linux-ng`, `ldap-utils`, `dnsutils`, `samba-common-bin`
- Missing tools are skipped gracefully with warnings

## General
- Only IPv4 addresses supported (no IPv6)
- DNS resolution uses system-configured DNS servers
