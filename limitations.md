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

## External Dependencies
- Requires: `nmap`, `searchsploit`
- Optional: `enum4linux-ng`, `ldap-utils`, `dnsutils`, `samba-common-bin`
- Missing tools are skipped gracefully with warnings

## General
- Only IPv4 addresses supported (no IPv6)
- DNS resolution uses system-configured DNS servers
