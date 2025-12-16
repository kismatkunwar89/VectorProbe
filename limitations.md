# Limitations and Edge Cases

This document outlines the limitations and edge cases encountered during the development of the network enumeration tool.

## 1. Network Discovery Limitations
- The tool may not discover hosts that are behind firewalls or are configured to not respond to ping requests.
- Some network configurations may prevent accurate detection of all active hosts.

## 2. OS Detection Limitations
- The operating system detection may not be accurate for hosts that employ advanced security measures or custom configurations.
- Certain operating systems may not be identifiable due to lack of response to probing techniques.

## 3. Service Enumeration Limitations
- The tool may not enumerate services running on hosts that have restrictive firewall rules.
- Some services may not provide sufficient information for accurate enumeration.

## 4. Performance Considerations
- Scanning large networks may take a significant amount of time and resources.
- The tool's performance may degrade with an increasing number of targets.

## 5. Error Handling
- The tool may not gracefully handle all edge cases, such as unexpected input formats or network timeouts.
- Users should be aware of potential exceptions that may arise during execution.

## 6. Dependency Issues
- The tool relies on external libraries (e.g., Nmap) which must be installed and properly configured on the host machine.
- Compatibility issues may arise with different versions of dependencies.

## 7. User Permissions
- The tool may require elevated permissions to perform certain operations, such as network scanning and service enumeration.

## 8. Ethical Considerations
- Users must ensure they have explicit permission to scan and enumerate networks and hosts to avoid legal repercussions.

## 9. Active Directory Enumeration Limitations

### Unauthenticated Scope
All AD enumeration is performed without credentials using:
- **LDAP Base DSE anonymous queries** (RFC 4512 compliant)
- **SMB security mode detection** via Nmap NSE scripts
- **NetBIOS role identification** using `nmblookup`

This approach provides domain structure and DC identification but **does not include**:
- User or group enumeration (requires authentication)
- Password policy details (requires authentication)
- Detailed group memberships (requires authentication)
- Trust relationships (requires authentication)

### Tool Availability Constraints
AD enumeration requires external tools to be installed:
- **ldapsearch** (ldap-utils package): Required for LDAP Base DSE queries
- **dig** (dnsutils package): Required for DNS SRV record lookups
- **nmblookup** (samba-common-bin): Required for NetBIOS role detection
- **nmap NSE scripts**: ldap-rootdse and smb-security-mode

If any tool is unavailable, VectorProbe gracefully skips that enumeration method with a warning. This may result in reduced or incomplete AD information in the report.

### .local DNS Domain Interpretation
Domains ending in `.local` (e.g., `fnn.local`) are interpreted as:
- Active Directory internal domains (not publicly resolvable)
- Local network DNS domains (typically not accessible via external DNS servers)
- Triggers for DC-specific enumeration workflows

Inconsistent DNS resolution or missing internal DNS records may lead to incomplete domain or naming context information.

### LDAP Base DSE Visibility Requirements
LDAP Base DSE queries provide read-only access to:
- Domain naming context (e.g., `DC=fnn,DC=local`)
- Configuration naming context
- Schema naming context
- Forest and domain functional levels
- Supported LDAP capabilities and controls

**Note**: This is **read-only** and does not modify directory state. However, Base DSE visibility can vary based on server configuration and hardening policies. Some attributes may be hidden or restricted.

### DC-Only Targeting Explanation
Active Directory enumeration is performed **only on identified Domain Controllers**, detected via:
1. LDAP/LDAPS ports (389, 636, 3268, 3269)
2. Kerberos port (88)
3. SMB shares indicating DC role (SYSVOL, NETLOGON)
4. enum4linux-ng root/parent DC identification

**Windows workstations** receive standard Windows enumeration (SMB, NetBIOS) but not full AD context, as they typically don't expose LDAP services.

### Partial Enumeration Scenarios
If LDAP queries fail due to:
- Firewall blocking ports 389/636
- LDAP service disabled on scanned host
- Network segmentation preventing access

VectorProbe will:
- Fall back to SMB-based domain detection
- Document partial enumeration in the report
- Continue with remaining enumeration methods
- Not fail the entire scan

### LDAP Data Precedence Rules
When multiple sources provide overlapping AD information, the data precedence is:
1. **ldapsearch Base DSE output** (authoritative - direct LDAP query)
2. **nmap ldap-rootdse NSE script** (secondary confirmation)
3. **SMB domain information** (fallback when LDAP unavailable)

Reports clearly label the data source to indicate origin and reliability level.


This document will be updated as new limitations or edge cases are discovered during further testing and validation.