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

## 9. Active Directory / LDAP Limitations

- **Tool availability:** Active Directory enumeration depends on required system utilities such as `ldapsearch`, DNS tools, and SMB helpers. Missing tools will result in reduced or skipped AD-related output.
- **Unauthenticated LDAP access:** Many LDAP attributes are restricted without credentials. As a result, unauthenticated enumeration may return partial or limited domain information.
- **Domain Controller targeting:** Best results are obtained when scanning a Domain Controller. Non-DC Windows hosts may not expose LDAP services and will not return full Active Directory context.
- **Firewall and port restrictions:** If LDAP/LDAPS ports (389/636) or related services are blocked, AD discovery will be incomplete even if the host is part of a domain.
- **`.local` domain behavior:** `.local` Active Directory domains rely heavily on proper DNS configuration. Inconsistent DNS resolution may lead to incomplete domain or naming context information.
- **BaseDSE visibility:** RootDSE/BaseDSE attributes and naming contexts can vary based on server configuration and hardening. Some fields may be hidden or restricted.
- **Partial enumeration expectations:** Active Directory environments may return inconsistent results depending on network segmentation, permissions, and server policy.
- **Data precedence:** When multiple tools report overlapping LDAP/BaseDSE information, `ldapsearch` output should be treated as the primary data source, with other tools used only for secondary confirmation.


This document will be updated as new limitations or edge cases are discovered during further testing and validation.