"""
Active Directory enumeration output parser.

Parses output from AD enumeration tools:
- LDAP RootDSE (nmap NSE)
- LDAP Base DSE (ldapsearch LDIF)
- SMB security mode
- NetBIOS role information
- DNS SRV records
- Kerberos information
"""

import re
from typing import Dict, List, Optional, Any

from src.utils.logger import get_logger

logger = get_logger()


class ADParser:
    """Parser for Active Directory enumeration tool outputs."""

    # Functional level mappings
    FUNCTIONAL_LEVELS = {
        0: "Windows 2000 Mixed",
        1: "Windows Server 2003 Interim",
        2: "Windows Server 2003",
        3: "Windows Server 2008",
        4: "Windows Server 2008 R2",
        5: "Windows Server 2012",
        6: "Windows Server 2012 R2",
        7: "Windows Server 2016",
        10: "Windows Server 2025"
    }

    def parse_ldap_rootdse(self, output: str) -> Dict[str, Any]:
        """
        Parse Nmap ldap-rootdse NSE script output.

        Args:
            output: Raw nmap ldap-rootdse output

        Returns:
            Dictionary with extracted LDAP RootDSE information
        """
        if not output or not output.strip():
            return self._empty_ldap_dict()

        result = {
            "_source": "nmap",
            "namingContexts": [],
            "defaultNamingContext": None,
            "schemaNamingContext": None,
            "configurationNamingContext": None,
            "rootDomainNamingContext": None,
            "supportedLDAPVersion": [],
            "supportedSASLMechanisms": [],
            "supportedCapabilities": [],
            "dnsHostName": None,
            "serverName": None,
            "ldapServiceName": None,
            "isGlobalCatalogReady": None,
            "isSynchronized": None,
            "domainFunctionality": None,
            "forestFunctionality": None,
            "domainControllerFunctionality": None,
            "highestCommittedUSN": None
        }

        # Extract multi-value fields (namingContexts)
        for match in re.finditer(r'namingContexts:\s*(.+)', output):
            context = match.group(1).strip()
            if context and context not in result["namingContexts"]:
                result["namingContexts"].append(context)

        # Extract single-value fields
        patterns = {
            "defaultNamingContext": r'defaultNamingContext:\s*(.+)',
            "schemaNamingContext": r'schemaNamingContext:\s*(.+)',
            "configurationNamingContext": r'configurationNamingContext:\s*(.+)',
            "rootDomainNamingContext": r'rootDomainNamingContext:\s*(.+)',
            "dnsHostName": r'dnsHostName:\s*(.+)',
            "serverName": r'serverName:\s*(.+)',
            "ldapServiceName": r'ldapServiceName:\s*(.+)',
            "isGlobalCatalogReady": r'isGlobalCatalogReady:\s*(.+)',
            "isSynchronized": r'isSynchronized:\s*(.+)',
            "highestCommittedUSN": r'highestCommittedUSN:\s*(\d+)'
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                result[field] = match.group(1).strip()

        # Extract functional levels (integers)
        for level_field in ["domainFunctionality", "forestFunctionality", "domainControllerFunctionality"]:
            match = re.search(rf'{level_field}:\s*(\d+)', output)
            if match:
                result[level_field] = int(match.group(1))

        # Extract LDAP versions
        for match in re.finditer(r'supportedLDAPVersion:\s*(\d+)', output):
            version = match.group(1).strip()
            if version not in result["supportedLDAPVersion"]:
                result["supportedLDAPVersion"].append(version)

        # Extract SASL mechanisms
        for match in re.finditer(r'supportedSASLMechanisms:\s*(.+)', output):
            mechanism = match.group(1).strip()
            if mechanism and mechanism not in result["supportedSASLMechanisms"]:
                result["supportedSASLMechanisms"].append(mechanism)

        # Extract capabilities
        for match in re.finditer(r'supportedCapabilities:\s*(.+)', output):
            capability = match.group(1).strip()
            if capability and capability not in result["supportedCapabilities"]:
                result["supportedCapabilities"].append(capability)

        return result

    def parse_ldap_basedse(self, output: str) -> Dict[str, Any]:
        """
        Parse ldapsearch LDIF output for Base DSE (authoritative source).

        Handles multi-line LDIF continuations (lines starting with space).

        Args:
            output: Raw ldapsearch LDIF output

        Returns:
            Dictionary with extracted LDAP Base DSE information
        """
        if not output or not output.strip():
            return self._empty_ldap_dict()

        result = {
            "_source": "ldapsearch",
            "namingContexts": [],
            "defaultNamingContext": None,
            "schemaNamingContext": None,
            "configurationNamingContext": None,
            "rootDomainNamingContext": None,
            "supportedLDAPVersion": [],
            "supportedSASLMechanisms": [],
            "supportedCapabilities": [],
            "dnsHostName": None,
            "serverName": None,
            "dsServiceName": None,
            "ldapServiceName": None,
            "isGlobalCatalogReady": None,
            "isSynchronized": None,
            "domainFunctionality": None,
            "forestFunctionality": None,
            "domainControllerFunctionality": None,
            "highestCommittedUSN": None,
            "site": None  # Extracted from serverName DN
        }

        # Parse LDIF with multi-line continuation support
        lines = output.split('\n')
        current_attr = None
        current_value = []

        for line in lines:
            # Skip comments and empty lines
            if line.startswith('#') or not line.strip():
                if current_attr:
                    self._process_ldif_attribute(
                        current_attr, ' '.join(current_value), result)
                    current_attr = None
                    current_value = []
                continue

            # Continuation line (starts with space)
            if line.startswith(' ') and current_attr:
                current_value.append(line[1:])  # Remove leading space
            else:
                # Process previous attribute if exists
                if current_attr:
                    self._process_ldif_attribute(
                        current_attr, ' '.join(current_value), result)

                # Parse new attribute
                if ':' in line:
                    attr, value = line.split(':', 1)
                    current_attr = attr.strip()
                    current_value = [value.strip()]
                else:
                    current_attr = None
                    current_value = []

        # Process last attribute
        if current_attr:
            self._process_ldif_attribute(
                current_attr, ' '.join(current_value), result)

        # Extract site from serverName DN
        if result["serverName"]:
            site_match = re.search(
                r'CN=([^,]+),CN=Sites', result["serverName"])
            if site_match:
                result["site"] = site_match.group(1)

        return result

    def _process_ldif_attribute(self, attr: str, value: str, result: Dict[str, Any]) -> None:
        """
        Process a single LDIF attribute and update result dictionary.

        Args:
            attr: Attribute name
            value: Attribute value (may be multi-line concatenated)
            result: Result dictionary to update
        """
        if not value:
            return

        # Multi-value attributes
        if attr == "namingContexts":
            if value not in result["namingContexts"]:
                result["namingContexts"].append(value)
        elif attr == "supportedLDAPVersion":
            if value not in result["supportedLDAPVersion"]:
                result["supportedLDAPVersion"].append(value)
        elif attr == "supportedSASLMechanisms":
            if value not in result["supportedSASLMechanisms"]:
                result["supportedSASLMechanisms"].append(value)
        elif attr == "supportedCapabilities":
            if value not in result["supportedCapabilities"]:
                result["supportedCapabilities"].append(value)
        # Functional levels (convert to int)
        elif attr in ["domainFunctionality", "forestFunctionality", "domainControllerFunctionality"]:
            try:
                result[attr] = int(value)
            except ValueError:
                result[attr] = value
        elif attr == "highestCommittedUSN":
            try:
                result[attr] = int(value)
            except ValueError:
                result[attr] = value
        # Single-value attributes
        elif attr in result and attr not in ["_source", "site"]:
            result[attr] = value

    def merge_ldap_data(self, basedse_dict: Dict[str, Any], rootdse_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge LDAP Base DSE and RootDSE data with Base DSE precedence.

        Args:
            basedse_dict: LDAP Base DSE data from ldapsearch (authoritative)
            rootdse_dict: LDAP RootDSE data from nmap (secondary)

        Returns:
            Merged dictionary with Base DSE values taking precedence
        """
        merged = basedse_dict.copy()
        merged["_merge_notes"] = []

        for key, rootdse_value in rootdse_dict.items():
            # Skip metadata fields
            if key.startswith("_"):
                continue

            basedse_value = basedse_dict.get(key)

            # If field only in rootdse, include it
            if basedse_value is None or (isinstance(basedse_value, list) and not basedse_value):
                merged[key] = rootdse_value
            # If values differ, log discrepancy (basedse wins)
            elif basedse_value != rootdse_value and rootdse_value:
                if isinstance(basedse_value, list) and isinstance(rootdse_value, list):
                    # For lists, check if they're different sets
                    if set(basedse_value) != set(rootdse_value):
                        logger.debug(
                            f"LDAP field '{key}' differs: basedse={basedse_value} (used), rootdse={rootdse_value} (discarded)")
                        merged["_merge_notes"].append(
                            f"{key}: values differ between sources")
                else:
                    logger.debug(
                        f"LDAP field '{key}' differs: basedse='{basedse_value}' (used), rootdse='{rootdse_value}' (discarded)")
                    merged["_merge_notes"].append(
                        f"{key}: values differ between sources")

        merged["_sources"] = "ldapsearch (authoritative), nmap (secondary)"
        return merged

    def parse_smb_security(self, output: str) -> Dict[str, Any]:
        """
        Parse Nmap smb-security-mode and smb2-security-mode output.

        Args:
            output: Raw nmap smb-security-mode output

        Returns:
            Dictionary with SMB security information
        """
        if not output or not output.strip():
            return {
                "account_used": None,
                "authentication_level": None,
                "challenge_response": None,
                "message_signing": None,
                "smb2_version": None,
                "smb2_message_signing": None,
                "signing_required": False,
                "interpretation": None
            }

        result = {
            "account_used": None,
            "authentication_level": None,
            "challenge_response": None,
            "message_signing": None,
            "smb2_version": None,
            "smb2_message_signing": None,
            "signing_required": False,
            "interpretation": None
        }

        # Parse SMB 1.0 security mode
        patterns = {
            "account_used": r'account_used:\s*(.+)',
            "authentication_level": r'authentication_level:\s*(.+)',
            "challenge_response": r'challenge_response:\s*(.+)',
            "message_signing": r'message_signing:\s*(.+)'
        }

        for field, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                result[field] = match.group(1).strip()

        # Parse SMB 2.0/3.0 security mode
        smb2_version_match = re.search(r'(\d+:\d+:\d+):', output)
        if smb2_version_match:
            result["smb2_version"] = smb2_version_match.group(1)

        smb2_signing_match = re.search(r'Message signing (.+)', output)
        if smb2_signing_match:
            result["smb2_message_signing"] = smb2_signing_match.group(
                1).strip()

        # Determine if signing is required
        if result["message_signing"]:
            msg_lower = result["message_signing"].lower()
            if "required" in msg_lower and "not required" not in msg_lower:
                result["signing_required"] = True
        if result["smb2_message_signing"]:
            smb2_lower = result["smb2_message_signing"].lower()
            if "required" in smb2_lower and "not required" not in smb2_lower:
                result["signing_required"] = True

        # Generate interpretation
        if result["signing_required"]:
            result["interpretation"] = "SMB signing is required, mitigating relay attacks"
        elif result["message_signing"] or result["smb2_message_signing"]:
            result["interpretation"] = "SMB signing is enabled but not required (potential relay attack risk)"
        else:
            result["interpretation"] = "SMB signing status could not be determined"

        return result

    def parse_netbios_role(self, output: str) -> Dict[str, Any]:
        """
        Parse nmblookup NetBIOS information.

        Args:
            output: Raw nmblookup -A output

        Returns:
            Dictionary with NetBIOS role information
        """
        if not output or not output.strip():
            return {
                "netbios_names": [],
                "domain": None,
                "computer_name": None,
                "is_dc": False,
                "is_domain_master": False,
                "mac_address": None,
                "groups": []
            }

        result = {
            "netbios_names": [],
            "domain": None,
            "computer_name": None,
            "is_dc": False,
            "is_domain_master": False,
            "mac_address": None,
            "groups": []
        }

        # Parse NetBIOS name table
        # Format: NAME <code> - <GROUP> B <ACTIVE>
        for match in re.finditer(r'^\s*(\S+)\s+<(\w+)>\s+-\s+(<GROUP>)?\s*(\w+)?\s*<(\w+)>', output, re.MULTILINE):
            name = match.group(1).strip()
            code = match.group(2).strip()
            is_group = match.group(3) is not None

            entry = {
                "name": name,
                "code": code,
                "is_group": is_group
            }
            result["netbios_names"].append(entry)

            # Identify DC by <1c> group (Domain Controllers)
            if code == "1c" and is_group:
                result["is_dc"] = True
                result["domain"] = name
                result["groups"].append("Domain Controllers <1c>")

            # Identify Domain Master Browser by <1b>
            if code == "1b":
                result["is_domain_master"] = True
                result["groups"].append("Domain Master Browser <1b>")

            # Extract computer name (<00> without GROUP)
            if code == "00" and not is_group:
                result["computer_name"] = name

            # Extract domain name (<00> with GROUP)
            if code == "00" and is_group and not result["domain"]:
                result["domain"] = name

        # Extract MAC address
        mac_match = re.search(
            r'MAC Address\s*=\s*([0-9A-F\-:]+)', output, re.IGNORECASE)
        if mac_match:
            result["mac_address"] = mac_match.group(1).strip()

        return result

    def parse_dns_srv(self, output: str) -> Dict[str, Any]:
        """
        Parse dig SRV record output.

        Args:
            output: Raw dig SRV output (combined LDAP and Kerberos)

        Returns:
            Dictionary with DNS SRV information and interpretation
        """
        if not output or not output.strip():
            return {
                "found": False,
                "is_local_domain": False,
                "records": [],
                "ldap_status": None,
                "kerberos_status": None,
                "interpretation": None
            }

        result = {
            "found": False,
            "is_local_domain": False,
            "records": [],
            "ldap_status": None,
            "kerberos_status": None,
            "interpretation": None
        }

        # Check for .local domain warning
        if ".local is reserved for Multicast DNS" in output or "mDNS" in output:
            result["is_local_domain"] = True

        # Check for NXDOMAIN status
        if "status: NXDOMAIN" in output:
            if result["is_local_domain"]:
                result[
                    "interpretation"] = "DNS SRV enumeration returned NXDOMAIN for .local domain (expected behavior when querying external DNS servers)"
            else:
                result["interpretation"] = "DNS SRV records not found (NXDOMAIN)"
            # Separate status for LDAP and Kerberos
            if "# LDAP" in output or "_ldap" in output:
                result["ldap_status"] = "NXDOMAIN"
            if "# Kerberos" in output or "_kerberos" in output:
                result["kerberos_status"] = "NXDOMAIN"
        else:
            # Parse SRV records if found
            for match in re.finditer(r'(\S+)\.\s+\d+\s+IN\s+SRV\s+\d+\s+\d+\s+(\d+)\s+(\S+)', output):
                record = {
                    "service": match.group(1),
                    "port": match.group(2),
                    "target": match.group(3)
                }
                result["records"].append(record)
                result["found"] = True

            if result["found"]:
                result["interpretation"] = f"Found {len(result['records'])} DNS SRV record(s)"
                result["ldap_status"] = "Found"
                result["kerberos_status"] = "Found"

        return result

    def parse_kerberos_info(self, output: str) -> Dict[str, Any]:
        """
        Parse Nmap krb5-enum-users output.

        Args:
            output: Raw nmap krb5-enum-users output

        Returns:
            Dictionary with Kerberos information
        """
        result = {
            "available": True,
            "realm": None,
            "kdc": None,
            "limitation": None
        }

        if not output or not output.strip():
            result["available"] = False
            result["limitation"] = "No output received"
            return result

        # Check for script unavailability
        if "not available" in output.lower() or "not found" in output.lower():
            result["available"] = False
            result["limitation"] = "Kerberos NSE script (krb5-enum-users) not available in this nmap installation"
            return result

        # Extract realm
        realm_match = re.search(r'Realm:\s*(\S+)', output, re.IGNORECASE)
        if realm_match:
            result["realm"] = realm_match.group(1).strip()

        # Extract KDC
        kdc_match = re.search(r'KDC:\s*(\S+)', output, re.IGNORECASE)
        if kdc_match:
            result["kdc"] = kdc_match.group(1).strip()

        return result

    def _empty_ldap_dict(self) -> Dict[str, Any]:
        """Return empty LDAP result dictionary."""
        return {
            "_source": None,
            "namingContexts": [],
            "defaultNamingContext": None,
            "schemaNamingContext": None,
            "configurationNamingContext": None,
            "rootDomainNamingContext": None,
            "supportedLDAPVersion": [],
            "supportedSASLMechanisms": [],
            "supportedCapabilities": [],
            "dnsHostName": None,
            "serverName": None,
            "ldapServiceName": None,
            "isGlobalCatalogReady": None,
            "isSynchronized": None,
            "domainFunctionality": None,
            "forestFunctionality": None,
            "domainControllerFunctionality": None,
            "highestCommittedUSN": None
        }

    def interpret_functional_level(self, level: Optional[int]) -> str:
        """
        Interpret numeric functional level to Windows version.

        Args:
            level: Numeric functional level

        Returns:
            Human-readable Windows version or "Unknown"
        """
        if level is None:
            return "Unknown"
        return self.FUNCTIONAL_LEVELS.get(level, f"Unknown (Level {level})")
