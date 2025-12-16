"""
Unit tests for Active Directory parser.

Tests cover:
- LDAP RootDSE parsing (Nmap NSE)
- LDAP Base DSE parsing (ldapsearch LDIF with multi-line continuations)
- LDAP data merging with Base DSE precedence
- SMB security mode parsing
- NetBIOS role identification
- DNS SRV record interpretation
- Kerberos information extraction
- Edge cases and error handling
"""

import pytest
from src.parsers.ad_parser import ADParser


@pytest.fixture
def ldap_rootdse_fixture():
    """Load LDAP RootDSE sample from nmap."""
    with open("tests/fixtures/ldap_rootdse_dc01.txt", "r") as f:
        return f.read()


@pytest.fixture
def ldap_basedse_fixture():
    """Load LDAP Base DSE sample from ldapsearch."""
    with open("tests/fixtures/ldap_basedse_dc01.txt", "r") as f:
        return f.read()


@pytest.fixture
def smb_security_dc_fixture():
    """Load SMB security mode sample for DC (signing required)."""
    with open("tests/fixtures/smb_security_dc01.txt", "r") as f:
        return f.read()


@pytest.fixture
def smb_security_workstation_fixture():
    """Load SMB security mode sample for workstation (signing not required)."""
    with open("tests/fixtures/smb_security_workstation.txt", "r") as f:
        return f.read()


@pytest.fixture
def netbios_dc_fixture():
    """Load NetBIOS sample for DC."""
    with open("tests/fixtures/netbios_dc01.txt", "r") as f:
        return f.read()


@pytest.fixture
def dns_srv_nxdomain_fixture():
    """Load DNS SRV NXDOMAIN sample."""
    with open("tests/fixtures/dns_srv_nxdomain.txt", "r") as f:
        return f.read()


@pytest.fixture
def dns_srv_found_fixture():
    """Load DNS SRV found records sample."""
    with open("tests/fixtures/dns_srv_found.txt", "r") as f:
        return f.read()


@pytest.fixture
def kerberos_unavailable_fixture():
    """Load Kerberos unavailable script sample."""
    with open("tests/fixtures/kerberos_unavailable.txt", "r") as f:
        return f.read()


class TestADParserLDAPRootDSE:
    """Test LDAP RootDSE parsing (Nmap NSE)."""

    def test_parse_naming_contexts(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        assert len(result["namingContexts"]) == 5
        assert "DC=fnn,DC=local" in result["namingContexts"]
        assert "CN=Configuration,DC=fnn,DC=local" in result["namingContexts"]
        assert "CN=Schema,CN=Configuration,DC=fnn,DC=local" in result["namingContexts"]
        assert "DC=ForestDnsZones,DC=fnn,DC=local" in result["namingContexts"]
        assert "DC=DomainDnsZones,DC=fnn,DC=local" in result["namingContexts"]

    def test_parse_default_naming_context(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)
        assert result["defaultNamingContext"] == "DC=fnn,DC=local"

    def test_parse_functional_levels(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        assert result["domainFunctionality"] == 7
        assert result["forestFunctionality"] == 7
        assert result["domainControllerFunctionality"] == 7

    def test_parse_global_catalog_ready(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)
        assert result["isGlobalCatalogReady"] == "TRUE"

    def test_parse_dns_hostname(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)
        assert result["dnsHostName"] == "FNN-DC01.fnn.local"

    def test_parse_server_name(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)
        assert "CN=FNN-DC01,CN=Servers,CN=Default-First-Site-Name" in result["serverName"]

    def test_parse_ldap_versions(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        assert "3" in result["supportedLDAPVersion"]
        assert "2" in result["supportedLDAPVersion"]
        assert len(result["supportedLDAPVersion"]) == 2

    def test_parse_sasl_mechanisms(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        assert "GSSAPI" in result["supportedSASLMechanisms"]
        assert "GSS-SPNEGO" in result["supportedSASLMechanisms"]
        assert "EXTERNAL" in result["supportedSASLMechanisms"]
        assert "DIGEST-MD5" in result["supportedSASLMechanisms"]
        assert len(result["supportedSASLMechanisms"]) == 4

    def test_parse_capabilities(self, ldap_rootdse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        assert len(result["supportedCapabilities"]) == 6
        assert "1.2.840.113556.1.4.800" in result["supportedCapabilities"]

    def test_parse_empty_input(self):
        parser = ADParser()
        result = parser.parse_ldap_rootdse("")

        assert result["_source"] is None
        assert result["namingContexts"] == []
        assert result["defaultNamingContext"] is None

    def test_parse_none_input(self):
        parser = ADParser()
        result = parser.parse_ldap_rootdse(None)

        assert result["_source"] is None
        assert result["namingContexts"] == []


class TestADParserLDAPBaseDSE:
    """Test LDAP Base DSE parsing (ldapsearch LDIF)."""

    def test_parse_multi_line_continuation(self, ldap_basedse_fixture):
        """Test parsing of LDIF multi-line attributes with leading spaces."""
        parser = ADParser()
        result = parser.parse_ldap_basedse(ldap_basedse_fixture)

        # dsServiceName and serverName have continuations
        assert "CN=NTDS Settings,CN=FNN-DC01" in result["dsServiceName"]
        assert "Default-First-Site" in result["dsServiceName"]
        assert "Default-First-Site" in result["serverName"]

    def test_parse_site_extraction(self, ldap_basedse_fixture):
        """Test extraction of AD site from serverName DN."""
        parser = ADParser()
        result = parser.parse_ldap_basedse(ldap_basedse_fixture)

        assert result["site"] == "Default-First-Site-Name"

    def test_parse_functional_levels_ldif(self, ldap_basedse_fixture):
        parser = ADParser()
        result = parser.parse_ldap_basedse(ldap_basedse_fixture)

        assert result["domainFunctionality"] == 7
        assert result["forestFunctionality"] == 7
        assert result["domainControllerFunctionality"] == 7

    def test_source_metadata(self, ldap_basedse_fixture):
        """Verify Base DSE has correct source metadata."""
        parser = ADParser()
        result = parser.parse_ldap_basedse(ldap_basedse_fixture)

        assert result["_source"] == "ldapsearch"

    def test_parse_dns_zones(self, ldap_basedse_fixture):
        """Test that DomainDnsZones and ForestDnsZones are extracted."""
        parser = ADParser()
        result = parser.parse_ldap_basedse(ldap_basedse_fixture)

        assert any("ForestDnsZones" in ctx for ctx in result["namingContexts"])
        assert any("DomainDnsZones" in ctx for ctx in result["namingContexts"])


class TestADParserLDAPMerge:
    """Test LDAP data merging with Base DSE precedence."""

    def test_basedse_precedence(self, ldap_basedse_fixture, ldap_rootdse_fixture):
        """Test that Base DSE values take precedence over RootDSE."""
        parser = ADParser()
        basedse = parser.parse_ldap_basedse(ldap_basedse_fixture)
        rootdse = parser.parse_ldap_rootdse(ldap_rootdse_fixture)

        merged = parser.merge_ldap_data(basedse, rootdse)

        # Base DSE should be the source
        assert merged["_source"] == "ldapsearch"
        assert "_sources" in merged
        assert "authoritative" in merged["_sources"]

    def test_rootdse_fills_missing_fields(self):
        """Test that RootDSE fills in fields missing from Base DSE."""
        parser = ADParser()
        basedse = {
            "_source": "ldapsearch",
            "defaultNamingContext": "DC=test,DC=local",
            "dnsHostName": None,
            "namingContexts": []
        }
        rootdse = {
            "_source": "nmap",
            "defaultNamingContext": "DC=test,DC=local",
            "dnsHostName": "dc1.test.local",
            "namingContexts": []
        }

        merged = parser.merge_ldap_data(basedse, rootdse)

        # RootDSE dnsHostName should be included
        assert merged["dnsHostName"] == "dc1.test.local"

    def test_merge_notes_on_conflict(self):
        """Test that conflicts are noted in merge_notes."""
        parser = ADParser()
        basedse = {
            "_source": "ldapsearch",
            "domainFunctionality": 7,
            "namingContexts": []
        }
        rootdse = {
            "_source": "nmap",
            "domainFunctionality": 6,
            "namingContexts": []
        }

        merged = parser.merge_ldap_data(basedse, rootdse)

        # Base DSE value should win
        assert merged["domainFunctionality"] == 7
        # Conflict should be noted
        assert "_merge_notes" in merged


class TestADParserSMBSecurity:
    """Test SMB security mode parsing."""

    def test_parse_signing_required(self, smb_security_dc_fixture):
        parser = ADParser()
        result = parser.parse_smb_security(smb_security_dc_fixture)

        assert result["message_signing"] == "required"
        assert result["smb2_message_signing"] == "enabled and required"
        assert result["signing_required"] is True
        assert "mitigating relay attacks" in result["interpretation"]

    def test_parse_signing_not_required(self, smb_security_workstation_fixture):
        parser = ADParser()
        result = parser.parse_smb_security(smb_security_workstation_fixture)

        assert "not required" in result["message_signing"].lower()
        assert result["signing_required"] is False
        assert "risk" in result["interpretation"].lower()

    def test_parse_smb2_version(self, smb_security_dc_fixture):
        parser = ADParser()
        result = parser.parse_smb_security(smb_security_dc_fixture)

        assert result["smb2_version"] == "3:1:1"

    def test_parse_authentication_level(self, smb_security_dc_fixture):
        parser = ADParser()
        result = parser.parse_smb_security(smb_security_dc_fixture)

        assert result["authentication_level"] == "user"
        assert result["challenge_response"] == "supported"
        assert result["account_used"] == "guest"

    def test_parse_empty_smb_security(self):
        parser = ADParser()
        result = parser.parse_smb_security("")

        assert result["message_signing"] is None
        assert result["signing_required"] is False


class TestADParserNetBIOS:
    """Test NetBIOS role identification."""

    def test_identify_dc_by_1c_group(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert result["is_dc"] is True
        assert "Domain Controllers <1c>" in result["groups"]

    def test_identify_domain_master_browser(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert result["is_domain_master"] is True
        assert "Domain Master Browser <1b>" in result["groups"]

    def test_extract_computer_name(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert result["computer_name"] == "FNN-DC01"

    def test_extract_domain_name(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert result["domain"] == "FNN"

    def test_extract_mac_address(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert result["mac_address"] == "F0-DB-30-76-EE-EA"

    def test_parse_netbios_names_list(self, netbios_dc_fixture):
        parser = ADParser()
        result = parser.parse_netbios_role(netbios_dc_fixture)

        assert len(result["netbios_names"]) > 0
        # Check for specific entries
        has_dc_entry = any(
            entry["name"] == "FNN-DC01" and entry["code"] == "00"
            for entry in result["netbios_names"]
        )
        assert has_dc_entry

    def test_empty_netbios_input(self):
        parser = ADParser()
        result = parser.parse_netbios_role("")

        assert result["is_dc"] is False
        assert result["netbios_names"] == []


class TestADParserDNSSRV:
    """Test DNS SRV record parsing and interpretation."""

    def test_detect_nxdomain_for_local_domain(self, dns_srv_nxdomain_fixture):
        parser = ADParser()
        result = parser.parse_dns_srv(dns_srv_nxdomain_fixture)

        assert result["found"] is False
        assert result["is_local_domain"] is True
        assert "NXDOMAIN" in result["interpretation"]
        assert "expected behavior" in result["interpretation"]

    def test_detect_mdns_warning(self, dns_srv_nxdomain_fixture):
        parser = ADParser()
        result = parser.parse_dns_srv(dns_srv_nxdomain_fixture)

        assert ".local" in dns_srv_nxdomain_fixture.lower()
        assert result["is_local_domain"] is True

    def test_parse_found_srv_records(self, dns_srv_found_fixture):
        parser = ADParser()
        result = parser.parse_dns_srv(dns_srv_found_fixture)

        assert result["found"] is True
        assert len(result["records"]) > 0
        assert result["interpretation"] is not None

    def test_separate_ldap_kerberos_status(self, dns_srv_nxdomain_fixture):
        parser = ADParser()
        result = parser.parse_dns_srv(dns_srv_nxdomain_fixture)

        assert result["ldap_status"] == "NXDOMAIN"
        assert result["kerberos_status"] == "NXDOMAIN"

    def test_empty_dns_input(self):
        parser = ADParser()
        result = parser.parse_dns_srv("")

        assert result["found"] is False
        assert result["records"] == []


class TestADParserKerberos:
    """Test Kerberos information parsing."""

    def test_script_unavailable_detection(self, kerberos_unavailable_fixture):
        parser = ADParser()
        # Simulate unavailable script by passing stderr message
        result = parser.parse_kerberos_info(
            "Kerberos NSE script (krb5-enum-users) not available")

        assert result["available"] is False
        assert result["limitation"] is not None

    def test_empty_kerberos_output(self):
        parser = ADParser()
        result = parser.parse_kerberos_info("")

        assert result["available"] is False
        assert result["limitation"] == "No output received"

    def test_parse_none_input(self):
        parser = ADParser()
        result = parser.parse_kerberos_info(None)

        assert result["available"] is False


class TestADParserFunctionalLevels:
    """Test functional level interpretation."""

    def test_interpret_level_7(self):
        parser = ADParser()
        interpretation = parser.interpret_functional_level(7)
        assert "Windows Server 2016" in interpretation

    def test_interpret_level_6(self):
        parser = ADParser()
        interpretation = parser.interpret_functional_level(6)
        assert "Windows Server 2012 R2" in interpretation

    def test_interpret_unknown_level(self):
        parser = ADParser()
        interpretation = parser.interpret_functional_level(99)
        assert "Unknown" in interpretation
        assert "99" in interpretation

    def test_interpret_none_level(self):
        parser = ADParser()
        interpretation = parser.interpret_functional_level(None)
        assert interpretation == "Unknown"
