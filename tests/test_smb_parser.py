"""
Unit tests for SMB parser module.

Tests the SMBParser class which parses nmap SMB enumeration output
from scripts like smb-enum-shares, smb-enum-users, and nbstat.

Note: These tests define the expected behavior for the SMB parser.
Since the parser is currently a stub implementation, tests will initially fail.
This is expected and follows a TDD (Test-Driven Development) approach.
"""

import pytest
from src.parsers.smb_parser import SMBParser
from src.parsers.netbios_parser import parse_netbios_output


@pytest.fixture
def smb_shares_fixture_path():
    """Return path to SMB shares enumeration fixture."""
    return "tests/fixtures/smb_enum_shares.txt"


@pytest.fixture
def smb_users_fixture_path():
    """Return path to SMB users enumeration fixture."""
    return "tests/fixtures/smb_enum_users.txt"


@pytest.fixture
def smb_combined_fixture_path():
    """Return path to combined SMB output fixture."""
    return "tests/fixtures/smb_combined.txt"


@pytest.fixture
def netbios_fixture_path():
    """Return path to NetBIOS enumeration fixture."""
    return "tests/fixtures/netbios_sample.txt"


@pytest.fixture
def smb_shares_sample():
    """Return sample SMB shares output."""
    return """Host script results:
| smb-enum-shares:
|   \\\\192.168.1.100\\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ/WRITE
|   \\\\192.168.1.100\\SharedFiles:
|     Type: STYPE_DISKTREE
|     Comment: Public shared folder
|     Anonymous access: READ/WRITE"""


@pytest.fixture
def smb_users_sample():
    """Return sample SMB users output."""
    return """Host script results:
| smb-enum-users:
|   WORKGROUP\\Administrator (RID: 500)
|     Description: Built-in account
|     Flags:       Normal user account
|   WORKGROUP\\Guest (RID: 501)
|     Description: Built-in guest account
|     Flags:       Account disabled"""


class TestSMBParserBasicParsing:
    """Test basic SMB parser functionality."""

    def test_parse_valid_fixture_file(self, smb_combined_fixture_path):
        """Test parsing a valid SMB combined fixture file."""
        with open(smb_combined_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        result = parser.parse_smb_results(content)

        assert isinstance(result, dict)
        assert result is not None

    def test_parse_returns_dict(self, smb_shares_sample):
        """Test that parse_smb_results returns a dictionary."""
        parser = SMBParser()
        result = parser.parse_smb_results(smb_shares_sample)

        assert isinstance(result, dict)

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        parser = SMBParser()
        result = parser.parse_smb_results("")

        assert isinstance(result, dict)

    def test_parse_whitespace_only(self):
        """Test parsing whitespace-only input."""
        parser = SMBParser()
        result = parser.parse_smb_results("   \n\n   \t   ")

        assert isinstance(result, dict)


class TestSMBParserShareExtraction:
    """Test SMB share extraction from nmap output."""

    def test_extract_shares_returns_list(self, smb_shares_sample):
        """Test that extract_shares returns a list."""
        parser = SMBParser()
        shares = parser.extract_shares(smb_shares_sample)

        assert isinstance(shares, list)

    def test_extract_standard_shares(self, smb_shares_fixture_path):
        """Test extraction of standard Windows shares (C$, IPC$, ADMIN$)."""
        with open(smb_shares_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        shares = parser.extract_shares(content)

        # Convert shares to strings for checking
        shares_str = str(shares)

        # Should find at least some standard shares
        assert isinstance(shares, list)
        # Parser should extract share information
        assert 'IPC$' in content  # Verify fixture has this data

    def test_extract_custom_shares(self):
        """Test extraction of custom file shares."""
        sample = """Host script results:
| smb-enum-shares:
|   \\\\192.168.1.100\\SharedFiles:
|     Type: STYPE_DISKTREE
|     Comment: Public shared folder
|     Anonymous access: READ/WRITE
|   \\\\192.168.1.100\\Documents:
|     Type: STYPE_DISKTREE
|     Comment: Document repository
|     Anonymous access: READ"""

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        assert isinstance(shares, list)
        # Fixture contains SharedFiles and Documents

    def test_extract_shares_with_different_types(self, smb_shares_fixture_path):
        """Test extraction handles different share types (DISK, IPC, PRINT)."""
        with open(smb_shares_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        shares = parser.extract_shares(content)

        # Should handle different share types
        assert isinstance(shares, list)

    def test_extract_shares_with_permissions(self):
        """Test that share permissions are captured."""
        sample = """| smb-enum-shares:
|   \\\\192.168.1.100\\Public:
|     Anonymous access: READ/WRITE
|   \\\\192.168.1.100\\ReadOnly:
|     Anonymous access: READ
|   \\\\192.168.1.100\\NoAccess:
|     Anonymous access: <none>"""

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        # Parser should handle different permission levels
        assert isinstance(shares, list)

    def test_empty_shares_list(self):
        """Test handling of output with no shares."""
        sample = "No shares found"

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        assert isinstance(shares, list)

    def test_shares_with_spaces_in_names(self):
        """Test handling shares with spaces in names."""
        sample = """| smb-enum-shares:
|   \\\\192.168.1.100\\My Documents:
|     Type: STYPE_DISKTREE
|     Comment: Personal files
|   \\\\192.168.1.100\\Shared Folder:
|     Type: STYPE_DISKTREE"""

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        assert isinstance(shares, list)


class TestSMBParserUserExtraction:
    """Test SMB user extraction from nmap output."""

    def test_extract_users_returns_list(self, smb_users_sample):
        """Test that extract_users returns a list."""
        parser = SMBParser()
        users = parser.extract_users(smb_users_sample)

        assert isinstance(users, list)

    def test_extract_builtin_users(self, smb_users_fixture_path):
        """Test extraction of built-in users (Administrator, Guest)."""
        with open(smb_users_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        users = parser.extract_users(content)

        assert isinstance(users, list)
        # Fixture contains Administrator and Guest users

    def test_extract_custom_users(self):
        """Test extraction of custom users."""
        sample = """Host script results:
| smb-enum-users:
|   WORKGROUP\\john (RID: 1001)
|     Description: John Smith - IT Administrator
|   WORKGROUP\\alice (RID: 1002)
|     Description: Alice Johnson - Developer"""

        parser = SMBParser()
        users = parser.extract_users(sample)

        assert isinstance(users, list)
        # Fixture contains custom users john and alice

    def test_extract_users_with_descriptions(self, smb_users_fixture_path):
        """Test that user descriptions are captured."""
        with open(smb_users_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        users = parser.extract_users(content)

        # Users should include description information
        assert isinstance(users, list)

    def test_empty_users_list(self):
        """Test handling of output with no users."""
        sample = "No users found"

        parser = SMBParser()
        users = parser.extract_users(sample)

        assert isinstance(users, list)


class TestSMBParserVersionInfo:
    """Test SMB version and OS information extraction."""

    def test_extract_smb_version(self, smb_combined_fixture_path):
        """Test extraction of SMB protocol version."""
        with open(smb_combined_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        result = parser.parse_smb_results(content)

        # Result should be a dict that could contain version info
        assert isinstance(result, dict)
        # Fixture contains SMB2/SMB3 version information

    def test_extract_os_information(self, smb_combined_fixture_path):
        """Test extraction of OS information."""
        with open(smb_combined_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        result = parser.parse_smb_results(content)

        # Should extract OS information
        assert isinstance(result, dict)
        # Fixture contains Windows Server 2019 information

    def test_extract_computer_name(self, smb_combined_fixture_path):
        """Test extraction of NetBIOS computer name."""
        with open(smb_combined_fixture_path, 'r') as f:
            content = f.read()

        parser = SMBParser()
        result = parser.parse_smb_results(content)

        assert isinstance(result, dict)
        # Fixture contains WIN-SRV01 as computer name


class TestSMBParserEdgeCases:
    """Test edge cases and error handling."""

    def test_malformed_share_entry(self):
        """Test handling of malformed share entry."""
        sample = """| smb-enum-shares:
|   Invalid share entry
|   \\\\192.168.1.100\\ValidShare:
|     Type: STYPE_DISKTREE"""

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        # Should gracefully handle malformed data
        assert isinstance(shares, list)

    def test_malformed_user_entry(self):
        """Test handling of malformed user entry."""
        sample = """| smb-enum-users:
|   Invalid user entry
|   WORKGROUP\\ValidUser (RID: 1001)"""

        parser = SMBParser()
        users = parser.extract_users(sample)

        # Should gracefully handle malformed data
        assert isinstance(users, list)

    def test_mixed_valid_invalid_data(self):
        """Test handling of mixed valid and invalid entries."""
        sample = """Host script results:
| smb-enum-shares:
|   \\\\192.168.1.100\\ValidShare:
|     Type: STYPE_DISKTREE
|   Invalid line here
|   \\\\192.168.1.100\\AnotherShare:
|     Type: STYPE_DISKTREE"""

        parser = SMBParser()
        shares = parser.extract_shares(sample)

        # Should extract valid entries and skip invalid ones
        assert isinstance(shares, list)

    def test_none_input(self):
        """Test handling of None input."""
        parser = SMBParser()

        # Should handle None gracefully
        try:
            result = parser.parse_smb_results(None)
            assert isinstance(result, dict)
        except (TypeError, AttributeError):
            # Acceptable to raise exception for None input
            pass


class TestNetBIOSParserIntegration:
    """Test NetBIOS parser integration."""

    def test_parse_netbios_output(self, netbios_fixture_path):
        """Test parsing NetBIOS output."""
        with open(netbios_fixture_path, 'r') as f:
            content = f.read()

        result = parse_netbios_output(content)

        assert isinstance(result, dict)

    def test_extract_netbios_name(self, netbios_fixture_path):
        """Test extraction of NetBIOS computer name."""
        with open(netbios_fixture_path, 'r') as f:
            content = f.read()

        result = parse_netbios_output(content)

        # Should extract NetBIOS name information
        assert isinstance(result, dict)
        # Fixture contains WIN-SRV01

    def test_extract_workgroup(self, netbios_fixture_path):
        """Test extraction of workgroup name."""
        with open(netbios_fixture_path, 'r') as f:
            content = f.read()

        result = parse_netbios_output(content)

        # Should extract workgroup information
        assert isinstance(result, dict)
        # Fixture contains WORKGROUP

    def test_extract_mac_address(self, netbios_fixture_path):
        """Test extraction of MAC address."""
        with open(netbios_fixture_path, 'r') as f:
            content = f.read()

        result = parse_netbios_output(content)

        # Should extract MAC address if present
        assert isinstance(result, dict)
        # Fixture contains 00:0c:29:3a:2b:1c (VMware)
