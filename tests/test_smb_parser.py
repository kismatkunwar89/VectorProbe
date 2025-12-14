"""
Unit tests for smb_parser module.

Tests the SMBParser class which parses enum4linux-ng output.
"""

import pytest
from src.parsers.smb_parser import SMBParser


@pytest.fixture
def enum4linux_windows_fixture():
    """Load Windows enum4linux sample."""
    with open("tests/fixtures/enum4linux_windows.txt", "r") as f:
        return f.read()


@pytest.fixture
def enum4linux_linux_fixture():
    """Load Linux enum4linux sample."""
    with open("tests/fixtures/enum4linux_linux.txt", "r") as f:
        return f.read()


class TestSMBParserBasicParsing:
    """Test basic parsing functionality."""

    def test_parse_returns_dict(self, enum4linux_windows_fixture):
        """Test that parse returns a dictionary."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        assert isinstance(result, dict)
        assert "domain" in result
        assert "os_info" in result
        assert "null_session" in result
        assert "users" in result
        assert "groups" in result
        assert "shares" in result

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        parser = SMBParser()
        result = parser.parse("")
        assert result["domain"] is None
        assert result["os_info"] is None
        assert result["null_session"] is False
        assert result["users"] == []
        assert result["groups"] == []
        assert result["shares"] == []

    def test_parse_none_input(self):
        """Test parsing None input."""
        parser = SMBParser()
        result = parser.parse(None)
        assert result["domain"] is None
        assert result["null_session"] is False


class TestSMBParserDomainExtraction:
    """Test domain name extraction."""

    def test_extract_domain_windows(self, enum4linux_windows_fixture):
        """Test domain extraction from Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        assert result["domain"] == "WINSERVER"

    def test_extract_domain_linux(self, enum4linux_linux_fixture):
        """Test domain extraction from Linux/Samba target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        assert result["domain"] == "SAMBA"

    def test_extract_domain_not_found(self):
        """Test when domain is not in output."""
        parser = SMBParser()
        output = "Some random output without domain info"
        result = parser.parse(output)
        assert result["domain"] is None


class TestSMBParserOSExtraction:
    """Test OS information extraction."""

    def test_extract_os_windows(self, enum4linux_windows_fixture):
        """Test OS extraction from Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        assert "Windows Server 2019" in result["os_info"]

    def test_extract_os_linux(self, enum4linux_linux_fixture):
        """Test OS extraction from Linux/Samba target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        assert "Linux" in result["os_info"]

    def test_extract_os_not_found(self):
        """Test when OS is not in output."""
        parser = SMBParser()
        output = "Random output without OS"
        result = parser.parse(output)
        assert result["os_info"] is None


class TestSMBParserNullSessionDetection:
    """Test null session vulnerability detection."""

    def test_null_session_detected_windows(self, enum4linux_windows_fixture):
        """Test null session detection in Windows output."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        assert result["null_session"] is True

    def test_null_session_detected_linux(self, enum4linux_linux_fixture):
        """Test null session detection in Linux output."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        assert result["null_session"] is True

    def test_null_session_not_detected(self):
        """Test when null session is not detected."""
        parser = SMBParser()
        output = "Some random enumeration output without indicators"
        result = parser.parse(output)
        assert result["null_session"] is False


class TestSMBParserUserExtraction:
    """Test user extraction from enum4linux output."""

    def test_extract_users_windows(self, enum4linux_windows_fixture):
        """Test user extraction from Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        users = result["users"]
        assert len(users) == 5
        assert "Administrator" in users
        assert "admin" in users
        assert "dbuser" in users
        assert "webadmin" in users
        assert "Guest" in users

    def test_extract_users_linux(self, enum4linux_linux_fixture):
        """Test user extraction from Linux target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        users = result["users"]
        assert len(users) == 3
        assert "samba" in users
        assert "scanner" in users
        assert "backup" in users

    def test_extract_users_sorted(self, enum4linux_windows_fixture):
        """Test that users are sorted alphabetically."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        users = result["users"]
        assert users == sorted(users)

    def test_extract_users_no_duplicates(self, enum4linux_windows_fixture):
        """Test that user list has no duplicates."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        users = result["users"]
        assert len(users) == len(set(users))

    def test_extract_users_empty_when_no_users(self):
        """Test empty user list when no users found."""
        parser = SMBParser()
        output = "Some output with no user information"
        result = parser.parse(output)
        assert result["users"] == []


class TestSMBParserGroupExtraction:
    """Test group extraction from enum4linux output."""

    def test_extract_groups_windows(self, enum4linux_windows_fixture):
        """Test group extraction from Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        groups = result["groups"]
        assert len(groups) == 4
        assert "Administrators" in groups
        assert "Users" in groups
        assert "Guests" in groups
        assert "Domain Admins" in groups

    def test_extract_groups_linux(self, enum4linux_linux_fixture):
        """Test group extraction from Linux target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        groups = result["groups"]
        assert len(groups) == 3
        assert "None" in groups
        assert "samba" in groups
        assert "scanner" in groups

    def test_extract_groups_sorted(self, enum4linux_windows_fixture):
        """Test that groups are sorted alphabetically."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        groups = result["groups"]
        assert groups == sorted(groups)

    def test_extract_groups_no_duplicates(self, enum4linux_windows_fixture):
        """Test that group list has no duplicates."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        groups = result["groups"]
        assert len(groups) == len(set(groups))

    def test_extract_groups_empty_when_none(self):
        """Test empty group list when no groups found."""
        parser = SMBParser()
        output = "Some output with no group information"
        result = parser.parse(output)
        assert result["groups"] == []


class TestSMBParserShareExtraction:
    """Test share extraction from enum4linux output."""

    def test_extract_shares_windows(self, enum4linux_windows_fixture):
        """Test share extraction from Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        shares = result["shares"]
        assert len(shares) == 5

        share_names = [s["name"] for s in shares]
        assert "ADMIN$" in share_names
        assert "C$" in share_names
        assert "IPC$" in share_names
        assert "Documents" in share_names
        assert "Public" in share_names

    def test_extract_shares_linux(self, enum4linux_linux_fixture):
        """Test share extraction from Linux target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)
        shares = result["shares"]
        assert len(shares) == 3

        share_names = [s["name"] for s in shares]
        assert "IPC$" in share_names
        assert "backup" in share_names
        assert "data" in share_names

    def test_share_has_required_fields(self, enum4linux_windows_fixture):
        """Test that each share has required fields."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        shares = result["shares"]
        for share in shares:
            assert "name" in share
            assert "type" in share
            assert "comment" in share
            assert share["type"] == "Disk"

    def test_share_comment_extraction(self, enum4linux_windows_fixture):
        """Test that share comments are extracted correctly."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        shares = result["shares"]

        # Find C$ share
        c_share = next((s for s in shares if s["name"] == "C$"), None)
        assert c_share is not None
        assert c_share["comment"] == "Default share"

    def test_extract_shares_empty_when_none(self):
        """Test empty share list when no shares found."""
        parser = SMBParser()
        output = "Some output with no share information"
        result = parser.parse(output)
        assert result["shares"] == []

    def test_shares_no_duplicates(self, enum4linux_windows_fixture):
        """Test that share list has no duplicates."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)
        shares = result["shares"]
        share_names = [s["name"] for s in shares]
        assert len(share_names) == len(set(share_names))


class TestSMBParserCompleteness:
    """Test that all data is extracted correctly for complete targets."""

    def test_complete_windows_enumeration(self, enum4linux_windows_fixture):
        """Test complete enumeration data for Windows target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_windows_fixture)

        # Verify all components are present
        assert result["domain"] == "WINSERVER"
        assert result["os_info"] is not None
        assert result["null_session"] is True
        assert len(result["users"]) == 5
        assert len(result["groups"]) == 4
        assert len(result["shares"]) == 5

    def test_complete_linux_enumeration(self, enum4linux_linux_fixture):
        """Test complete enumeration data for Linux/Samba target."""
        parser = SMBParser()
        result = parser.parse(enum4linux_linux_fixture)

        # Verify all components are present
        assert result["domain"] == "SAMBA"
        assert result["os_info"] is not None
        assert result["null_session"] is True
        assert len(result["users"]) == 3
        assert len(result["groups"]) == 3
        assert len(result["shares"]) == 3


class TestSMBParserEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_parse_whitespace_only(self):
        """Test parsing string with only whitespace."""
        parser = SMBParser()
        result = parser.parse("   \n  \t  \n")
        assert result["domain"] is None
        assert result["users"] == []

    def test_parse_malformed_entries(self):
        """Test parsing with malformed entries mixed in."""
        output = """
        [E] Domain Name: TESTDOMAIN
        [E] Invalid line with no proper format
        [-] User 'testuser' (rid 1000)
        """
        parser = SMBParser()
        result = parser.parse(output)
        assert result["domain"] == "TESTDOMAIN"
        assert "testuser" in result["users"]

    def test_case_insensitive_domain_extraction(self):
        """Test that domain extraction is case-insensitive."""
        output = "domain name: MYTEST"
        parser = SMBParser()
        result = parser.parse(output)
        assert result["domain"] == "MYTEST"

    def test_multiple_domains_first_wins(self):
        """Test that first domain found is used."""
        output = """
        Domain Name: FIRST
        Domain Name: SECOND
        """
        parser = SMBParser()
        result = parser.parse(output)
        assert result["domain"] == "FIRST"
