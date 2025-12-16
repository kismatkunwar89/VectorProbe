"""
SMB Enumeration Parser

Parses output from enum4linux-ng to extract:
- Domain name
- Users
- Groups  
- Shares
- OS information
- Null session status
"""

import re
from typing import Dict, List, Optional


class SMBParser:
    """Parse enum4linux-ng output into structured data."""

    def parse(self, raw_output: str) -> Dict:
        """
        Parse enum4linux-ng output.

        Args:
            raw_output: Raw text output from enum4linux-ng

        Returns:
            Dict with keys: domain, os_info, null_session, users, groups, shares
        """
        if not raw_output or not raw_output.strip():
            return self._empty_result()

        return {
            "domain": self._extract_domain(raw_output),
            "os_info": self._extract_os_info(raw_output),
            "null_session": self._check_null_session(raw_output),
            "users": self._extract_users(raw_output),
            "groups": self._extract_groups(raw_output),
            "shares": self._extract_shares(raw_output),
        }

    def _empty_result(self) -> Dict:
        """Return empty enumeration result."""
        return {
            "domain": None,
            "os_info": None,
            "null_session": False,
            "users": [],
            "groups": [],
            "shares": [],
        }

    def _extract_domain(self, output: str) -> Optional[str]:
        """Extract domain name from enum4linux output."""
        patterns = [
            r"\[E\]\s+Domain Name:\s*(\S+)",
            r"Domain Name:\s*(\S+)",
            r"Domain:\s*(\S+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    def _extract_os_info(self, output: str) -> Optional[str]:
        """Extract OS information from enum4linux output."""
        patterns = [
            r"OS:\s*(.+?)(?:\n|$)",
            r"OS Information:\s*(.+?)(?:\n|$)",
            r"\[E\]\s+OS Information:\s*(.+?)(?:\n|$)",
        ]

        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                os_str = match.group(1).strip()
                if os_str and os_str.lower() != "unknown":
                    return os_str

        return None

    def _check_null_session(self, output: str) -> bool:
        """
        Check if null sessions are allowed by looking for:
        - Positive indicators (session successful)
        - Negative indicators (session denied/failed)
        """
        # Negative indicators: null session explicitly denied
        denial_patterns = [
            r"Could not establish null session",
            r"STATUS_ACCESS_DENIED",
            r"null session.*denied",
            r"null session.*failed",
            r"\[-\].*null session",  # Negative status indicator
        ]

        # Positive indicators: null session succeeded
        success_patterns = [
            r"Access over.*session successful",
            r"\[E\]\s+null session",
            r"Null Session.*allowed",
            r"anonymous.*successful",
        ]

        # Check for explicit denials first (more specific)
        for pattern in denial_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return False  # Explicitly denied

        # Then check for positive indicators
        for pattern in success_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                return True  # Session allowed

        # Default: if no indicators found, assume disabled
        return False

    def _extract_users(self, output: str) -> List[str]:
        """Extract user list from enum4linux output."""
        users = []

        # Pattern 1: [-] User 'username' (rid ...
        pattern1 = r"\[-\]\s+User\s+'([^']+)'"
        for match in re.finditer(pattern1, output):
            username = match.group(1).strip()
            if username and username not in users:
                users.append(username)

        # Pattern 2: [+] Users: admin,guest,user1
        pattern2 = r"\[\+\]\s+Users?\s*:\s*(.+?)(?:\n|$)"
        match = re.search(pattern2, output, re.IGNORECASE)
        if match:
            user_str = match.group(1).strip()
            for user in user_str.split(","):
                user = user.strip()
                if user and user not in users and user.lower() != "none":
                    users.append(user)

        return sorted(list(set(users)))

    def _extract_groups(self, output: str) -> List[str]:
        """Extract group list from enum4linux output."""
        groups = []

        # Pattern: [-] Group 'groupname' (rid ...
        pattern = r"\[-\]\s+Group\s+'([^']+)'"
        for match in re.finditer(pattern, output):
            group = match.group(1).strip()
            if group and group not in groups:
                groups.append(group)

        return sorted(list(set(groups)))

    def _extract_shares(self, output: str) -> List[Dict]:
        """Extract share information from enum4linux output."""
        shares = []

        # Pattern: Disk: \\target\C$ (C$) Disk 'Default share'
        pattern = r"Disk:\s+\\\\[^\s]+\\([^\s]+)\s+\(([^)]*)\)\s+Disk\s+['\"]?([^'\"]*)['\"]?"

        for match in re.finditer(pattern, output, re.IGNORECASE):
            share_name = match.group(1).strip()
            share_remark = match.group(2).strip() if match.group(2) else ""
            share_comment = match.group(3).strip() if match.group(3) else ""

            share_dict = {
                "name": share_name,
                "type": "Disk",
                "comment": share_comment or share_remark or "",
            }

            if share_dict not in shares:
                shares.append(share_dict)

        return shares
