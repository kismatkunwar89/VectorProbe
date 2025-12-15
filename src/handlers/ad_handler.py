"""
Active Directory enumeration handler.

Provides methods to run various AD enumeration tools without authentication:
- LDAP RootDSE and Base DSE queries
- SMB security mode enumeration
- NetBIOS role identification
- DNS SRV record lookups
- Kerberos information gathering
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from src.utils.decorators import timed_operation, log_exceptions
from src.utils.logger import get_logger

logger = get_logger()


@dataclass
class CommandResult:
    """Result of a command execution."""
    command: str
    stdout: str
    stderr: str
    exit_code: int


class ADHandler:
    """Handler for Active Directory enumeration tools."""

    def __init__(self, timeout: int = 30):
        """
        Initialize AD handler.

        Args:
            timeout: Command timeout in seconds
        """
        self.timeout = timeout

    def _ensure_ldapsearch_exists(self) -> None:
        """
        Verify ldapsearch is installed.

        Raises:
            FileNotFoundError: If ldapsearch is not found
        """
        if not shutil.which("ldapsearch"):
            raise FileNotFoundError(
                "ldapsearch not found. Install with: sudo apt install -y ldap-utils"
            )

    def _ensure_dig_exists(self) -> None:
        """
        Verify dig is installed.

        Raises:
            FileNotFoundError: If dig is not found
        """
        if not shutil.which("dig"):
            raise FileNotFoundError(
                "dig not found. Install with: sudo apt install -y dnsutils"
            )

    def _ensure_nmblookup_exists(self) -> None:
        """
        Verify nmblookup is installed.

        Raises:
            FileNotFoundError: If nmblookup is not found
        """
        if not shutil.which("nmblookup"):
            raise FileNotFoundError(
                "nmblookup not found. Install with: sudo apt install -y samba-common-bin"
            )

    def _ensure_nmap_exists(self) -> None:
        """
        Verify nmap is installed.

        Raises:
            FileNotFoundError: If nmap is not found
        """
        if not shutil.which("nmap"):
            raise FileNotFoundError(
                "nmap not found. Install with: sudo apt install -y nmap"
            )

    def _run_command(self, command: list, tool_name: str) -> CommandResult:
        """
        Execute a command and return results.

        Args:
            command: Command and arguments as list
            tool_name: Name of tool for logging

        Returns:
            CommandResult with command output and exit code
        """
        cmd_str = " ".join(command)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return CommandResult(
                command=cmd_str,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                f"{tool_name} timed out after {self.timeout}s: {cmd_str}")
            return CommandResult(
                command=cmd_str,
                stdout="",
                stderr=f"Command timed out after {self.timeout} seconds",
                exit_code=-1
            )
        except Exception as e:
            logger.error(f"{tool_name} execution failed: {e}")
            return CommandResult(
                command=cmd_str,
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

    @timed_operation
    @log_exceptions
    def ldap_rootdse(self, dc_ip: str) -> CommandResult:
        """
        Query LDAP RootDSE using Nmap NSE script.

        Args:
            dc_ip: Domain Controller IP address

        Returns:
            CommandResult with nmap ldap-rootdse output
        """
        try:
            self._ensure_nmap_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f"nmap -p 389 --script ldap-rootdse {dc_ip}",
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        command = ["nmap", "-p", "389", "--script", "ldap-rootdse", dc_ip]
        return self._run_command(command, "nmap ldap-rootdse")

    @timed_operation
    @log_exceptions
    def ldap_basedse(self, dc_ip: str) -> CommandResult:
        """
        Query LDAP Base DSE using ldapsearch (authoritative source).

        Args:
            dc_ip: Domain Controller IP address

        Returns:
            CommandResult with ldapsearch LDIF output
        """
        try:
            self._ensure_ldapsearch_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f'ldapsearch -x -H ldap://{dc_ip} -b "" -s base',
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        command = ["ldapsearch", "-x", "-H",
                   f"ldap://{dc_ip}", "-b", "", "-s", "base"]
        return self._run_command(command, "ldapsearch")

    @timed_operation
    @log_exceptions
    def smb_security_mode(self, dc_ip: str) -> CommandResult:
        """
        Enumerate SMB security mode and signing requirements.

        Args:
            dc_ip: Domain Controller IP address

        Returns:
            CommandResult with nmap smb-security-mode output
        """
        try:
            self._ensure_nmap_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f"nmap -p 445 --script smb-security-mode,smb2-security-mode {dc_ip}",
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        command = [
            "nmap", "-p", "445",
            "--script", "smb-security-mode,smb2-security-mode",
            dc_ip
        ]
        return self._run_command(command, "nmap smb-security-mode")

    @timed_operation
    @log_exceptions
    def netbios_role(self, dc_ip: str) -> CommandResult:
        """
        Query NetBIOS information and identify DC role.

        Args:
            dc_ip: Domain Controller IP address

        Returns:
            CommandResult with nmblookup output
        """
        try:
            self._ensure_nmblookup_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f"nmblookup -A {dc_ip}",
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        command = ["nmblookup", "-A", dc_ip]
        return self._run_command(command, "nmblookup")

    @timed_operation
    @log_exceptions
    def dns_srv_records(self, domain: str) -> CommandResult:
        """
        Query DNS SRV records for Active Directory services.

        Args:
            domain: DNS domain name (e.g., fnn.local)

        Returns:
            CommandResult with combined dig SRV output
        """
        try:
            self._ensure_dig_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f"dig SRV _ldap._tcp.dc._msdcs.{domain}",
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        # Query LDAP DC SRV records
        ldap_command = ["dig", "SRV", f"_ldap._tcp.dc._msdcs.{domain}"]
        ldap_result = self._run_command(ldap_command, "dig SRV LDAP")

        # Query Kerberos SRV records
        krb_command = ["dig", "SRV", f"_kerberos._tcp.{domain}"]
        krb_result = self._run_command(krb_command, "dig SRV Kerberos")

        # Combine both outputs
        combined_stdout = f"# LDAP DC SRV Query:\n{ldap_result.stdout}\n\n"
        combined_stdout += f"# Kerberos SRV Query:\n{krb_result.stdout}"
        combined_stderr = ""
        if ldap_result.stderr:
            combined_stderr += f"LDAP: {ldap_result.stderr}\n"
        if krb_result.stderr:
            combined_stderr += f"Kerberos: {krb_result.stderr}"

        return CommandResult(
            command=f"{ldap_result.command} && {krb_result.command}",
            stdout=combined_stdout,
            stderr=combined_stderr,
            exit_code=0 if ldap_result.exit_code == 0 or krb_result.exit_code == 0 else -1
        )

    @timed_operation
    @log_exceptions
    def kerberos_info(self, dc_ip: str, realm: Optional[str] = None) -> CommandResult:
        """
        Attempt to gather Kerberos information using Nmap NSE script.

        Note: krb5-enum-users script may not be available in all nmap installations.

        Args:
            dc_ip: Domain Controller IP address
            realm: Kerberos realm (optional, e.g., FNN.LOCAL)

        Returns:
            CommandResult with nmap krb5-enum-users output or limitation note
        """
        try:
            self._ensure_nmap_exists()
        except FileNotFoundError as e:
            return CommandResult(
                command=f"nmap -p 88 --script krb5-enum-users {dc_ip}",
                stdout="",
                stderr=str(e),
                exit_code=-1
            )

        # Build command with realm if provided
        if realm:
            command = [
                "nmap", "-p", "88",
                "--script", "krb5-enum-users",
                "--script-args", f"krb5-enum-users.realm={realm},userdb=/dev/null",
                dc_ip
            ]
            cmd_desc = f"nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm={realm},userdb=/dev/null {dc_ip}"
        else:
            command = ["nmap", "-p", "88",
                       "--script", "krb5-enum-users", dc_ip]
            cmd_desc = f"nmap -p 88 --script krb5-enum-users {dc_ip}"

        result = self._run_command(command, "nmap krb5-enum-users")

        # Check if script is unavailable
        if "NSE: failed to initialize the script engine" in result.stderr or \
           "krb5-enum-users" in result.stderr and "not found" in result.stderr.lower():
            return CommandResult(
                command=cmd_desc,
                stdout="",
                stderr="Kerberos NSE script (krb5-enum-users) not available in this nmap installation",
                exit_code=-1
            )

        return result
