"""
SMB Enumeration Handler

Wraps enum4linux-ng to enumerate SMB shares, users, groups, and OS info.
"""

from typing import Optional

from models.command_result import CommandResult
from utils.decorators import validate_ip, timing, retry
from utils.shell import execute_command
from utils.tool_checker import ensure_tool_exists


class SMBHandler:
    """Handler for SMB/NetBIOS enumeration using enum4linux-ng."""

    def __init__(self, timeout_sec: int = 120):
        """
        Initialize SMB handler.

        Args:
            timeout_sec: Timeout for enum4linux-ng execution
        """
        self.timeout_sec = timeout_sec

    def _run(self, cmd: list) -> CommandResult:
        """
        Execute a command and return the result.

        Args:
            cmd: Command as list of arguments

        Returns:
            CommandResult with stdout, stderr, exit_code
        """
        return execute_command(cmd, timeout=self.timeout_sec)

    @validate_ip
    @timing
    def enumerate_target(self, target: str) -> CommandResult:
        """
        Enumerate SMB info on target using enum4linux-ng.

        Args:
            target: Single IP address (e.g., "192.168.1.100")

        Returns:
            CommandResult with enum4linux-ng output
        """
        tool = ensure_tool_exists(
            "enum4linux-ng",
            alternatives=["enum4linux"],
            install_hint="Install with: pip install enum4linux-ng or apt install enum4linux"
        )

        # Run: enum4linux-ng -A <target>
        # -A: All simple enumeration (users, shares, groups, OS info)
        cmd = [tool, "-A", target]

        return self._run(cmd)
