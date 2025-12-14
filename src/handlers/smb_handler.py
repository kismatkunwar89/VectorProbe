"""
SMB Enumeration Handler

Wraps enum4linux-ng to enumerate SMB shares, users, groups, and OS info.
"""

import subprocess
import shutil
from dataclasses import dataclass
from typing import Optional
from utils.decorators import validate_ip, timing, retry


@dataclass
class CommandResult:
    """Stores result of an SMB enumeration command."""
    command: str
    stdout: str
    stderr: str
    exit_code: int


class SMBHandler:
    """Handler for SMB/NetBIOS enumeration using enum4linux-ng."""

    def __init__(self, timeout_sec: int = 120):
        """
        Initialize SMB handler.

        Args:
            timeout_sec: Timeout for enum4linux-ng execution
        """
        self.timeout_sec = timeout_sec

    def _ensure_enum4linux_exists(self):
        """Ensure enum4linux-ng is installed and accessible."""
        tools = ["enum4linux-ng", "enum4linux"]
        for tool in tools:
            if shutil.which(tool) is not None:
                return tool
        raise RuntimeError(
            "enum4linux-ng or enum4linux not found in PATH. "
            "Install with: pip install enum4linux-ng or apt install enum4linux"
        )

    def _run(self, cmd: list) -> CommandResult:
        """
        Execute a command and return the result.

        Args:
            cmd: Command as list of arguments

        Returns:
            CommandResult with stdout, stderr, exit_code
        """
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
            )
            return CommandResult(
                command=" ".join(cmd),
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                exit_code=completed.returncode,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                command=" ".join(cmd),
                stdout="",
                stderr=f"Timeout after {self.timeout_sec} seconds",
                exit_code=-1,
            )
        except Exception as e:
            return CommandResult(
                command=" ".join(cmd),
                stdout="",
                stderr=str(e),
                exit_code=-1,
            )

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
        tool = self._ensure_enum4linux_exists()

        # Run: enum4linux-ng -A <target>
        # -A: All simple enumeration (users, shares, groups, OS info)
        cmd = [tool, "-A", target]

        return self._run(cmd)
