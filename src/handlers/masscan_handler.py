"""
masscan_handler.py

Responsible for:
- Running Masscan commands safely (high-speed port scanning)
- Returning stdout/stderr/exit_code + command string
- Keeping the rest of the program independent from subprocess details

NOTE:
- This does NOT parse Masscan output (parsing is done in src/parsers/).
- This module only EXECUTES Masscan and captures output.
"""

from __future__ import annotations

from typing import List

from models.command_result import CommandResult
from utils.decorators import timing, retry
from utils.shell import execute_command
from utils.tool_checker import ensure_tool_exists


class MasscanHandler:
    """
    A wrapper around subprocess for running Masscan scans.

    Masscan is a high-speed port scanner that can scan large networks
    much faster than Nmap.

    Why this class?
    - Keeps your code modular and testable
    - Central place to change scan options later
    - Handles timeout and error conditions gracefully
    """

    def __init__(self, timeout_sec: int = 300):
        """
        Initialize the Masscan handler.

        Args:
            timeout_sec: Maximum time to wait for scan to complete (default 300 seconds)
        """
        self.timeout_sec = timeout_sec

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _run(self, cmd: List[str]) -> CommandResult:
        """
        Runs a command and captures output safely.

        Args:
            cmd: Command as a list of strings (e.g., ["masscan", "-p", "80"])

        Returns:
            CommandResult: Contains command, stdout, stderr, and exit code
        """
        ensure_tool_exists(
            "masscan",
            install_hint="Visit: https://github.com/robertdavidgraham/masscan"
        )
        return execute_command(cmd, timeout=self.timeout_sec)

    # ---------------------------
    # Public scan methods
    # ---------------------------
    @timing
    def scan_targets(
        self,
        targets: str,
        top_ports: int = 1000,
        rate: int = 100000
    ) -> CommandResult:
        """
        High-speed scan of target(s) using Masscan.

        Args:
            targets: Target specification as string. Can include:
                     - Single IP: "192.168.1.1"
                     - CIDR range: "192.168.1.0/24"
                     - Multiple targets: "192.168.1.0/24,10.0.0.1,10.0.0.5"
            top_ports: Number of top ports to scan (default 1000)
            rate: Packets per second rate limit (default 100000)

        Returns:
            CommandResult: Contains masscan output in greppable format

        Note:
            - Output is in greppable format (-oG)
            - Requires root/administrator privileges on most systems
            - rate parameter controls speed vs. system load
        """
        cmd = [
            "masscan",
            "--top-ports", str(top_ports),
            "--rate", str(rate),
            "-oG", "-",  # Output to stdout in greppable format
            targets
        ]

        return self._run(cmd)

    @timing
    def scan_ports(
        self,
        targets: str,
        ports: str,
        rate: int = 100000
    ) -> CommandResult:
        """
        Scan specific ports on target(s) using Masscan.

        Args:
            targets: Target specification (see scan_targets for format)
            ports: Port specification. Examples:
                   - Single port: "80"
                   - Port range: "80-443"
                   - Multiple: "80,443,8080"
                   - All ports: "0-65535"
            rate: Packets per second (default 100000)

        Returns:
            CommandResult: Contains masscan output in greppable format
        """
        cmd = [
            "masscan",
            "-p", ports,
            "--rate", str(rate),
            "-oG", "-",  # Output to stdout in greppable format
            targets
        ]

        return self._run(cmd)


# ---------------------------------------------------------------------------
# Standalone testing (safe to delete later)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    """
    This is ONLY to test this file by itself.

    Run:
      python src/handlers/masscan_handler.py

    Note: Masscan requires root/administrator privileges.
    """
    scanner = MasscanHandler(timeout_sec=60)

    # Use a safe test target (localhost only)
    test_target = "127.0.0.1"

    try:
        result = scanner.scan_targets(test_target, top_ports=100, rate=10000)
        print("Command:", result.command)
        print("Exit Code:", result.exit_code)
        print("---- STDOUT (first 500 chars) ----")
        print(result.stdout[:500] if result.stdout else "(empty)")
        print("---- STDERR ----")
        print(result.stderr if result.stderr else "(empty)")
    except RuntimeError as e:
        print(f"Error: {e}")
