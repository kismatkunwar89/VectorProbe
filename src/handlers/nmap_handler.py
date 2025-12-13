# nmap
# requests
# pyyaml

"""
nmap_handler.py

Responsible for:
- Running Nmap commands safely (no exploitation)
- Returning stdout/stderr/exit_code + command string
- Keeping the rest of the program independent from subprocess details

NOTE:
- This does NOT parse Nmap output (parsing is done in src/parsers/).
- This module only EXECUTES Nmap and captures output.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

# Import custom decorators
from utils.decorators import validate_ip, timing, retry


@dataclass
class CommandResult:
    """
    Holds results of a command execution.

    command   : exact command string that was run
    stdout    : normal output from command
    stderr    : error output from command
    exit_code : return code (0 usually means success)
    """
    command: str
    stdout: str
    stderr: str
    exit_code: int


class NmapHandler:
    """
    A wrapper around subprocess for running Nmap scans.

    Why this class?
    - Keeps your code modular and testable
    - Central place to change scan options later
    """

    def __init__(self, timeout_sec: int = 300):
        # timeout_sec: prevents scans from running forever
        self.timeout_sec = timeout_sec

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _ensure_nmap_exists(self) -> None:
        """
        Checks if nmap is available in PATH.
        If not, raise a clear error.
        """
        if shutil.which("nmap") is None:
            raise RuntimeError(
                "Nmap is not installed or not in PATH. "
                "Install nmap and ensure it is accessible from terminal."
            )

    def _run(self, cmd: List[str]) -> CommandResult:
        """
        Runs a command and captures output safely.
        """
        self._ensure_nmap_exists()

        command_str = " ".join(cmd)

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec
            )

            return CommandResult(
                command=command_str,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                exit_code=completed.returncode
            )

        except subprocess.TimeoutExpired as e:
            # If nmap takes too long, we still return whatever we have.
            return CommandResult(
                command=command_str,
                stdout=(e.stdout or ""),
                stderr=(e.stderr or "") + "\n[!] Timeout expired.",
                exit_code=-1
            )

        except Exception as e:
            # Any other unexpected error
            return CommandResult(
                command=command_str,
                stdout="",
                stderr=f"[!] Exception running command: {e}",
                exit_code=-1
            )

    # ---------------------------
    # Public scan methods
    # ---------------------------
    @validate_ip
    @timing
    def scan_targets(self, targets: str) -> CommandResult:
        """
        Scan targets using standard service enumeration.

        Args:
            targets: Target(s) - IP, CIDR, or comma-separated IPs
                    Examples: "192.168.1.1" or "192.168.1.0/24" or "192.168.1.1,192.168.1.2"

        Returns:
            CommandResult with command, stdout, stderr, exit_code
        """
        cmd = [
            "nmap",
            "-sS",      # TCP SYN scan (half-open)
            "-sV",      # Version detection
            "-sC",      # Default safe scripts
            "-O",       # OS detection
            "-Pn",      # Skip ping (useful in restricted networks)
            targets
        ]
        return self._run(cmd)

    @validate_ip
    @timing
    def tcp_default_scan(self, ip: str) -> CommandResult:
        """
        General enumeration scan:
        - -sS : TCP SYN scan
        - -sV : service version detection
        - -sC : default scripts (safe)
        - -O  : OS detection (best-effort)
        - -Pn : do not ping (avoid ICMP restrictions)
        """
        cmd = ["nmap", "-sS", "-sV", "-sC", "-O", "-Pn", ip]
        return self._run(cmd)

    @validate_ip
    @timing
    def traceroute_scan(self, ip: str) -> CommandResult:
        """
        Topology mapping / traceroute via nmap.
        """
        cmd = ["nmap", "--traceroute", "-Pn", ip]
        return self._run(cmd)

    @validate_ip
    @timing
    def smb_enum_scan(self, ip: str) -> CommandResult:
        """
        Windows SMB enumeration (port 445) using safe NSE scripts.
        """
        cmd = ["nmap", "-p", "445", "--script",
               "smb-enum-shares,smb-enum-users", "-Pn", ip]
        return self._run(cmd)

    @validate_ip
    @timing
    def netbios_enum_scan(self, ip: str) -> CommandResult:
        """
        Windows NetBIOS enumeration using nbstat script.
        """
        cmd = ["nmap", "-p", "137,138,139", "--script", "nbstat", "-Pn", ip]
        return self._run(cmd)


# ---------------------------------------------------------------------------
# Standalone testing (safe to delete later)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    """
    This is ONLY to test this file by itself.

    Run:
      python src/handlers/nmap_handler.py

    If Nmap is installed, it should print the first part of output.
    """
    scanner = NmapHandler(timeout_sec=60)

    # Use a safe test target.
    # You can also use your own lab IP.
    test_ip = "127.0.0.1"

    result = scanner.tcp_default_scan(test_ip)

    print("Command:", result.command)
    print("Exit Code:", result.exit_code)
    print("---- STDOUT (first 500 chars) ----")
    print(result.stdout[:500])
    print("---- STDERR ----")
    print(result.stderr)
