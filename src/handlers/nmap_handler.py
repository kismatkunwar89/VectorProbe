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

from typing import List, Optional

from models.command_result import CommandResult
from utils.decorators import validate_ip, timing, retry
from utils.shell import execute_command
from utils.tool_checker import ensure_tool_exists


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
    def _run(self, cmd: List[str]) -> CommandResult:
        """
        Runs a command and captures output safely.
        """
        ensure_tool_exists(
            "nmap",
            install_hint="Install with: sudo apt install nmap"
        )
        return execute_command(cmd, timeout=self.timeout_sec)

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
        # Normalize targets and split on commas/whitespace for subprocess
        normalized = (targets or "").replace(',', ' ')
        target_args = [token for token in normalized.split() if token]

        if not target_args:
            raise ValueError("No targets provided for Nmap scan.")

        cmd = [
            "nmap",
            "-sS",      # TCP SYN scan (half-open)
            "-sV",      # Version detection
            "-sC",      # Default safe scripts
            "-O",       # OS detection
            "-Pn",      # Skip ping (useful in restricted networks)
            "-oN",      # Normal output format
            "-",        # Output to stdout
            *target_args
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

    @timing
    def host_discovery(self, targets: str, exclude: str = "") -> CommandResult:
        """
        Fast host discovery using ping sweep (-sn).

        Args:
            targets: Target(s) - IP, CIDR, or comma-separated targets
                    Examples: "192.168.1.1" or "192.168.1.0/24"
            exclude: Hosts to exclude from scan (comma-separated)

        Returns:
            CommandResult with greppable output containing live hosts
        """
        # Normalize targets and split on commas/whitespace for subprocess
        normalized = (targets or "").replace(',', ' ')
        target_args = [token for token in normalized.split() if token]

        if not target_args:
            raise ValueError("No targets provided for host discovery.")

        cmd = [
            "nmap",
            "-sn",      # Ping sweep only (no port scan)
            "-oG",     # Greppable output format
            "-",       # Output to stdout
        ]

        # Add exclusion if provided
        if exclude and exclude.strip():
            cmd.extend(["--exclude", exclude.strip()])

        cmd.extend(target_args)
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

    @timing
    def tcp_quick_scan(self, targets: str) -> CommandResult:
        """
        Quick TCP scan - top 100 ports only for fast enumeration.

        Useful for rapid network discovery when time is limited.
        Uses --top-ports 100 to scan most common ports.

        Args:
            targets: Target(s) - IP, CIDR, or comma-separated IPs

        Returns:
            CommandResult with command, stdout, stderr, exit_code
        """
        normalized = (targets or "").replace(',', ' ')
        target_args = [token for token in normalized.split() if token]

        if not target_args:
            raise ValueError("No targets provided for quick TCP scan.")

        cmd = [
            "nmap",
            "-sS",           # TCP SYN scan
            "-Pn",           # Skip ping
            "--top-ports",   # Scan most common ports
            "100",           # Top 100 ports
            "-oN",
            "-",
            *target_args
        ]
        return self._run(cmd)

    @timing
    def tcp_full_scan(self, targets: str) -> CommandResult:
        """
        Full TCP scan - all 65535 ports with version detection.

        Comprehensive scan that checks every TCP port. This can take
        significant time depending on network conditions and target count.

        Args:
            targets: Target(s) - IP, CIDR, or comma-separated IPs

        Returns:
            CommandResult with command, stdout, stderr, exit_code
        """
        normalized = (targets or "").replace(',', ' ')
        target_args = [token for token in normalized.split() if token]

        if not target_args:
            raise ValueError("No targets provided for full TCP scan.")

        cmd = [
            "nmap",
            "-sS",      # TCP SYN scan
            "-sV",      # Version detection
            "-sC",      # Default scripts
            "-O",       # OS detection
            "-p-",      # All 65535 ports
            "-Pn",      # Skip ping
            "-oN",
            "-",
            *target_args
        ]
        return self._run(cmd)

    @timing
    def udp_scan(self, targets: str) -> CommandResult:
        """
        UDP scan - common UDP ports for service discovery.

        Scans top 20 UDP ports (DNS, SNMP, DHCP, etc.).
        UDP scanning is slower than TCP due to protocol characteristics.

        Args:
            targets: Target(s) - IP, CIDR, or comma-separated IPs

        Returns:
            CommandResult with command, stdout, stderr, exit_code
        """
        normalized = (targets or "").replace(',', ' ')
        target_args = [token for token in normalized.split() if token]

        if not target_args:
            raise ValueError("No targets provided for UDP scan.")

        cmd = [
            "nmap",
            "-sU",           # UDP scan
            "-Pn",           # Skip ping
            "--top-ports",   # Scan most common UDP ports
            "20",            # Top 20 UDP ports
            "-oN",
            "-",
            *target_args
        ]
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
