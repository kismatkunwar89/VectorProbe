import ipaddress
import socket
from dataclasses import dataclass
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Data model to store resolved targets
# ---------------------------------------------------------------------------
@dataclass
class ResolvedTarget:
    """
    Represents a resolved scan target.

    original : The original input (IP, CIDR, or DNS)
    ip       : The resolved IPv4 address
    hostname : DNS name (only for DNS-based targets)
    """
    original: str
    ip: str
    hostname: str | None = None


# ---------------------------------------------------------------------------
# Helper utility functions
# ---------------------------------------------------------------------------
def _split_csv(value: str) -> List[str]:
    """
    Splits comma-separated input into a clean list.
    Example: "a, b, c" -> ["a", "b", "c"]
    """
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def _is_ip(value: str) -> bool:
    """
    Checks whether the given value is a valid IP address.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _expand_cidr(value: str):
    """
    Generator that yields individual host IPs from a CIDR range.

    This uses a generator for memory efficiency when dealing with large networks.
    For example, a /16 network has 65,534 hosts - using a generator means
    we don't need to store all IPs in memory at once.

    Example: 192.168.1.0/30 yields "192.168.1.1", "192.168.1.2"

    Yields:
        str: Individual IP addresses from the CIDR range
    """
    network = ipaddress.ip_network(value, strict=False)
    for ip in network.hosts():
        yield str(ip)


def _resolve_dns(name: str) -> List[str]:
    """
    Resolves a DNS name to IPv4 addresses.
    """
    infos = socket.getaddrinfo(name, None, socket.AF_INET)
    return list({info[4][0] for info in infos})


def _get_dns_servers() -> List[str]:
    """
    Attempts to list configured DNS servers.

    On Linux/macOS: reads /etc/resolv.conf
    On Windows: fallback message (DNS not directly accessible)
    """
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except Exception:
        servers.append("System DNS (Windows / Unknown)")
    return servers


# ---------------------------------------------------------------------------
# MAIN FUNCTION: parse targets + resolve IPs
# ---------------------------------------------------------------------------
def parse_and_resolve_targets(
    targets: str,
    exclude: str,
    no_prompt: bool = False
) -> Tuple[List[ResolvedTarget], List[str]]:
    """
    Parses targets and exclusions, resolves IPs, and applies DNS safety rules.

    Args:
        targets (str): Targets provided by user
        exclude (str): Exclusion list
        no_prompt (bool): Skip DNS safety confirmation

    Returns:
        Tuple:
            - List of resolved targets
            - List of DNS-based targets
    """

    # Split user inputs
    target_list = _split_csv(targets)
    exclude_list = _split_csv(exclude)

    excluded_ips = set()
    excluded_names = set()

    # Process exclusions
    for item in exclude_list:
        if "/" in item:
            excluded_ips.update(_expand_cidr(item))
        elif _is_ip(item):
            excluded_ips.add(item)
        else:
            excluded_names.add(item.lower())

    # Identify DNS targets for safety prompt
    dns_targets = [t for t in target_list if not _is_ip(t) and "/" not in t]

    # ---------------- DNS SAFETY PROMPT ----------------
    if dns_targets and not no_prompt:
        print("\n[DNS SAFETY CHECK]")
        print("Configured DNS servers:")
        for dns in _get_dns_servers():
            print(f"  - {dns}")

        print("\nDNS targets to resolve:")
        for d in dns_targets:
            print(f"  - {d}")

        choice = input("\nProceed with DNS resolution? [y/N]: ").strip().lower()
        if choice != "y":
            raise SystemExit("DNS resolution aborted by user.")
    # --------------------------------------------------

    resolved: List[ResolvedTarget] = []

    # Process each target
    for target in target_list:
        # CIDR range
        if "/" in target:
            for ip in _expand_cidr(target):
                if ip not in excluded_ips:
                    resolved.append(ResolvedTarget(target, ip))
            continue

        # Direct IP
        if _is_ip(target):
            if target not in excluded_ips:
                resolved.append(ResolvedTarget(target, target))
            continue

        # DNS name
        if target.lower() in excluded_names:
            continue

        for ip in _resolve_dns(target):
            if ip not in excluded_ips:
                resolved.append(ResolvedTarget(target, ip, target))

    # Remove duplicate IPs
    seen = set()
    final_targets = []
    for r in resolved:
        if r.ip not in seen:
            seen.add(r.ip)
            final_targets.append(r)

    return final_targets, dns_targets


# ---------------------------------------------------------------------------
# Standalone testing (safe to remove later)
# ---------------------------------------------------------------------------
#if __name__ == "__main__":
    results, dns = parse_and_resolve_targets(
        targets="8.8.8.8,8.8.4.0/30,google.com",
        exclude="8.8.4.2",
        no_prompt=True
    )

    for r in results:
        print(r)
