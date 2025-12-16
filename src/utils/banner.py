"""
ASCII art banner and CLI styling utilities for VectorProbe.

This module provides visually appealing banners and formatting for the CLI interface.
"""

import sys
from typing import Optional


def print_banner(version: str = "1.0.0") -> None:
    """
    Prints the VectorProbe ASCII art banner to the terminal.

    Args:
        version: The version string to display
    """
    banner = r"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗                   ║
║   ██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗                  ║
║   ██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝                  ║
║   ╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗                  ║
║    ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║                  ║
║     ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝                  ║
║                                                                          ║
║   ██████╗ ██████╗  ██████╗ ██████╗ ███████╗                            ║
║   ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝                            ║
║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗                              ║
║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝                              ║
║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗                            ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝                            ║
║                                                                          ║
║             Network Enumeration & Security Assessment Tool              ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

    print(banner)
    print(f"                              Version: {version}")
    print(f"                          Developed for Ethical Use Only")
    print()


def print_section_header(title: str, width: int = 76) -> None:
    """
    Prints a formatted section header.

    Args:
        title: The section title
        width: The total width of the header (default 76 to fit banner)
    """
    border = "═" * width
    padding = (width - len(title) - 2) // 2

    print(f"\n╔{border}╗")
    print(f"║{' ' * padding}{title}{' ' * (width - padding - len(title))}║")
    print(f"╚{border}╝\n")


def print_subsection(title: str) -> None:
    """
    Prints a formatted subsection title.

    Args:
        title: The subsection title
    """
    print(f"\n┌─ {title}")


def print_item(label: str, value: str, indent: int = 2) -> None:
    """
    Prints a formatted key-value item.

    Args:
        label: The item label
        value: The item value
        indent: Number of spaces to indent (default 2)
    """
    prefix = " " * indent
    print(f"{prefix}• {label}: {value}")


def print_list_item(item: str, indent: int = 2) -> None:
    """
    Prints a formatted list item.

    Args:
        item: The item text
        indent: Number of spaces to indent (default 2)
    """
    prefix = " " * indent
    print(f"{prefix}• {item}")


def print_success(message: str) -> None:
    """
    Prints a success message with formatting.

    Args:
        message: The success message
    """
    print(f"✓ {message}")


def print_warning(message: str) -> None:
    """
    Prints a warning message with formatting.

    Args:
        message: The warning message
    """
    print(f"⚠ {message}")


def print_error(message: str) -> None:
    """
    Prints an error message with formatting.

    Args:
        message: The error message
    """
    print(f"✗ {message}", file=sys.stderr)


def print_progress(message: str) -> None:
    """
    Prints a progress message with formatting.

    Args:
        message: The progress message
    """
    print(f"→ {message}")


# Example usage demonstration
if __name__ == "__main__":
    # Display banner
    print_banner()

    # Example section
    print_section_header("TARGET RESOLUTION")
    print_item("Total Targets", "254")
    print_item("Excluded", "1")
    print_item("Final Scope", "253 hosts")

    # Example subsection
    print_subsection("Resolved Targets")
    print_list_item("192.168.1.2")
    print_list_item("192.168.1.3")
    print_list_item("192.168.1.4")

    # Example messages
    print()
    print_success("Target resolution completed successfully")
    print_warning("Large CIDR range detected - scan may take time")
    print_error("Invalid IP address: 999.999.999.999")
    print_progress("Starting nmap scan...")
