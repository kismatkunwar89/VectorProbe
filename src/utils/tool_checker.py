"""
Tool Availability Checker Utility

Centralized utility for checking if required command-line tools are installed.
"""

import shutil
from typing import List, Optional


def ensure_tool_exists(
    tool_name: str,
    alternatives: Optional[List[str]] = None,
    install_hint: str = ""
) -> str:
    """
    Verify tool exists in PATH, check alternatives, raise if not found.

    This utility prevents code duplication across handlers by providing a
    centralized way to check for required command-line tools.

    Args:
        tool_name: Primary tool to check (e.g., "nmap")
        alternatives: Optional list of alternative tool names (e.g., ["enum4linux-ng", "enum4linux"])
        install_hint: Installation instructions for error message (e.g., "Install with: apt install nmap")

    Returns:
        The name of the found tool (primary or alternative)

    Raises:
        RuntimeError: If tool not found in PATH

    Examples:
        >>> ensure_tool_exists("nmap")
        'nmap'

        >>> ensure_tool_exists("enum4linux-ng", alternatives=["enum4linux"])
        'enum4linux'  # if enum4linux-ng not found but enum4linux is

        >>> ensure_tool_exists("masscan", install_hint="Visit: https://github.com/robertdavidgraham/masscan")
        RuntimeError: masscan not found in PATH. Visit: https://github.com/robertdavidgraham/masscan
    """
    # Check primary tool
    if shutil.which(tool_name):
        return tool_name

    # Check alternatives
    if alternatives:
        for alt in alternatives:
            if shutil.which(alt):
                return alt

    # Build error message
    tools = [tool_name] + (alternatives or [])
    tools_str = " or ".join(tools)
    msg = f"{tools_str} not found in PATH."
    if install_hint:
        msg += f" {install_hint}"

    raise RuntimeError(msg)
