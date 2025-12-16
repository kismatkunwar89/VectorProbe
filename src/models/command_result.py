"""
Command Result Data Model

This module defines the CommandResult dataclass for storing command execution results.
"""

from dataclasses import dataclass


@dataclass
class CommandResult:
    """
    Holds results of a command execution.

    This dataclass provides a standardized structure for command results
    across all handlers in the VectorProbe tool.

    Attributes:
        command: Exact command string that was run
        stdout: Normal output from command
        stderr: Error output from command
        exit_code: Return code (0 usually means success)
    """
    command: str
    stdout: str
    stderr: str
    exit_code: int
