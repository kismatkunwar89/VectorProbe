import subprocess
import logging
from typing import Optional

from models.command_result import CommandResult

# Get the logger for this module
logger = logging.getLogger(__name__)


def execute_command(
    command: list[str],
    timeout: Optional[int] = None
) -> CommandResult:
    """
    Execute external command with optional timeout support.

    This is the centralized command execution utility used by all handlers
    to ensure consistent error handling, logging, and result formatting.

    Args:
        command: List of strings representing the command and its arguments
        timeout: Optional timeout in seconds (None for no timeout)

    Returns:
        CommandResult object with stdout, stderr, exit_code, and command string

    Raises:
        No exceptions raised - all errors captured in CommandResult
    """
    command_str = ' '.join(command)

    try:
        logger.info(f"Executing command: {command_str}")

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout
        )

        if process.returncode != 0:
            logger.warning(
                f"Command '{command_str}' finished with non-zero exit code {process.returncode}."
            )
            if process.stderr:
                logger.debug(f"Stderr: {process.stderr.strip()}")

        return CommandResult(
            command=command_str,
            stdout=process.stdout,
            stderr=process.stderr,
            exit_code=process.returncode
        )

    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {timeout} seconds"
        logger.error(f"Timeout executing '{command_str}': {error_msg}")
        return CommandResult(
            command=command_str,
            stdout="",
            stderr=error_msg,
            exit_code=-1
        )

    except FileNotFoundError:
        error_msg = f"Command not found: {command[0]}"
        logger.error(f"Error: Command '{command[0]}' not found. Is it installed and in your PATH?")
        return CommandResult(
            command=command_str,
            stdout="",
            stderr=error_msg,
            exit_code=-1
        )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"An unexpected error occurred while executing command: {e}")
        return CommandResult(
            command=command_str,
            stdout="",
            stderr=error_msg,
            exit_code=-1
        )
