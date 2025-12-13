import subprocess
import logging

# Get the logger for this module
logger = logging.getLogger(__name__)

def execute_command(command: list[str]) -> tuple[str, str, int]:
    """
    Executes an external command and captures its stdout, stderr, and return code.

    Args:
        command: A list of strings representing the command and its arguments.

    Returns:
        A tuple containing:
        - The standard output (stdout) as a string.
        - The standard error (stderr) as a string.
        - The exit code as an integer.
    """
    try:
        command_str = ' '.join(command)
        logger.info(f"Executing command: {command_str}")
        
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False 
        )
        
        if process.returncode != 0:
            logger.warning(
                f"Command '{command_str}' finished with non-zero exit code {process.returncode}."
            )
            if process.stderr:
                logger.debug(f"Stderr: {process.stderr.strip()}")

        return process.stdout, process.stderr, process.returncode

    except FileNotFoundError:
        logger.error(f"Error: Command '{command[0]}' not found. Is it installed and in your PATH?")
        return "", f"Command not found: {command[0]}", -1
    except Exception as e:
        logger.error(f"An unexpected error occurred while executing command: {e}")
        return "", str(e), -1
