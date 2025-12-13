#!/usr/bin/env python3
"""
Logging configuration for the Network Enumeration Tool.

This module sets up logging so we can track what the program is doing,
catch errors, and debug issues.
"""

import logging
import sys
from datetime import datetime


def setup_logging(log_level=logging.INFO):
    """
    Configure logging for the application.

    Args:
        log_level: The minimum level of messages to display
                   (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        A configured logger object

    Example:
        >>> logger = setup_logging(logging.DEBUG)
        >>> logger.info("This is an info message")
        >>> logger.error("This is an error message")
    """

    # Create a logger with our application name
    logger = logging.getLogger('NetEnumTool')
    logger.setLevel(log_level)

    # Remove any existing handlers (prevents duplicate messages)
    logger.handlers.clear()

    # Create a handler that outputs to the console (terminal)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create a formatter that defines how log messages look
    # Format: [2024-12-10 15:30:45] INFO: Starting scan...
    log_format = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Attach the formatter to the handler
    console_handler.setFormatter(log_format)

    # Attach the handler to the logger
    logger.addHandler(console_handler)

    return logger


def get_logger():
    """
    Get the application logger.

    Returns:
        The configured logger object

    Example:
        >>> logger = get_logger()
        >>> logger.info("Getting logger")
    """
    return logging.getLogger('NetEnumTool')
