#!/usr/bin/env python3
"""
Network Enumeration Tool - Main Entry Point

This is where the program starts. It sets up logging, parses command-line
arguments, and kicks off the enumeration process.
"""

import logging
from utils.logger import setup_logging


def main():
    """
    Main function - the starting point of our program.

    This function:
    1. Sets up logging
    2. Displays a welcome message
    3. Will later parse arguments and start scanning
    """
    # Set up logging (INFO level means we see INFO, WARNING, ERROR, CRITICAL)
    logger = setup_logging(logging.INFO)

    # Log some messages at different levels
    logger.info("=" * 60)
    logger.info("Network Enumeration Tool - Starting Up")
    logger.info("=" * 60)

    logger.debug("This is a debug message - only shows if DEBUG level is set")
    logger.info("This is an info message - normal operation")
    logger.warning("This is a warning - something unexpected")
    logger.error("This is an error - something failed")

    logger.info("Initialization complete!")


if __name__ == "__main__":
    main()
