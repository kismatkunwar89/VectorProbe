#!/usr/bin/env python3
"""
Network Enumeration Tool - Main Entry Point

This is where the program starts. It sets up logging, parses command-line
arguments, and kicks off the enumeration process.
"""

import logging
import sys
from utils.logger import setup_logging
from utils.banner import print_banner
from cli.argument_parser import parse_args
from handlers.masscan_handler import MasscanHandler
from parsers.masscan_parser import MasscanParser


def main():
    """
    Main function - the starting point of our program.

    This function:
    1. Displays the ASCII banner
    2. Sets up logging
    3. Parses command-line arguments
    4. Executes the appropriate scanning workflow
    """
    # Display the ASCII art banner
    print_banner(version="1.0.0")

    # Set up logging (INFO level means we see INFO, WARNING, ERROR, CRITICAL)
    logger = setup_logging(logging.INFO)

    # Log initialization
    logger.info("Initialization complete - Ready for enumeration")

    # Parse command-line arguments
    args = parse_args()
    logger.info(
        f"Arguments parsed: targets={args.targets}, fast_scan={args.fast_scan}")

    # Check if --fast-scan flag is present
    if args.fast_scan:
        logger.info(
            "Fast scan mode enabled - using Masscan for initial host discovery")

        try:
            # Initialize Masscan handler
            masscan = MasscanHandler(timeout_sec=300)

            # Run Masscan on targets
            logger.info(f"Running Masscan on targets: {args.targets}")
            result = masscan.scan_targets(
                targets=args.targets,
                top_ports=1000,
                rate=100000
            )

            logger.info(f"Masscan command executed: {result.command}")
            logger.info(f"Masscan exit code: {result.exit_code}")

            if result.exit_code == 0 and result.stdout:
                # Parse Masscan output
                parser = MasscanParser(result.stdout)
                hosts = parser.parse()
                logger.info(f"Masscan discovered {len(hosts)} hosts")

                for host_info in hosts:
                    logger.info(
                        f"Host {host_info['host']}: {len(host_info['ports'])} open ports")
            elif result.stderr:
                logger.warning(f"Masscan stderr: {result.stderr}")

        except RuntimeError as e:
            logger.error(f"Masscan error: {e}")
            logger.info("Proceeding without fast scan...")
    else:
        logger.info("Standard scan mode - skipping Masscan discovery")

    logger.info("Enumeration workflow complete")


if __name__ == "__main__":
    main()
