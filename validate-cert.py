#!/usr/bin/env python3
from src.verify import verify_certificate_chain
from src.colors import *
from src.logger import set_verbose_mode, get_logger

import sys
import argparse


def parse_arguments():
    """Parse command line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="Validate certificate chains",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-f", "--format",
        choices=["DER", "PEM"],
        required=True,
        help="Certificate format (DER or PEM)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "certificates",
        nargs="+",
        help="Certificate files to validate"
    )

    return parser.parse_args()


def main():
    """Main entry point for the certificate validation tool."""
    try:
        args = parse_arguments()

        # Set global verbose mode and get a logger for this module
        set_verbose_mode(args.verbose)
        logger = get_logger()

        if args.verbose:
            logger.debug(f"Running with format: {args.format}")
            logger.debug(f"Certificates to verify: {args.certificates}")

        # Verify the certificate chain
        result = verify_certificate_chain(args.format, args.certificates)

        if result:
            print(colored("✓ Certificate chain is valid", Colors.GREEN))
            return 0
        else:
            print(colored("✗ Certificate chain is invalid", Colors.RED))
            return 1

    except Exception as e:
        print(colored(f"Error: {str(e)}", Colors.RED))
        return 1


if __name__ == "__main__":
    sys.exit(main())