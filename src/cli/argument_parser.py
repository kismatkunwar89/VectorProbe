#requests
#dnspython
#python-nmap
#paramiko
#pyyaml
import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="VectorProbe",
        description="Network enumeration tool that generates a Markdown report.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-t", "--targets",
        required=True,
        help="Targets to scan: IP, CIDR, DNS, or comma-separated mix."
    )

    parser.add_argument(
        "-x", "--exclude",
        default="",
        help="Excluded out-of-scope hosts: IP, CIDR, DNS, or comma-separated mix."
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output report path/filename. If not given, uses a UTC timestamp filename."
    )

    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Disable interactive prompts (DNS safety prompt)."
    )

    return parser

def parse_args(argv=None):
    return build_parser().parse_args(argv)
