# requests
# dnspython
# python-nmap
# paramiko
# pyyaml
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
        "--scan-type",
        choices=["default", "quick", "full", "udp"],
        default="default",
        help=(
            "Scan type: "
            "'default' = TCP SYN scan on top 1000 ports with service/OS detection (-sS -sV -sC -O); "
            "'quick' = Fast scan on top 100 TCP ports (--top-ports 100); "
            "'full' = Complete scan of all 65535 TCP ports (-p-); "
            "'udp' = UDP scan on top 20 common UDP ports (-sU --top-ports 20)"
        )
    )

    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Disable interactive prompts (DNS safety prompt)."
    )

    return parser


def parse_args(argv=None):
    return build_parser().parse_args(argv)
