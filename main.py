"""
main.py
-------
Network Scanner — CLI entry point

Examples:
  # Scan top 1024 ports on a single host
  python main.py -t scanme.nmap.org

  # Scan a custom port range with banners
  python main.py -t 192.168.1.1 -p 1-65535 --banners

  # Discover live hosts on a subnet
  python main.py --discover 192.168.1.0/24

  # Save results to JSON
  python main.py -t 192.168.1.1 --output results.json

  # Save results to CSV
  python main.py -t 192.168.1.1 --output results.csv
"""

import argparse
import sys
import os

from scanner.port_scanner import scan_range
from scanner.host_discovery import discover_hosts
from scanner.banner_grabber import enrich_scan_results
from scanner.reporter import print_report, save_json, save_csv


BANNER = r"""
  _   _      _      _____
 | \ | | ___| |_   / ____|
 |  \| |/ _ \ __| | (___   ___ __ _ _ __  _ __   ___ _ __
 | . ` |  __/ |_   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |\___|\__|  ____) | (_| (_| | | | | | | |  __/ |
 |_| \_|      _   |_____/ \___\__,_|_| |_|_| |_|\___|_|
              | |
   _ __   ___ | |_ _   _
  | '_ \ / _ \| __| | | |
  | | | |  __/| |_| |_| |
  |_| |_|\___| \__|\__, |
                    __/ |
                   |___/   v1.0  — for authorised use only
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="netscanner",
        description="A simple network port scanner and host discovery tool.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Target options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-t", "--target",
        metavar="HOST",
        help="Target IP or hostname for port scan (e.g. 192.168.1.1)",
    )
    group.add_argument(
        "--discover",
        metavar="NETWORK",
        help="Discover live hosts in a CIDR range (e.g. 192.168.1.0/24)",
    )

    # Port range
    parser.add_argument(
        "-p", "--ports",
        metavar="RANGE",
        default="1-1024",
        help="Port range to scan, e.g. 1-1024 or 80-443 (default: 1-1024)",
    )

    # Options
    parser.add_argument(
        "--banners",
        action="store_true",
        help="Grab service banners from open ports (slower)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SECS",
        help="Timeout per port/host probe in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        metavar="N",
        help="Number of concurrent threads (default: 100)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show each open port as it's found",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to file (.json or .csv)",
    )

    return parser.parse_args()


def parse_port_range(port_str: str) -> tuple[int, int]:
    """Parse '80-443' into (80, 443). Validates range."""
    try:
        if "-" in port_str:
            parts = port_str.split("-")
            start, end = int(parts[0]), int(parts[1])
        else:
            start = end = int(port_str)

        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        if start > end:
            raise ValueError("Start port must be <= end port")

        return start, end
    except (ValueError, IndexError) as e:
        print(f"[!] Invalid port range '{port_str}': {e}")
        sys.exit(1)


def save_output(results: dict, filepath: str) -> None:
    """Save results to JSON or CSV based on file extension."""
    _, ext = os.path.splitext(filepath.lower())
    if ext == ".json":
        save_json(results, filepath)
    elif ext == ".csv":
        save_csv(results, filepath)
    else:
        print(f"[!] Unknown file format '{ext}'. Use .json or .csv")


def main():
    print(BANNER)
    args = parse_args()

    # ── Host discovery mode ──────────────────────────────────────────────────
    if args.discover:
        results = discover_hosts(
            network=args.discover,
            timeout=args.timeout,
            max_threads=args.threads,
            verbose=args.verbose,
        )
        print_report(results)

        if args.output:
            save_output(results, args.output)

    # ── Port scan mode ───────────────────────────────────────────────────────
    else:
        start_port, end_port = parse_port_range(args.ports)

        results = scan_range(
            host=args.target,
            start_port=start_port,
            end_port=end_port,
            timeout=args.timeout,
            max_threads=args.threads,
            verbose=args.verbose,
        )

        # Optionally enrich with banner info
        if args.banners and results.get("open_ports"):
            print("[*] Grabbing service banners...")
            results = enrich_scan_results(results, timeout=args.timeout)

        print_report(results, show_banners=args.banners)

        if args.output:
            save_output(results, args.output)


if __name__ == "__main__":
    main()