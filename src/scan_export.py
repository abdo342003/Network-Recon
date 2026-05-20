"""Run the local network recon and export responsive hosts to CSV or JSON.

Usage: python scan_export.py --cidr 192.168.1.0/24 --out results.csv
Or use --auto to auto-detect CIDR.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from typing import List

from network_recon import run_scan, auto_detect_private_cidr


def parse_hosts_from_output(text: str) -> List[dict]:
    hosts = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        parts = line[1:].strip().split(maxsplit=1)
        ip = parts[0]
        hostname = parts[1].strip() if len(parts) > 1 else None
        hosts.append({"ip": ip, "hostname": hostname})
    return hosts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run network_recon and export results")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="Target CIDR, e.g., 192.168.1.0/24")
    group.add_argument("--auto", action="store_true", help="Auto-detect local CIDR")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--workers", type=int, default=64)
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--arp", action="store_true")
    parser.add_argument("--out", required=True, help="Output file (csv or json)")
    args = parser.parse_args(argv)

    cidr = None
    if args.auto:
        cidr = auto_detect_private_cidr()
    else:
        cidr = args.cidr

    output_text = run_scan(cidr, args.timeout, args.workers, args.dns, args.arp)
    hosts = parse_hosts_from_output(output_text)

    if args.out.lower().endswith(".csv"):
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "hostname"])
            w.writeheader()
            for h in hosts:
                w.writerow(h)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(hosts, f, indent=2)

    print(f"Exported {len(hosts)} hosts to {args.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
