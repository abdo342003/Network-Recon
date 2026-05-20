"""Simple report generator that aggregates header/TLS/CSRF checks into a markdown file.

Usage: python report_generator.py --url https://svpradius.emsi.ma/login --out report.md
"""
from __future__ import annotations

import argparse
import subprocess
import textwrap
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def run_cmd(cmd: list[str]) -> str:
    completed = subprocess.run(cmd, capture_output=True, text=True)
    return completed.stdout + completed.stderr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate quick checks into a markdown report")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    # Run checks (non-destructive)
    headers = run_cmd([sys.executable, str(ROOT / "check_headers.py"), args.url])
    tls = ""
    try:
        from urllib.parse import urlparse

        host = urlparse(args.url).hostname
        if host:
            tls = run_cmd([sys.executable, str(ROOT / "check_tls.py"), host])
    except Exception:
        tls = "TLS check skipped"

    csrf = run_cmd([sys.executable, str(ROOT / "check_csrf.py"), args.url])

    content = []
    content.append(f"# Quick Auth Assessment Report for {args.url}\n")
    content.append("## Headers\n")
    content.append("```")
    content.append(headers)
    content.append("```)\n")
    content.append("## TLS\n")
    content.append("```")
    content.append(tls)
    content.append("```)\n")
    content.append("## CSRF\n")
    content.append("```")
    content.append(csrf)
    content.append("```)\n")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(content))

    print(f"Report written to {args.out}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
