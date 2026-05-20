"""TLS certificate inspector (non-destructive).

Usage: python check_tls.py svpradius.emsi.ma
"""
from __future__ import annotations

import argparse
import socket
import ssl
from datetime import datetime


def get_cert(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    return cert


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TLS certificate checker")
    parser.add_argument("host")
    args = parser.parse_args(argv)

    try:
        cert = get_cert(args.host)
    except Exception as exc:
        print(f"Failed to retrieve certificate: {exc}")
        return 2

    subject = cert.get("subject", [])
    issuer = cert.get("issuer", [])
    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")

    def fmt_name(tuples):
        parts = []
        for t in tuples:
            for k, v in t:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    print(f"Subject: {fmt_name(subject)}")
    print(f"Issuer: {fmt_name(issuer)}")
    if not_after:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        print(f"Expires: {exp.isoformat()}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
