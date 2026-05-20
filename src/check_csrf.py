"""Check for CSRF token presence on a login page (non-destructive).

Usage: python check_csrf.py https://svpradius.emsi.ma/login
"""
from __future__ import annotations

import argparse
import requests
from bs4 import BeautifulSoup

COMMON_NAMES = [
    "csrfmiddlewaretoken",
    "csrf_token",
    "csrf",
    "authenticity_token",
    "_csrf",
    "_csrf_token",
]


def find_csrf_tokens(html: str) -> list[tuple[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    tokens: list[tuple[str, str]] = []
    for name in COMMON_NAMES:
        el = soup.find("input", {"name": name})
        if el and el.get("type") in ("hidden", None):
            tokens.append((name, el.get("value", "")))

    # also look for meta tag
    meta = soup.find("meta", {"name": "csrf-token"}) or soup.find("meta", {"name": "csrf_token"})
    if meta and meta.get("content"):
        tokens.append((meta.get("name"), meta.get("content")))
    return tokens


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CSRF token checker")
    parser.add_argument("url")
    args = parser.parse_args(argv)

    try:
        resp = requests.get(args.url, timeout=6)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}")
        return 2

    tokens = find_csrf_tokens(resp.text)
    if tokens:
        print("Possible CSRF tokens found:")
        for name, val in tokens:
            print(f"  {name}: (value length={len(val)})")
    else:
        print("No obvious CSRF tokens found in form inputs or meta tags.")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
