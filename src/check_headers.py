"""Non-destructive header and cookie inspection for an auth page.

Usage: python check_headers.py https://svpradius.emsi.ma/login
"""
from __future__ import annotations

import argparse
import re
import sys
from http import client

import requests

COOKIE_RE = re.compile(r"(?P<name>[^=]+)=(?P<value>[^;]+);?\s*(?P<flags>.*)")


def parse_set_cookie(set_cookie: str) -> dict:
    m = COOKIE_RE.match(set_cookie)
    if not m:
        return {"raw": set_cookie}
    name = m.group("name").strip()
    value = m.group("value").strip()
    flags = m.group("flags") or ""
    attrs = {"HttpOnly": False, "Secure": False, "SameSite": None}
    if "httponly" in flags.lower():
        attrs["HttpOnly"] = True
    if "secure" in flags.lower():
        attrs["Secure"] = True
    s = re.search(r"samesite=([A-Za-z]+)", flags, re.I)
    if s:
        attrs["SameSite"] = s.group(1)
    return {"name": name, "value": value, **attrs}


def check_headers(url: str, timeout: float = 5.0) -> dict:
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    headers = dict(resp.headers)
    cookies = []
    for sc in resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else resp.headers.get("Set-Cookie", ""):
        if not sc:
            continue
        # requests aggregates Set-Cookie into a single header sometimes; split on comma if multiple
        parts = sc.split(",") if "," in sc and "expires=" not in sc.lower() else [sc]
        for p in parts:
            parsed = parse_set_cookie(p.strip())
            cookies.append(parsed)
    return {"status_code": resp.status_code, "url": resp.url, "headers": headers, "cookies": cookies}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Header + cookie checker")
    parser.add_argument("url")
    args = parser.parse_args(argv)

    try:
        result = check_headers(args.url)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}")
        return 2

    print(f"URL: {result['url']}")
    print(f"Status: {result['status_code']}")
    print("Headers:")
    for k, v in result["headers"].items():
        print(f"  {k}: {v}")
    print("Cookies:")
    if not result["cookies"]:
        print("  (none)")
    for c in result["cookies"]:
        if "name" in c:
            print(f"  {c['name']}: HttpOnly={c['HttpOnly']} Secure={c['Secure']} SameSite={c['SameSite']}")
        else:
            print(f"  raw: {c.get('raw')}")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
