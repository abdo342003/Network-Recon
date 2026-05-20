#!/usr/bin/env python3
"""Local network discovery for an authorized lab.

What it does:
- ICMP sweep of a private CIDR, optional reverse DNS, optional ARP dump (timing in log)
- Host intel: parallel TCP probes, ping/TTL, ARP/OUI hints, optional SSH banner on :22
- Optional parallel HTTP(S) fingerprints (GET /, Server header, HTML title)
- Optional traceroute excerpt; subnet calculator; probe presets
- MITRE ATT&CK-aligned session notes, sweep deltas vs last run, purple-team tips
- Session ZIP bundle (hosts JSON, Navigator stub, optional intel snapshot)

TCP probes use a user-defined port list (defaults); not a full port scan.
"""

from __future__ import annotations

import errno
import concurrent.futures as futures
import csv
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import random
import zipfile
import queue
import re
import time
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Iterable

# Enhanced NetworkRecon modules
try:
    from network_logger import get_logger, LogContext
    from dns_cache import DNSCache, CachedDNSResolver, get_dns_cache_path
    from html_report import generate_html_report
    from scan_history import ScanHistory
    from config_manager import ConfigManager
    from security_framework import (
        AuthorizationManager, AuditLogger, SecurityCompliance, DataEncryption
    )
    from extended_discovery import (
        MultiSubnetScanner, NetworkHierarchyMapper, LargeNetworkScanner
    )
    ENHANCED_MODULES_AVAILABLE = True
    SECURITY_MODULES_AVAILABLE = True
except ImportError as e:
    ENHANCED_MODULES_AVAILABLE = False
    SECURITY_MODULES_AVAILABLE = False
    get_logger = lambda n: __import__('logging').getLogger(n)
    LogContext = None


def app_version_string() -> str:
    try:
        from importlib.metadata import version

        return version("pentesting-lab-tools")
    except Exception:
        return "0.2.0"


# Global logger and enhanced utilities
_logger = get_logger("network_recon")
_dns_cache: DNSCache | None = None
_dns_resolver: CachedDNSResolver | None = None
_scan_history: ScanHistory | None = None
_config_manager: ConfigManager | None = None
_authorization_manager: AuthorizationManager | None = None
_audit_logger: AuditLogger | None = None
_security_compliance: SecurityCompliance | None = None
_multi_subnet_scanner: MultiSubnetScanner | None = None
_last_scan_completed_at: datetime | None = None
_SCAN_COOLDOWN_SECONDS = 5.0


def _audit_username() -> str:
    """Return the best available username for audit events."""
    for env_var in ("USERNAME", "USER", "LOGNAME"):
        value = os.environ.get(env_var)
        if value:
            return value
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def initialize_enhanced_modules() -> None:
    """Initialize enhanced modules if available."""
    global _dns_cache, _dns_resolver, _scan_history, _config_manager
    global _authorization_manager, _audit_logger, _security_compliance
    global _multi_subnet_scanner
    
    if not ENHANCED_MODULES_AVAILABLE:
        return
    
    try:
        # Initialize DNS cache
        cache_path = get_dns_cache_path()
        _dns_cache = DNSCache(cache_path=cache_path, ttl_seconds=3600)
        _dns_resolver = CachedDNSResolver(_dns_cache)
        _logger.debug(f"DNS cache initialized at {cache_path}")
        
        # Initialize scan history
        _scan_history = ScanHistory(max_entries=100)
        _logger.debug("Scan history initialized")
        
        # Initialize config manager
        _config_manager = ConfigManager()
        _logger.debug("Config manager initialized")
        
    except Exception as e:
        _logger.warning(f"Failed to initialize some enhanced modules: {e}")
    
    # Initialize security framework if available
    if SECURITY_MODULES_AVAILABLE:
        try:
            _authorization_manager = AuthorizationManager()
            _audit_logger = AuditLogger()
            _security_compliance = SecurityCompliance()
            _multi_subnet_scanner = MultiSubnetScanner(max_workers=4)
            _logger.debug("Security framework initialized")
            _logger.info("Authorization and audit logging enabled")
        except Exception as e:
            _logger.warning(f"Failed to initialize security framework: {e}")



# --- Lab-oriented ATT&CK Enterprise references (reporting / purple team education only)
MITRE_SCAN_TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1018", "Remote System Discovery", "ICMP echo sweep enumerates responsive hosts on the target subnet."),
    ("T1590.002", "Gather Victim Identity Information: DNS", "PTR lookups when Reverse DNS is enabled."),
    ("T1016", "System Network Configuration Discovery", "Local ARP cache review when enabled."),
]

MITRE_INTEL_TECHNIQUES: list[tuple[str, str, str]] = [
    ("T1046", "Network Service Discovery", "TCP connection attempts to operator-selected ports."),
    ("T1592", "Gather Victim Host Information", "ICMP TTL / OS-path hints and SSH or HTTP banners."),
]

PURPLE_TEAM_TIPS: list[str] = [
    "SOC cue: burst ICMP from one workstation across a full /24 often correlates with ping-sweep tools.",
    "Detection idea: alert on >50 TCP SYNs from one internal host to many peers on uncommon ports within 60s.",
    "Noise tip: schedule heavy sweeps in maintenance windows so NIDS baselines stay trustworthy.",
    "Purple tip: export JSON after each run — chain deltas tell a story auditors understand.",
    "Lab hygiene: snapshot VM snapshots before testing lateral-movement chains.",
]


def app_state_dir() -> Path:
    if platform.system().lower() == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    else:
        base = Path.home() / ".config"
    d = base / "NetworkRecon"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_previous_scan_ips() -> set[str]:
    path = app_state_dir() / "previous_scan_ips.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("ips", []))
    except (OSError, json.JSONDecodeError, TypeError):
        return set()


def save_previous_scan_ips(ips: Iterable[str]) -> None:
    path = app_state_dir() / "previous_scan_ips.json"
    payload = {
        "ips": sorted(set(ips)),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def format_mitre_session_block(dns: bool, arp: bool) -> str:
    lines = ["", "══ MITRE ATT&CK · lab mapping (discovery sweep) ══", ""]
    for tid, name, blurb in MITRE_SCAN_TECHNIQUES:
        if tid.startswith("T1590") and not dns:
            continue
        if tid == "T1016" and not arp:
            continue
        lines.append(f"  · {tid} — {name}")
        lines.append(f"      {blurb}")
        lines.append("")
    lines.append("(References: https://attack.mitre.org/ — authorized scope only.)")
    lines.append("")
    return "\n".join(lines)


def format_mitre_intel_block() -> str:
    lines = ["", "══ MITRE ATT&CK · lab mapping (device intel pass) ══", ""]
    for tid, name, blurb in MITRE_INTEL_TECHNIQUES:
        lines.append(f"  · {tid} — {name}")
        lines.append(f"      {blurb}")
        lines.append("")
    lines.append("")
    return "\n".join(lines)


def format_scan_delta_block(previous: set[str], current: set[str]) -> str:
    new = sorted(current - previous)
    gone = sorted(previous - current)
    lines = ["══ Scan delta (session memory vs previous run) ══", ""]
    if not previous:
        lines.append("First sweep recorded — future runs will highlight newcomers.")
    elif not new and not gone:
        lines.append("No IP churn vs last sweep on this workstation.")
    else:
        if new:
            lines.append(f"New since last run ({len(new)}): " + ", ".join(new))
        if gone:
            lines.append(f"No longer seen ({len(gone)}): " + ", ".join(gone))
    lines.append("")
    return "\n".join(lines)


def lab_risk_notes_from_ports(tcp_states: dict[str, str]) -> list[str]:
    """Educational hints only — not a vulnerability assessment."""
    notes: list[str] = []
    ts = {int(k): v for k, v in tcp_states.items()}
    if ts.get(445) == "open":
        notes.append("TCP/445 open — SMB surface; validate signing & auth on lab targets.")
    if ts.get(3389) == "open":
        notes.append("TCP/3389 open — RDP exposure; restrict NLA / MFA policies in real deployments.")
    if ts.get(5985) == "open" or ts.get(5986) == "open":
        notes.append("WinRM listener likely — review privileged sessions.")
    if ts.get(23) == "open":
        notes.append("Telnet is rarely justified — lab artifact or legacy device.")
    if ts.get(21) == "open":
        notes.append("FTP observed — prefer SFTP in production designs.")
    return notes


def session_bundle_fingerprint(cidr: str, ips: list[str]) -> str:
    blob = "|".join(sorted(ips)) + "|" + cidr + "|" + app_version_string()
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_attack_navigator_stub(dns: bool, arp: bool, include_intel_techniques: bool) -> dict[str, Any]:
    techniques: list[dict[str, str]] = []
    for tid, name, _ in MITRE_SCAN_TECHNIQUES:
        if tid.startswith("T1590") and not dns:
            continue
        if tid == "T1016" and not arp:
            continue
        techniques.append({"techniqueID": tid, "techniqueName": name})
    if include_intel_techniques:
        for tid, name, _ in MITRE_INTEL_TECHNIQUES:
            techniques.append({"techniqueID": tid, "techniqueName": name})
    return {
        "description": "Network Recon lab stub — layer for ATT&CK Navigator coursework.",
        "name": "NetworkRecon session layer",
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
    }


def write_session_bundle_zip(
    path: str,
    *,
    hosts: list[dict[str, Any]],
    intel: dict[str, Any] | None,
    meta: dict[str, Any],
    dns: bool,
    arp: bool,
    include_intel_techniques: bool,
) -> None:
    stub = build_attack_navigator_stub(dns, arp, include_intel_techniques)
    summary_md = "\n".join(
        [
            "# Network Recon — session bundle",
            "",
            f"- Exported (UTC): `{meta.get('exported_at', '')}`",
            f"- App version: `{meta.get('app_version', '')}`",
            f"- Session fingerprint: `{meta.get('fingerprint', '')}`",
            f"- Target CIDR: `{meta.get('cidr', '')}`",
            "",
            "## Hosts",
            "",
            *[f"- `{h.get('ip')}` — PTR: {h.get('hostname') or '—'}" for h in hosts],
            "",
            "Authorized lab use only.",
            "",
        ]
    )
    rich_hosts = {
        "meta": meta,
        "hosts": hosts,
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("SUMMARY.md", summary_md.encode("utf-8"))
        zf.writestr("hosts.json", json.dumps(rich_hosts, indent=2).encode("utf-8"))
        zf.writestr("attack_navigator_layer.stub.json", json.dumps(stub, indent=2).encode("utf-8"))
        if intel:
            zf.writestr("last_intel.json", json.dumps(intel, indent=2).encode("utf-8"))


# Default TCP probes for lab device profiling (common services only).
_DEFAULT_PROBE_PORTS = (22, 80, 443, 445, 3389, 8080)

_PROBE_PORT_PRESETS: dict[str, str] = {
    "default": "22,80,443,445,3389,8080",
    "web": "80,443,8080,8443,8000,8888",
    "windows_lab": "135,139,445,3389,5985,5986",
}

# Ports eligible for application-layer HTTP(S) fingerprinting when open.
_HTTP_PLAINTEXT_PORTS = frozenset({80, 8080, 8000, 8008, 8888, 8880})
_HTTPS_PORTS = frozenset({443, 8443})

# Common IEEE OUI prefixes (hex with colons) for lab triage — not exhaustive.
_KNOWN_OUI_VENDOR: dict[str, str] = {
    "00:0c:29": "VMware",
    "00:1c:14": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen",
    "52:54:00": "QEMU/KVM (common)",
    "bc:24:11": "Proxmox/QEMU (common)",
}


def _tcp_refused_codes() -> set[int]:
    codes = {10061}  # WSAECONNREFUSED (Windows)
    if hasattr(errno, "ECONNREFUSED"):
        codes.add(int(errno.ECONNREFUSED))
    return codes


@dataclass(frozen=True)
class HostResult:
    ip: str
    alive: bool
    hostname: str | None = None


def _hidden_subprocess_kwargs() -> dict[str, object]:
    if platform.system().lower() != "windows":
        return {}

    startup_info = subprocess.STARTUPINFO()
    startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup_info.wShowWindow = 0
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
        "startupinfo": startup_info,
    }

def validate_private_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    network = ipaddress.ip_network(cidr, strict=False)
    if not network.is_private:
        raise ValueError("Refusing to scan non-private ranges. Use an RFC1918 or ULA lab network.")
    return network


def _cidr_from_ip_and_mask(ip_text: str, mask_text: str) -> str:
    network = ipaddress.IPv4Network(f"{ip_text}/{mask_text}", strict=False)
    return network.with_prefixlen


def _collect_windows_ipv4_adapters(ipconfig_output: str) -> list[dict[str, str]]:
    adapters: list[dict[str, str]] = []
    current_name = ""
    current_ip = ""
    current_mask = ""
    current_gateway = ""

    adapter_header = re.compile(r"^[A-Za-z].* adapter (.+):$")
    ip_pattern = re.compile(r"IPv4 Address[^:]*:\s*([0-9.]+)")
    mask_pattern = re.compile(r"Subnet Mask[^:]*:\s*([0-9.]+)")
    gateway_pattern = re.compile(r"Default Gateway[^:]*:\s*([0-9.]+)")

    lines = ipconfig_output.splitlines()
    for line in lines:
        header_match = adapter_header.match(line.strip())
        if header_match:
            if current_ip and current_mask:
                adapters.append(
                    {
                        "name": current_name,
                        "ip": current_ip,
                        "mask": current_mask,
                        "gateway": current_gateway,
                    }
                )
            current_name = header_match.group(1)
            current_ip = ""
            current_mask = ""
            current_gateway = ""
            continue

        ip_match = ip_pattern.search(line)
        if ip_match:
            current_ip = ip_match.group(1)
            continue

        mask_match = mask_pattern.search(line)
        if mask_match:
            current_mask = mask_match.group(1)
            continue

        gateway_match = gateway_pattern.search(line)
        if gateway_match:
            current_gateway = gateway_match.group(1)

    if current_ip and current_mask:
        adapters.append(
            {
                "name": current_name,
                "ip": current_ip,
                "mask": current_mask,
                "gateway": current_gateway,
            }
        )

    return adapters


def _select_default_route_interface_ip(route_output: str) -> str | None:
    route_pattern = re.compile(
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9.]+)\s+([0-9.]+)\s+(\d+)\s*$"
    )
    best_ip = None
    best_metric = None

    for line in route_output.splitlines():
        match = route_pattern.match(line)
        if not match:
            continue
        gateway_ip = match.group(1)
        interface_ip = match.group(2)
        metric = int(match.group(3))

        # Ignore unresolved default route placeholders.
        if gateway_ip == "0.0.0.0":
            continue

        if best_metric is None or metric < best_metric:
            best_metric = metric
            best_ip = interface_ip

    return best_ip


def auto_detect_private_cidr() -> str:
    system = platform.system().lower()

    if system == "windows":
        ipconfig_output = subprocess.run(
            ["ipconfig"],
            check=False,
            capture_output=True,
            text=True,
            **_hidden_subprocess_kwargs(),
        ).stdout
        route_output = subprocess.run(
            ["route", "print", "-4"],
            check=False,
            capture_output=True,
            text=True,
            **_hidden_subprocess_kwargs(),
        ).stdout

        adapters = _collect_windows_ipv4_adapters(ipconfig_output)
        default_interface_ip = _select_default_route_interface_ip(route_output)

        if default_interface_ip:
            for adapter in adapters:
                if adapter["ip"] != default_interface_ip:
                    continue
                ip_obj = ipaddress.ip_address(adapter["ip"])
                if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                    return _cidr_from_ip_and_mask(adapter["ip"], adapter["mask"])

        # Fallback to private adapter with a configured default gateway.
        for adapter in adapters:
            if not adapter["gateway"]:
                continue
            ip_obj = ipaddress.ip_address(adapter["ip"])
            if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                return _cidr_from_ip_and_mask(adapter["ip"], adapter["mask"])

        # Final fallback to any private adapter.
        for adapter in adapters:
            ip_obj = ipaddress.ip_address(adapter["ip"])
            if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
                return _cidr_from_ip_and_mask(adapter["ip"], adapter["mask"])

        raise ValueError("Could not detect a private IPv4 adapter from ipconfig output.")

    # Cross-platform fallback: infer /24 when mask is not easily available.
    host_ip = socket.gethostbyname(socket.gethostname())
    ip_obj = ipaddress.ip_address(host_ip)
    if ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local:
        network = ipaddress.ip_network(f"{host_ip}/24", strict=False)
        return network.with_prefixlen
    raise ValueError("Could not detect a private adapter automatically on this OS.")


def get_local_adapters() -> list[tuple[str, str]]:
    """Module-level adapter discovery for CLI use.

    Returns a list of (display, cidr) tuples similar to the GUI helper.
    """
    adapters_list: list[tuple[str, str]] = []
    try:
        system = platform.system().lower()
        if system == "windows":
            ipconfig_output = subprocess.run(
                ["ipconfig"],
                check=False,
                capture_output=True,
                text=True,
                **_hidden_subprocess_kwargs(),
            ).stdout
            adapters = _collect_windows_ipv4_adapters(ipconfig_output)
            for a in adapters:
                try:
                    cidr = _cidr_from_ip_and_mask(a["ip"], a["mask"])
                except Exception:
                    continue
                display = f"{a['name']} — {a['ip']}/{a['mask']}"
                adapters_list.append((display, cidr))
            return adapters_list

        host_ip = socket.gethostbyname(socket.gethostname())
        network = ipaddress.ip_network(f"{host_ip}/24", strict=False)
        adapters_list.append((f"host — {host_ip}/24", network.with_prefixlen))
        return adapters_list
    except Exception:
        return adapters_list


def ping_one(ip: str, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]

    completed = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **_hidden_subprocess_kwargs(),
    )
    return completed.returncode == 0


def resolve_hostname(ip: str) -> str | None:
    """Resolve IP to hostname with caching if available."""
    # Try DNS cache first if available
    if _dns_resolver:
        return _dns_resolver.resolve_hostname(ip)
    
    # Fallback to direct socket resolution
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def discover_hosts(network: ipaddress._BaseNetwork, timeout: float, workers: int, dns: bool) -> list[HostResult]:
    addresses = [str(ip) for ip in network.hosts()]
    results: list[HostResult] = []

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(ping_one, ip, timeout): ip for ip in addresses}
        for future in futures.as_completed(future_map):
            ip = future_map[future]
            alive = future.result()
            hostname = resolve_hostname(ip) if alive and dns else None
            if alive:
                results.append(HostResult(ip=ip, alive=True, hostname=hostname))

    results.sort(key=lambda item: ipaddress.ip_address(item.ip))
    return results


def print_results(results: Iterable[HostResult]) -> None:
    rows = list(results)
    if not rows:
        print("No responsive hosts found.")
        return

    print("Alive hosts:")
    for host in rows:
        if host.hostname:
            print(f"- {host.ip:<15} {host.hostname}")
        else:
            print(f"- {host.ip}")


def format_results(results: Iterable[HostResult]) -> str:
    rows = list(results)
    if not rows:
        return "No responsive hosts found.\n"

    lines = ["Alive hosts:"]
    for host in rows:
        if host.hostname:
            lines.append(f"- {host.ip:<15} {host.hostname}")
        else:
            lines.append(f"- {host.ip}")
    return "\n".join(lines) + "\n"


def get_arp_table() -> str:
    if shutil.which("arp") is None:
        return "ARP command not available on this system.\n"

    completed = subprocess.run(
        ["arp", "-a"],
        check=False,
        capture_output=True,
        text=True,
        **_hidden_subprocess_kwargs(),
    )
    output = completed.stdout.strip()
    if not output:
        output = completed.stderr.strip() or "ARP table was empty."
    return "\nLocal ARP table:\n" + output + "\n"


def validate_private_host(ip_text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Reject non-private targets so lab tooling cannot be pointed at arbitrary internet hosts."""
    addr = ipaddress.ip_address(ip_text.strip())
    if addr.is_loopback or addr.is_link_local or addr.is_multicast:
        raise ValueError("Refusing: loopback, link-local, or multicast address.")
    if not addr.is_private:
        raise ValueError("Refusing: only RFC1918/ULA lab addresses are allowed.")
    return addr


def _ttl_os_hint(ttl: int | None) -> str:
    if ttl is None:
        return "unknown"
    # Rough heuristic for authorized lab education only (not definitive).
    if ttl <= 64:
        return "often Linux/Android/macOS or tracer adjusted (TTL≤64)"
    if ttl <= 128:
        return "often Windows (TTL≤128)"
    return "often network gear or unusual path (TTL>128)"


def parse_arp_row_for_ip(ip: str) -> tuple[str | None, str | None]:
    """Return (mac_or_none, entry_type_or_none) from `arp -a` output."""
    if shutil.which("arp") is None:
        return None, None
    completed = subprocess.run(
        ["arp", "-a"],
        check=False,
        capture_output=True,
        text=True,
        **_hidden_subprocess_kwargs(),
    )
    text = completed.stdout or completed.stderr or ""
    needle = ip.strip()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if needle not in line:
            continue
        # Windows: "192.168.1.1         aa-bb-cc-dd-ee-ff     dynamic"
        # Linux:   "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
        mac_match = re.search(r"((?:[0-9a-fA-F]{1,2}[-:]){5}[0-9a-fA-F]{1,2})", line)
        if not mac_match:
            continue
        mac = mac_match.group(1).replace("-", ":").lower()
        lower = line.lower()
        kind = None
        if "dynamic" in lower:
            kind = "dynamic"
        elif "static" in lower:
            kind = "static"
        elif "incomplete" in lower:
            kind = "incomplete"
        return mac, kind
    return None, None


def describe_lab_network(cidr_text: str) -> str:
    """Summarize a network for RFC1918/ULA lab planning."""
    net = ipaddress.ip_network(cidr_text.strip(), strict=False)
    if not net.is_private:
        raise ValueError("Calculator accepts private (RFC1918 / ULA) ranges only.")
    lines = [
        f"Network: {net.with_prefixlen}",
        f"Network address: {net.network_address}",
        f"Netmask: {net.netmask}  (/{net.prefixlen})",
    ]
    if net.version == 4:
        lines.append(f"Broadcast: {net.broadcast_address}")
    lines.append(f"Addresses in prefix: {net.num_addresses}")
    if net.version == 4 and net.prefixlen <= 30:
        lines.append(f"Usable IPv4 hosts (classic net+bcast exclusion): {max(0, net.num_addresses - 2)}")
    try:
        first = next(net.hosts())
        lines.append(f"First .hosts() address: {first}")
    except StopIteration:
        lines.append("First .hosts(): (none — e.g. /32 or non-standard split)")
    lines.append(f"Last address: {net[-1]}")
    return "\n".join(lines)


def ping_details(ip: str, timeout_sec: float) -> dict[str, object]:
    """One ICMP ping; parse latency and TTL when present."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(max(1, int(timeout_sec * 1000))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_sec))), ip]

    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        **_hidden_subprocess_kwargs(),
    )
    blob = ((completed.stdout or "") + "\n" + (completed.stderr or "")).lower()
    alive = completed.returncode == 0 or ("ttl=" in blob) or (" ttl=" in blob)

    time_ms: float | None = None
    # Windows: time=1ms or time<1ms
    m_time = re.search(r"(?:time[=<])(\d+)\s*ms", blob, re.I)
    if m_time:
        time_ms = float(m_time.group(1))
    else:
        m_time2 = re.search(r"time=([\d.]+)\s*ms", blob, re.I)
        if m_time2:
            time_ms = float(m_time2.group(1))

    ttl_val: int | None = None
    m_ttl = re.search(r"ttl[= ](\d+)", blob, re.I)
    if m_ttl:
        ttl_val = int(m_ttl.group(1))

    return {"alive": alive, "time_ms": time_ms, "ttl": ttl_val, "raw_excerpt": (completed.stdout or "")[:400]}


def _probe_single_tcp_port(ip: str, port: int, timeout: float) -> tuple[int, str]:
    addr_obj = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if addr_obj.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        err = sock.connect_ex((ip, port))
        if err == 0:
            state = "open"
        elif err in _tcp_refused_codes():
            state = "closed"
        else:
            state = "filtered_or_timeout"
    except OSError:
        state = "error"
    finally:
        sock.close()
    return port, state


def probe_tcp_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float,
    *,
    parallel: bool = True,
) -> dict[int, str]:
    """Return port -> state where state is open|closed|filtered|error."""
    port_list = tuple(sorted(set(ports)))
    if not port_list:
        return {}
    if not parallel or len(port_list) == 1:
        return dict(_probe_single_tcp_port(ip, p, timeout) for p in port_list)

    workers = min(48, max(4, len(port_list)))
    results: dict[int, str] = {}
    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(_probe_single_tcp_port, ip, p, timeout): p for p in port_list}
        for fut in futures.as_completed(future_map):
            port, state = fut.result()
            results[port] = state
    return results


def recv_ssh_banner(ip: str, timeout: float) -> str | None:
    """First line from SSH text banner if TCP/22 accepts (lab banner grab only)."""
    addr_obj = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if addr_obj.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, 22))
        data = sock.recv(768)
    except OSError:
        return None
    finally:
        sock.close()
    if not data:
        return None
    line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip("\r")
    return line[:240] if line else None


def parse_probe_ports(text: str) -> tuple[int, ...]:
    """Parse comma/semicolon-separated port list for custom probes."""
    out: list[int] = []
    for part in text.replace(";", ",").split(","):
        p = part.strip()
        if not p:
            continue
        n = int(p)
        if n < 1 or n > 65535:
            raise ValueError(f"Invalid port: {p}")
        out.append(n)
    if not out:
        raise ValueError("Provide at least one TCP port to probe.")
    return tuple(sorted(set(out)))


def mac_vendor_hint(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = ":".join(mac.lower().split(":")[:3])
    return _KNOWN_OUI_VENDOR.get(prefix)


def _http_host_header(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return f"[{ip}]"
    return ip


def _split_http_response(raw: bytes) -> tuple[str, dict[str, str], bytes]:
    idx = raw.find(b"\r\n\r\n")
    if idx == -1:
        return "", {}, raw
    header_blob = raw[:idx].decode("utf-8", errors="replace")
    body = raw[idx + 4 :]
    lines = header_blob.split("\r\n")
    status_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, rest = line.partition(":")
            headers[key.strip().lower()] = rest.strip()
    return status_line, headers, body


def _parse_http_status_code(status_line: str) -> int | None:
    parts = status_line.split(None, 2)
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def _extract_html_title(body: bytes) -> str | None:
    text = body[:65536].decode("utf-8", errors="ignore")
    match = re.search(r"<title[^>]*>\s*([^<]+?)\s*</title>", text, re.I | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:200] if title else None


def http_grab_lab(ip: str, port: int, use_tls: bool, timeout: float) -> dict[str, Any]:
    """Minimal GET / against a private lab host (TLS verification disabled intentionally)."""
    result: dict[str, Any] = {
        "port": port,
        "scheme": "https" if use_tls else "http",
        "error": None,
        "status_code": None,
        "server_header": None,
        "title": None,
    }
    host_hdr = _http_host_header(ip)
    addr_obj = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if addr_obj.version == 6 else socket.AF_INET
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        tcp = socket.socket(family, socket.SOCK_STREAM)
        tcp.settimeout(timeout)
        tcp.connect((ip, port))
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(tcp, server_hostname=ip)
            except Exception:
                tcp.close()
                raise
        else:
            sock = tcp

        req = (
            f"GET / HTTP/1.1\r\nHost: {host_hdr}\r\n"
            f"User-Agent: NetworkRecon-Lab/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(req.encode("utf-8", errors="replace"))

        chunks: list[bytes] = []
        total = 0
        while total < 98304:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            joined = b"".join(chunks)
            if b"\r\n\r\n" in joined and len(joined) > 4096:
                break

        raw = b"".join(chunks)
        status_line, hdrs, body = _split_http_response(raw)
        result["status_code"] = _parse_http_status_code(status_line)
        result["server_header"] = hdrs.get("server")
        result["title"] = _extract_html_title(body)
        ctype = hdrs.get("content-type", "")
        if ctype and "html" not in ctype.lower() and not result["title"]:
            result["note"] = f"non-html body ({ctype[:60]})"
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass

    return result


def traceroute_lab_excerpt(ip: str) -> str | None:
    """Short traceroute/tracert output for path context (best-effort)."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["tracert", "-d", "-h", "4", "-w", "600", ip]
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=22,
                **_hidden_subprocess_kwargs(),
            )
        else:
            tr_bin = shutil.which("traceroute") or shutil.which("tracepath")
            if not tr_bin:
                return None
            if tr_bin.endswith("tracepath"):
                cmd = [tr_bin, "-n", ip]
            else:
                cmd = [tr_bin, "-n", "-m", "4", "-w", "2", ip]
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=22)

        blob = (completed.stdout or "") + "\n" + (completed.stderr or "")
        blob = blob.strip()
        if not blob:
            return None
        return blob[:1600]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def gather_device_intel(
    ip: str,
    ping_timeout: float,
    tcp_timeout: float,
    ports: Iterable[int],
    *,
    grab_web: bool,
    trace_route: bool,
) -> dict[str, Any]:
    validate_private_host(ip)
    hostname = resolve_hostname(ip)
    detail = ping_details(ip, ping_timeout)
    ttl = detail.get("ttl")
    ttl_int = int(ttl) if ttl is not None else None

    mac, arp_kind = parse_arp_row_for_ip(ip)
    probe_results = probe_tcp_ports(ip, ports, tcp_timeout)

    ssh_banner: str | None = None
    if probe_results.get(22) == "open":
        ssh_banner = recv_ssh_banner(ip, min(3.5, tcp_timeout + 1.5))

    payload: dict[str, Any] = {
        "ip": ip,
        "reverse_dns": hostname,
        "icmp": {
            "alive": detail["alive"],
            "latency_ms": detail.get("time_ms"),
            "ttl": ttl_int,
            "ttl_hint": _ttl_os_hint(ttl_int) if ttl_int is not None else None,
        },
        "arp": {
            "mac": mac,
            "kind": arp_kind,
            "oui_vendor_hint": mac_vendor_hint(mac),
        },
        "tcp_ports": {str(p): probe_results[p] for p in sorted(probe_results.keys())},
        "ssh_banner": ssh_banner,
        "web_fingerprints": [],
        "traceroute_excerpt": None,
        "notes": "TTL/MAC hints are educational; TLS verification disabled for lab grabs only.",
    }

    if grab_web:
        http_tasks: list[tuple[int, bool, float]] = []
        for p, state in probe_results.items():
            if state != "open":
                continue
            if p in _HTTP_PLAINTEXT_PORTS:
                http_tasks.append((p, False, min(4.0, tcp_timeout + 2)))
            elif p in _HTTPS_PORTS:
                http_tasks.append((p, True, min(5.0, tcp_timeout + 3)))

        if len(http_tasks) <= 1:
            for p, use_tls, tmo in http_tasks:
                payload["web_fingerprints"].append(http_grab_lab(ip, p, use_tls, tmo))
        elif http_tasks:
            workers = min(8, len(http_tasks))
            grabs: list[dict[str, Any]] = []
            with futures.ThreadPoolExecutor(max_workers=workers) as pool:
                future_map = {
                    pool.submit(http_grab_lab, ip, p, use_tls, tmo): (p, use_tls)
                    for p, use_tls, tmo in http_tasks
                }
                for fut in futures.as_completed(future_map):
                    grabs.append(fut.result())
            grabs.sort(key=lambda item: (item.get("port") or 0, item.get("scheme") or ""))
            payload["web_fingerprints"].extend(grabs)

    if trace_route:
        payload["traceroute_excerpt"] = traceroute_lab_excerpt(ip)

    payload["lab_risk_notes"] = lab_risk_notes_from_ports(payload["tcp_ports"])
    payload["purple_team_tip"] = random.choice(PURPLE_TEAM_TIPS)

    return payload


def format_device_intel_report(payload: dict[str, Any]) -> str:
    """Human-readable report from gather_device_intel()."""
    ip = str(payload["ip"])
    lines: list[str] = [f"=== Device intel (authorized lab) — {ip} ===", "", "[Reverse DNS]"]
    lines.append(payload.get("reverse_dns") or "(no PTR record)")

    icmp = payload.get("icmp") or {}
    lines.extend(["", "[ICMP ping]"])
    lines.append(f"reachable: {icmp.get('alive')}")
    if icmp.get("latency_ms") is not None:
        lines.append(f"latency_ms: {icmp['latency_ms']}")
    if icmp.get("ttl") is not None:
        hint = icmp.get("ttl_hint") or ""
        lines.append(f"ttl: {icmp['ttl']} ({hint})")

    arp = payload.get("arp") or {}
    lines.extend(["", "[ARP / data-link]"])
    mac = arp.get("mac")
    if mac:
        oui = arp.get("oui_vendor_hint")
        extra = f" — OUI hint: {oui}" if oui else ""
        lines.append(f"mac: {mac} ({arp.get('kind') or 'seen'}){extra}")
    else:
        lines.append("mac: not in local ARP cache (ping or communicate to populate)")

    tcp_ports = payload.get("tcp_ports") or {}
    port_nums = sorted(int(k) for k in tcp_ports.keys())
    lines.extend(["", f"[TCP probes — {', '.join(str(p) for p in port_nums)}]"])
    for p in port_nums:
        lines.append(f"  port {p}: {tcp_ports[str(p)]}")

    ssh_banner = payload.get("ssh_banner")
    if ssh_banner:
        lines.extend(["", "[SSH banner — TCP/22]", ssh_banner])

    web = payload.get("web_fingerprints") or []
    if web:
        lines.extend(["", "[HTTP(S) application fingerprint]"])
        for item in web:
            port = item.get("port")
            scheme = item.get("scheme")
            if item.get("error"):
                lines.append(f"  {scheme}://{ip}:{port} — error: {item['error']}")
                continue
            status = item.get("status_code")
            srv = item.get("server_header") or "-"
            title = item.get("title") or "-"
            note = item.get("note")
            line = f"  {scheme}://{ip}:{port} — HTTP {status} | Server: {srv} | Title: {title}"
            lines.append(line)
            if note:
                lines.append(f"    ({note})")

    tre = payload.get("traceroute_excerpt")
    if tre:
        lines.extend(["", "[Traceroute excerpt]", tre])

    lines.extend(["", *format_mitre_intel_block().strip().splitlines()])
    risks = payload.get("lab_risk_notes") or []
    if risks:
        lines.extend(["", "[Lab posture hints — not a full VA]", *risks])
    tip = payload.get("purple_team_tip")
    if tip:
        lines.extend(["", "[Purple-team tip]", tip])

    lines.extend(["", str(payload.get("notes") or ""), ""])
    return "\n".join(lines)


def build_device_intel_report(
    ip: str,
    ping_timeout: float,
    tcp_timeout: float,
    ports: Iterable[int],
    *,
    grab_web: bool = True,
    trace_route: bool = False,
) -> str:
    payload = gather_device_intel(ip, ping_timeout, tcp_timeout, ports, grab_web=grab_web, trace_route=trace_route)
    return format_device_intel_report(payload)


def lab_rule_stem(ip: str) -> str:
    validate_private_host(ip)
    return "NetworkReconLab_" + ip.replace(".", "_")


def lab_block_local_windows(ip: str) -> str:
    """Add outbound+inbound block rules on this machine only (requires elevation)."""
    stem = lab_rule_stem(ip)
    out_name = f"{stem}_out"
    in_name = f"{stem}_in"
    specs = [
        (
            out_name,
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={out_name}", "dir=out", "action=block", f"remoteip={ip}", "enable=yes", "profile=any"],
        ),
        (
            in_name,
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={in_name}", "dir=in", "action=block", f"remoteip={ip}", "enable=yes", "profile=any"],
        ),
    ]
    messages: list[str] = []
    for label, cmd in specs:
        completed = subprocess.run(cmd, capture_output=True, text=True, **_hidden_subprocess_kwargs())
        if completed.returncode != 0:
            err = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(f"Firewall rule '{label}' failed ({completed.returncode}): {err or 'netsh error'}")
        messages.append(label)
    return f"Added Windows Firewall rules on this PC: {', '.join(messages)} (traffic to/from {ip} blocked locally)."


def lab_unblock_local_windows(ip: str) -> str:
    stem = lab_rule_stem(ip)
    removed: list[str] = []
    for suffix in ("_out", "_in"):
        name = f"{stem}{suffix}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        subprocess.run(cmd, capture_output=True, text=True, **_hidden_subprocess_kwargs())
        removed.append(name)
    return f"Removed lab rules if present: {', '.join(removed)}."


def lab_block_local_linux(ip: str) -> str:
    """Best-effort iptables when running as root (authorized lab)."""
    if os.name != "posix":
        raise RuntimeError("Linux iptables path only.")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("Linux blocking requires root for iptables (sudo).")

    ipt = shutil.which("iptables")
    if not ipt:
        raise RuntimeError("iptables not found.")

    cmds = [
        [ipt, "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"],
        [ipt, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
    ]
    for cmd in cmds:
        completed = subprocess.run(cmd, capture_output=True, text=True)
        if completed.returncode != 0:
            err = (completed.stderr or "").strip()
            raise RuntimeError(f"iptables failed: {err or completed.returncode}")

    return f"iptables: inserted DROP rules for {ip} (INPUT from / OUTPUT to). Remove manually when done."


def lab_unblock_local_linux(ip: str) -> str:
    if os.name != "posix":
        raise RuntimeError("Linux iptables path only.")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PermissionError("Linux unblock requires root for iptables (sudo).")

    ipt = shutil.which("iptables")
    if not ipt:
        raise RuntimeError("iptables not found.")

    for cmd in (
        [ipt, "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        [ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"],
    ):
        subprocess.run(cmd, capture_output=True, text=True)
    return f"iptables: attempted removal of DROP rules for {ip}."


def lab_block_local(ip: str) -> str:
    validate_private_host(ip)
    if ipaddress.ip_address(ip).version != 4:
        raise RuntimeError("Lab firewall quick-actions support IPv4 only; configure IPv6 rules manually if needed.")
    sysname = platform.system().lower()
    if sysname == "windows":
        return lab_block_local_windows(ip)
    if sysname == "linux":
        return lab_block_local_linux(ip)
    raise RuntimeError("Isolation test is implemented for Windows (netsh) and Linux root (iptables) only.")


def lab_unblock_local(ip: str) -> str:
    validate_private_host(ip)
    sysname = platform.system().lower()
    if sysname == "windows":
        return lab_unblock_local_windows(ip)
    if sysname == "linux":
        return lab_unblock_local_linux(ip)
    raise RuntimeError("Remove isolation is implemented for Windows and Linux only.")


def run_scan(cidr: str, timeout: float, workers: int, dns: bool, arp: bool, 
             auth_token: str | None = None) -> str:
    """Run network scan with optional authorization.
    
    Args:
        cidr: CIDR range to scan
        timeout: Ping timeout
        workers: Number of worker threads
        dns: Enable DNS resolution
        arp: Include ARP table
        auth_token: Optional authorization token
        
    Returns:
        Scan results as formatted string
    """
    global _last_scan_completed_at

    now = datetime.now(timezone.utc)
    if _last_scan_completed_at is not None:
        elapsed = (now - _last_scan_completed_at).total_seconds()
        if elapsed < _SCAN_COOLDOWN_SECONDS:
            remaining = _SCAN_COOLDOWN_SECONDS - elapsed
            raise RuntimeError(f"Scan cooldown active. Wait {remaining:.1f}s before running another scan.")

    network = validate_private_network(cidr)
    
    # Security checks if enabled
    if SECURITY_MODULES_AVAILABLE and _security_compliance:
        try:
            # Validate input for injection attacks
            _security_compliance.validate_input(cidr, input_type="cidr")
            
            # Validate scan scope
            scope_valid, scope_message = _security_compliance.validate_scan_scope(cidr)
            if not scope_valid:
                _logger.warning(f"Scan scope validation failed: {scope_message}")
                raise RuntimeError(f"Scan validation failed: {scope_message}")
            
            # Check authorization if token provided
            if auth_token and _authorization_manager:
                if not _authorization_manager.verify_authorization(cidr, auth_token):
                    _logger.warning(f"Authorization denied for {cidr} with token {auth_token[:8]}...")
                    _audit_logger.log_authorization_attempt(
                        user=_audit_username(),
                        token=auth_token,
                        cidr=cidr,
                        success=False,
                    )
                    raise RuntimeError("Authorization failed for this network scope")
                
                _logger.info(f"Authorization granted for {cidr}")
                _audit_logger.log_authorization_attempt(
                    user=_audit_username(),
                    token=auth_token,
                    cidr=cidr,
                    success=True,
                )
            
            # Log scan start
            if _audit_logger:
                _audit_logger.log_scan_start(
                    user=_audit_username(),
                    cidr=str(network),
                    scope=str(network),
                )
        
        except Exception as e:
            _logger.error(f"Security validation error: {e}")
            if _audit_logger:
                _audit_logger.log_security_event(
                    event_type="scan_blocked",
                    severity="CRITICAL",
                    description=str(e),
                    details={"cidr": cidr}
                )
            raise
    
    try:
        results = discover_hosts(network, timeout, workers, dns)
        output = format_results(results)
        if arp:
            output += get_arp_table()
        
        # Log scan completion
        if SECURITY_MODULES_AVAILABLE and _audit_logger:
            try:
                _audit_logger.log_scan_complete(
                    user=_audit_username(),
                    cidr=str(network),
                    host_count=len(results),
                    duration_seconds=0.0  # Duration would be tracked separately
                )
            except Exception as e:
                _logger.warning(f"Failed to log scan completion: {e}")
        
        return output
    finally:
        _last_scan_completed_at = datetime.now(timezone.utc)


class NetworkReconApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Network Recon — Lab")
        self.geometry("1040x760")
        self.minsize(920, 660)

        self._queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self._worker_thread: threading.Thread | None = None
        self._intel_thread: threading.Thread | None = None
        self._results: list[HostResult] = []
        self._last_intel_payload: dict[str, Any] | None = None
        self._previous_scan_ips: set[str] = load_previous_scan_ips()
        self._highlight_new_ips: set[str] = set()
        self._last_scan_meta: dict[str, Any] = {}
        self._sort_descending: dict[str, bool] = {"ip": False, "status": False, "hostname": False}

        self.cidr_var = tk.StringVar(value="192.168.1.0/24")
        self.timeout_var = tk.StringVar(value="1.0")
        self.workers_var = tk.StringVar(value="64")
        self.dns_var = tk.BooleanVar(value=True)
        self.arp_var = tk.BooleanVar(value=False)
        self.probe_ports_var = tk.StringVar(value="22,80,443,445,3389,8080")
        self.web_intel_var = tk.BooleanVar(value=True)
        self.trace_route_var = tk.BooleanVar(value=False)
        self.auth_token_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0 responsive hosts")
        self.target_summary_var = tk.StringVar(value=self.cidr_var.get())
        self.adapter_summary_var = tk.StringVar(value="Auto-detect")
        self.scan_summary_var = tk.StringVar(value="Idle")
        self.security_summary_var = tk.StringVar(
            value="Audit enabled" if SECURITY_MODULES_AVAILABLE and _audit_logger else "Security offline"
        )

        self._build_ui()
        self.after(100, self._poll_queue)

    def _configure_styles(self, style: ttk.Style) -> None:
        bg = "#0b1220"
        card = "#121c2e"
        banner = "#0f172a"
        inset = "#0c1424"
        accent = "#38bdf8"
        style.theme_use("clam")
        style.configure("Root.TFrame", background=bg)
        style.configure("Banner.TFrame", background=banner)
        style.configure("Card.TFrame", background=card)
        style.configure("Inset.TFrame", background=inset)
        style.configure("Title.TLabel", background=bg, foreground="#f8fbff", font=("Segoe UI", 22, "bold"))
        style.configure("Subtitle.TLabel", background=bg, foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("Ver.TLabel", background=inset, foreground="#64748b", font=("Segoe UI", 9))
        style.configure("Body.TLabel", background=card, foreground="#e2e8f0", font=("Segoe UI", 10))
        style.configure("Hint.TLabel", background=card, foreground="#8599b5", font=("Segoe UI", 9))
        style.configure("Section.TLabel", background=card, foreground="#93c5fd", font=("Segoe UI", 11, "bold"))
        style.configure("SummaryTitle.TLabel", background=card, foreground="#7c9cbc", font=("Segoe UI", 8, "bold"))
        style.configure("SummaryValue.TLabel", background=card, foreground="#f8fbff", font=("Segoe UI", 12, "bold"))
        style.configure("Badge.TLabel", background="#1e3a5f", foreground="#bae6fd", font=("Segoe UI", 9, "bold"), padding=(12, 5))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(18, 10))
        style.configure("Secondary.TButton", font=("Segoe UI", 9), padding=(12, 7))
        style.configure("Danger.TButton", font=("Segoe UI", 9), padding=(10, 6), background="#7f1d1d", foreground="#fecaca")
        style.map("Danger.TButton", background=[("active", "#991b1b"), ("pressed", "#450a0a")])
        style.configure(
            "TLabelframe",
            background=card,
            relief="solid",
            borderwidth=1,
            bordercolor="#223047",
        )
        style.configure("TLabelframe.Label", background=card, foreground="#93c5fd", font=("Segoe UI", 10, "bold"))
        style.configure(
            "Treeview",
            background="#0d1629",
            fieldbackground="#0d1629",
            foreground="#e8eef8",
            bordercolor="#223047",
            rowheight=32,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#1a2942",
            foreground="#f1f5f9",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview.Heading", background=[("active", "#243652")])
        style.map(
            "Accent.TButton",
            background=[("active", "#2563eb"), ("pressed", "#1d4ed8"), ("disabled", "#334155")],
            foreground=[("disabled", "#94a3b8")],
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#2d4a6f"), ("pressed", "#243e5c")],
        )
        style.map("Treeview", background=[("selected", "#1e3a5f")])
        style.configure(
            "TEntry",
            fieldbackground="#0d1629",
            foreground="#f1f5f9",
            insertcolor="#f1f5f9",
            bordercolor="#334155",
        )
        style.configure(
            "TCombobox",
            fieldbackground="#0d1629",
            foreground="#f1f5f9",
            bordercolor="#334155",
            arrowcolor="#94a3b8",
        )
        style.map("TCombobox", fieldbackground=[("readonly", "#0d1629")])
        style.configure(
            "TCheckbutton",
            background=card,
            foreground="#cbd5e1",
            font=("Segoe UI", 9),
        )
        style.map("TCheckbutton", background=[("active", card)])

    def _build_menubar(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export scan CSV…", command=self._export_csv)
        file_menu.add_command(label="Export scan JSON…", command=self._export_json)
        file_menu.add_command(label="Export as HTML Report…", command=self._export_html)
        file_menu.add_command(label="Export last intel JSON…", command=self._export_intel_json)
        file_menu.add_command(label="Export session bundle (ZIP)…", command=self._export_session_bundle)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Subnet calculator…", command=self._open_subnet_calc)
        tools_menu.add_command(label="Refresh adapters", command=self._populate_adapters)
        tools_menu.add_command(label="Clear activity log", command=self._clear_activity_log)
        tools_menu.add_command(label="Reset sweep delta memory", command=self._reset_sweep_delta_memory)
        tools_menu.add_separator()
        if ENHANCED_MODULES_AVAILABLE:
            tools_menu.add_command(label="Scan history…", command=self._show_scan_history)
            tools_menu.add_command(label="Clear DNS cache", command=self._clear_dns_cache)
            tools_menu.add_separator()
        tools_menu.add_command(label="Open report generator", command=self._open_report)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Keyboard shortcuts…", command=self._show_shortcuts_help)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About Network Recon",
            f"Network Recon — authorized lab discovery\n\n"
            f"Version {app_version_string()}\n"
            f"Author: Abdellah ERRAOUI\n\n"
            "Private RFC1918 / ULA ranges only.\n"
            "Use only on systems you are permitted to assess.",
        )

    def _show_shortcuts_help(self) -> None:
        messagebox.showinfo(
            "Shortcuts",
            "F5  — Run scan\n"
            "Ctrl+L — Clear activity log\n"
            "Double-click row — Copy IP address\n"
            "Right-click row — Context menu",
        )

    def _clear_activity_log(self) -> None:
        self.output.delete("1.0", "end")
        self._append_output("Activity log cleared.\n")

    def _reset_sweep_delta_memory(self) -> None:
        self._previous_scan_ips = set()
        save_previous_scan_ips([])
        self._highlight_new_ips = set()
        self._insert_results(list(self._results))
        self._append_output("Sweep delta memory cleared — next scan establishes a fresh baseline.\n")
        messagebox.showinfo("Delta reset", "Previous sweep IPs forgotten. New hosts will highlight after the next scan.")

    def _build_ui(self) -> None:
        self.configure(bg="#0b1220")

        accent = tk.Frame(self, bg="#38bdf8", height=4, highlightthickness=0)
        accent.pack(fill="x")

        root = ttk.Frame(self, style="Root.TFrame", padding=(18, 14, 18, 10))
        root.pack(fill="both", expand=True)

        style = ttk.Style(self)
        self._configure_styles(style)
        self._build_menubar()

        self.bind_all("<F5>", lambda e: self._start_scan())
        self.bind_all("<Control-l>", lambda e: self._clear_activity_log())
        self.bind_all("<Control-L>", lambda e: self._clear_activity_log())

        banner = ttk.Frame(root, style="Banner.TFrame", padding=(20, 18))
        banner.pack(fill="x")
        banner.columnconfigure(0, weight=1)
        ttk.Label(banner, text="Network Recon", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            banner,
            text="Discovery, DNS hints, ARP, parallel probes, HTTP(S) fingerprints — private lab subnets only.",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(banner, text="AUTHORIZED USE", style="Badge.TLabel").grid(row=0, column=1, rowspan=2, sticky="ne", padx=(12, 0))

        summary = ttk.Frame(root, style="Card.TFrame", padding=(18, 16))
        summary.pack(fill="x", pady=(14, 10))
        summary.columnconfigure((0, 1, 2, 3), weight=1)
        summary_cards = [
            ("Target", self.target_summary_var),
            ("Adapter", self.adapter_summary_var),
            ("Scan / session", self.scan_summary_var),
            ("Security", self.security_summary_var),
        ]
        for column, (title, variable) in enumerate(summary_cards):
            wrap = ttk.Frame(summary, style="Inset.TFrame", padding=(12, 10))
            wrap.grid(row=0, column=column, sticky="nsew", padx=(0, 10) if column < 3 else (0, 0))
            wrap.columnconfigure(0, weight=1)
            ttk.Label(wrap, text=title.upper(), style="SummaryTitle.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(wrap, textvariable=variable, style="SummaryValue.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))

        scan_labelframe = ttk.LabelFrame(root, text="  Discovery  ", padding=(14, 12))
        scan_labelframe.pack(fill="x", pady=(6, 10))

        form = ttk.Frame(scan_labelframe, style="Card.TFrame")
        form.pack(fill="x")
        form.columnconfigure((1, 2, 3), weight=1)

        ttk.Label(form, text="CIDR", style="Body.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        cidr_row = ttk.Frame(form, style="Card.TFrame")
        cidr_row.grid(row=0, column=1, sticky="ew", pady=6)
        cidr_row.columnconfigure(0, weight=1)
        ttk.Entry(cidr_row, textvariable=self.cidr_var, font=("Segoe UI", 10)).grid(row=0, column=0, sticky="ew")
        ttk.Button(cidr_row, text="Auto Detect", style="Secondary.TButton", command=self._auto_fill_cidr).grid(
            row=0, column=1, padx=(10, 6)
        )
        ttk.Button(cidr_row, text="Subnet calc", style="Secondary.TButton", command=self._open_subnet_calc).grid(
            row=0, column=2, padx=(4, 0)
        )
        ttk.Label(form, text="Adapter", style="Body.TLabel").grid(row=0, column=2, sticky="w", padx=(14, 10), pady=6)
        self.adapter_var = tk.StringVar(value="(auto)")
        self.adapter_combo = ttk.Combobox(form, textvariable=self.adapter_var, state="readonly", width=34)
        self.adapter_combo.grid(row=0, column=3, sticky="ew", pady=6)
        self.adapter_combo.bind("<<ComboboxSelected>>", lambda e: self._on_adapter_select())
        self._populate_adapters()

        ttk.Label(form, text="Auth token", style="Body.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        token_row = ttk.Frame(form, style="Card.TFrame")
        token_row.grid(row=1, column=1, columnspan=3, sticky="ew", pady=6)
        token_row.columnconfigure(0, weight=1)
        ttk.Entry(token_row, textvariable=self.auth_token_var, show="*", font=("Segoe UI", 10)).grid(
            row=0, column=0, sticky="ew"
        )
        ttk.Label(token_row, text="Optional, for logged authorization runs", style="Hint.TLabel").grid(
            row=1, column=0, sticky="w", pady=(4, 0)
        )

        ttk.Label(form, text="Timeout (sec)", style="Body.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.timeout_var, width=12, font=("Segoe UI", 10)).grid(row=2, column=1, sticky="w", pady=6)

        ttk.Label(form, text="Workers", style="Body.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.workers_var, width=12, font=("Segoe UI", 10)).grid(row=3, column=1, sticky="w", pady=6)

        ttk.Label(form, text="TCP probe ports", style="Body.TLabel").grid(row=4, column=0, sticky="nw", padx=(0, 10), pady=6)
        probe_row = ttk.Frame(form, style="Card.TFrame")
        probe_row.grid(row=4, column=1, columnspan=3, sticky="ew", pady=6)
        probe_row.columnconfigure(0, weight=1)
        ttk.Entry(probe_row, textvariable=self.probe_ports_var, font=("Segoe UI", 10)).grid(row=0, column=0, sticky="ew")
        preset_frm = ttk.Frame(probe_row, style="Card.TFrame")
        preset_frm.grid(row=0, column=1, padx=(8, 0))
        ttk.Button(preset_frm, text="Default", width=8, style="Secondary.TButton", command=lambda: self._apply_port_preset("default")).pack(
            side="left", padx=(0, 4)
        )
        ttk.Button(preset_frm, text="Web", width=7, style="Secondary.TButton", command=lambda: self._apply_port_preset("web")).pack(
            side="left", padx=(0, 4)
        )
        ttk.Button(
            preset_frm,
            text="Windows",
            width=9,
            style="Secondary.TButton",
            command=lambda: self._apply_port_preset("windows_lab"),
        ).pack(side="left", padx=(0, 4))

        options = ttk.Frame(form, style="Card.TFrame")
        options.grid(row=5, column=1, columnspan=3, sticky="w", pady=(6, 4))
        ttk.Label(options, text="Scan options", style="Hint.TLabel").pack(side="left", padx=(0, 12))
        ttk.Checkbutton(options, text="Reverse DNS", variable=self.dns_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(options, text="ARP table after sweep", variable=self.arp_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(options, text="Web fingerprint", variable=self.web_intel_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(options, text="Traceroute excerpt", variable=self.trace_route_var).pack(side="left")

        actions = ttk.Frame(root, style="Root.TFrame")
        actions.pack(fill="x", pady=(4, 12))
        self.run_button = ttk.Button(actions, text="▶  Run Scan", style="Accent.TButton", command=self._start_scan)
        self.run_button.pack(side="left")
        ttk.Button(actions, text="Export CSV", style="Secondary.TButton", command=self._export_csv).pack(side="left", padx=(10, 0))
        ttk.Button(actions, text="Export JSON", style="Secondary.TButton", command=self._export_json).pack(side="left", padx=(6, 0))
        ttk.Button(actions, text="Report", style="Secondary.TButton", command=self._open_report).pack(side="left", padx=(6, 0))
        status_wrap = ttk.Frame(actions, style="Root.TFrame")
        status_wrap.pack(side="left", padx=(16, 8), fill="x", expand=True)
        ttk.Label(status_wrap, textvariable=self.status_var, style="Subtitle.TLabel").pack(side="left")
        ttk.Label(actions, textvariable=self.count_var, style="Subtitle.TLabel").pack(side="right")

        self._main_paned = ttk.Panedwindow(root, orient=tk.VERTICAL)
        self._main_paned.pack(fill="both", expand=True, pady=(4, 0))

        table_card = ttk.LabelFrame(self._main_paned, text="  Live hosts  ", padding=(12, 10))
        self._main_paned.add(table_card, weight=3)

        table_header = ttk.Frame(table_card, style="Card.TFrame")
        table_header.pack(fill="x", pady=(0, 8))
        ttk.Label(table_header, text="Responsive endpoints", style="Section.TLabel").pack(side="left")
        ttk.Label(table_header, text="Sort columns · Double-click copies IP · Right-click menu", style="Hint.TLabel").pack(
            side="right"
        )

        table_wrap = ttk.Frame(table_card, style="Card.TFrame")
        table_wrap.pack(fill="both", expand=True)

        self.results_tree = ttk.Treeview(
            table_wrap,
            columns=("ip", "status", "hostname"),
            show="headings",
            selectmode="browse",
        )
        self.results_tree.heading("ip", text="IP Address", command=lambda: self._sort_results("ip"))
        self.results_tree.heading("status", text="Status", command=lambda: self._sort_results("status"))
        self.results_tree.heading("hostname", text="Hostname (PTR)", command=lambda: self._sort_results("hostname"))
        self.results_tree.column("ip", width=180, anchor="w", stretch=False)
        self.results_tree.column("status", width=100, anchor="center", stretch=False)
        self.results_tree.column("hostname", width=560, anchor="w")
        self._create_context_menu()
        self.results_tree.bind("<Button-3>", self._on_tree_right_click)
        self.results_tree.bind("<Double-1>", lambda event: self._copy_selected_ip())
        self.results_tree.tag_configure("even", background="#0c1528")
        self.results_tree.tag_configure("odd", background="#0a1222")
        self.results_tree.tag_configure("alive", foreground="#7dd3c0")
        self.results_tree.tag_configure("new_host", foreground="#fbbf24")

        results_scroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scroll.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        results_scroll.grid(row=0, column=1, sticky="ns")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)

        host_actions = ttk.Frame(table_card, style="Card.TFrame")
        host_actions.pack(fill="x", pady=(12, 2))
        host_actions.columnconfigure(0, weight=1)
        ttk.Label(host_actions, text="Selected host", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            host_actions,
            text="Firewall isolation is local to this PC · Admin rights on Windows",
            style="Hint.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 8))

        btn_row = ttk.Frame(host_actions, style="Card.TFrame")
        btn_row.grid(row=2, column=0, sticky="e")
        self.lab_unblock_btn = ttk.Button(btn_row, text="Remove block", style="Secondary.TButton", command=self._lab_unblock_selected)
        self.lab_unblock_btn.pack(side="right", padx=(6, 0))
        self.lab_block_btn = ttk.Button(btn_row, text="Block IP (lab)", style="Danger.TButton", command=self._lab_block_selected)
        self.lab_block_btn.pack(side="right", padx=(6, 0))
        self.copy_intel_btn = ttk.Button(btn_row, text="Copy intel", style="Secondary.TButton", command=self._copy_last_intel_report)
        self.copy_intel_btn.pack(side="right", padx=(6, 0))
        self.export_intel_btn = ttk.Button(btn_row, text="Export intel JSON", style="Secondary.TButton", command=self._export_intel_json)
        self.export_intel_btn.pack(side="right", padx=(6, 0))
        self.device_intel_btn = ttk.Button(btn_row, text="Device info", style="Accent.TButton", command=self._run_device_intel)
        self.device_intel_btn.pack(side="right", padx=(6, 0))

        log_card = ttk.LabelFrame(self._main_paned, text="  Activity log  ", padding=(10, 10))
        self._main_paned.add(log_card, weight=2)
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(1, weight=1)

        log_toolbar = ttk.Frame(log_card, style="Card.TFrame")
        log_toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(log_toolbar, text="Console output — scans, intel, and errors appear here", style="Hint.TLabel").pack(
            side="left"
        )
        ttk.Button(log_toolbar, text="Clear log", style="Secondary.TButton", command=self._clear_activity_log).pack(
            side="right"
        )

        # ScrolledText + explicit min height so the pane never collapses to invisible on Windows.
        self.output = ScrolledText(
            log_card,
            wrap="word",
            height=14,
            width=96,
            bg="#0d1117",
            fg="#f0f6fc",
            insertbackground="#f0f6fc",
            relief="flat",
            font=("Consolas", 10),
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#30363d",
            highlightcolor="#58a6ff",
            selectbackground="#264f78",
            selectforeground="#f0f6fc",
            undo=True,
            maxundo=-1,
            padx=10,
            pady=10,
        )
        self.output.grid(row=1, column=0, sticky="nsew")

        try:
            self._main_paned.paneconfigure(table_card, minsize=200)
            self._main_paned.paneconfigure(log_card, minsize=220)
        except tk.TclError:
            pass

        footer = ttk.Frame(root, style="Inset.TFrame", padding=(12, 8))
        footer.pack(fill="x", pady=(10, 0))
        ttk.Label(footer, text=f"v{app_version_string()}  ·  F5 run scan  ·  Ctrl+L clear log", style="Ver.TLabel").pack(
            side="left"
        )
        ttk.Label(footer, textvariable=self.count_var, style="Ver.TLabel").pack(side="right")

        self._append_output("Enter a private subnet and press Run Scan or F5.\n")
        self._auto_fill_cidr(log_errors=False)
        self.after(80, self._ensure_activity_pane_visible)

    def _ensure_activity_pane_visible(self, attempts: int = 0) -> None:
        """Position the vertical sash so the activity log keeps a visible height (fixes zero-height bottom pane on Windows)."""
        self.update_idletasks()
        try:
            ph = self._main_paned.winfo_height()
            if ph <= 80 and attempts < 15:
                self.after(120, lambda: self._ensure_activity_pane_visible(attempts + 1))
                return
            if ph > 80:
                # First sash: ~58% for live hosts, remainder for activity log (respects pane minsize).
                self._main_paned.sashpos(0, max(260, int(ph * 0.58)))
        except (tk.TclError, AttributeError):
            pass

    def _append_output(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")
        self.output.update_idletasks()

    def _clear_results(self) -> None:
        for item in self.results_tree.get_children(""):
            self.results_tree.delete(item)
        self.count_var.set("0 responsive hosts")
        self.scan_summary_var.set("Idle")

    def _get_local_adapters(self) -> list[tuple[str, str]]:
        """Return list of (display_name, cidr) for local adapters."""
        adapters_list: list[tuple[str, str]] = []
        try:
            system = platform.system().lower()
            if system == "windows":
                ipconfig_output = subprocess.run(
                    ["ipconfig"],
                    check=False,
                    capture_output=True,
                    text=True,
                    **_hidden_subprocess_kwargs(),
                ).stdout
                adapters = _collect_windows_ipv4_adapters(ipconfig_output)
                for a in adapters:
                    try:
                        cidr = _cidr_from_ip_and_mask(a["ip"], a["mask"])
                    except Exception:
                        continue
                    display = f"{a['name']} — {a['ip']}/{a['mask']}"
                    adapters_list.append((display, cidr))
                return adapters_list

            # Non-windows fallback: single host interface
            host_ip = socket.gethostbyname(socket.gethostname())
            network = ipaddress.ip_network(f"{host_ip}/24", strict=False)
            adapters_list.append((f"host — {host_ip}/24", network.with_prefixlen))
            return adapters_list
        except Exception:
            return adapters_list

    def _create_context_menu(self) -> None:
        self._menu = tk.Menu(self, tearoff=0)
        self._menu.add_command(label="Copy IP", command=self._copy_selected_ip)
        self._menu.add_command(label="Reverse DNS Lookup", command=self._reverse_dns_selected)
        self._menu.add_command(label="Forward DNS (hostname → IPs)", command=self._forward_dns_selected)
        self._menu.add_separator()
        self._menu.add_command(label="Device info (ARP, ping/TTL, TCP)", command=self._run_device_intel)
        self._menu.add_command(label="Lab: block IP on this PC", command=self._lab_block_selected)
        self._menu.add_command(label="Lab: remove firewall block", command=self._lab_unblock_selected)
        self._menu.add_separator()
        self._menu.add_command(label="Copy full intel report", command=self._copy_last_intel_report)

    def _on_tree_right_click(self, event) -> None:
        iid = self.results_tree.identify_row(event.y)
        if not iid:
            return
        self.results_tree.selection_set(iid)
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    def _copy_selected_ip(self) -> None:
        sel = self.results_tree.selection()
        if not sel:
            return
        vals = self.results_tree.item(sel[0], "values")
        ip = vals[0]
        try:
            self.clipboard_clear()
            self.clipboard_append(ip)
            self._append_output(f"Copied {ip} to clipboard.\n")
        except Exception:
            messagebox.showerror("Copy failed", "Could not copy to clipboard.")

    def _reverse_dns_selected(self) -> None:
        sel = self.results_tree.selection()
        if not sel:
            return
        vals = self.results_tree.item(sel[0], "values")
        ip = vals[0]
        hostname = resolve_hostname(ip)
        if hostname:
            messagebox.showinfo("Reverse DNS", f"{ip} → {hostname}")
            self._append_output(f"{ip} resolves to {hostname}\n")
        else:
            messagebox.showinfo("Reverse DNS", f"No PTR record for {ip}")
            self._append_output(f"No PTR record for {ip}\n")

    def _forward_dns_selected(self) -> None:
        sel = self.results_tree.selection()
        if not sel:
            return
        vals = self.results_tree.item(sel[0], "values")
        hostname = vals[2] if len(vals) > 2 else ""
        if not hostname or str(hostname).strip() in ("-", ""):
            messagebox.showinfo(
                "Forward DNS",
                "No hostname in this row. Run the scan with Reverse DNS enabled, or use another host.",
            )
            return
        hn = str(hostname).strip()
        try:
            infos = socket.getaddrinfo(hn, None, type=socket.SOCK_STREAM)
            ips = sorted({x[4][0] for x in infos})
            if not ips:
                messagebox.showinfo("Forward DNS", f"No addresses returned for {hn}")
                return
            lines = "\n".join(ips)
            messagebox.showinfo("Forward DNS", f"{hn}\n\n{lines}")
            self._append_output(f"Forward DNS {hn}: {', '.join(ips)}\n")
        except OSError as exc:
            messagebox.showinfo("Forward DNS", f"Lookup failed for {hn}: {exc}")
            self._append_output(f"Forward DNS failed for {hn}: {exc}\n")

    def _get_selected_ip(self) -> str | None:
        sel = self.results_tree.selection()
        if not sel:
            return None
        vals = self.results_tree.item(sel[0], "values")
        return str(vals[0]) if vals else None

    def _set_intel_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.device_intel_btn.configure(state=state)

    def _run_device_intel(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            messagebox.showinfo("No host", "Select a row in the results table first.")
            return
        try:
            validate_private_host(ip)
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return

        if self._intel_thread and self._intel_thread.is_alive():
            return

        try:
            ping_timeout = float(self.timeout_var.get().strip())
        except ValueError:
            ping_timeout = 1.0

        try:
            ports = parse_probe_ports(self.probe_ports_var.get().strip())
        except ValueError as exc:
            messagebox.showerror("Probe ports", str(exc))
            return

        self._append_output(f"Gathering device intel for {ip}...\n")
        self._set_intel_busy(True)

        def worker() -> None:
            try:
                payload = gather_device_intel(
                    ip,
                    ping_timeout=max(0.2, ping_timeout),
                    tcp_timeout=1.2,
                    ports=ports,
                    grab_web=self.web_intel_var.get(),
                    trace_route=self.trace_route_var.get(),
                )
                self._queue.put(("intel_ok", payload))
            except Exception as exc:  # noqa: BLE001
                self._queue.put(("intel_err", str(exc)))

        self._intel_thread = threading.Thread(target=worker, daemon=True)
        self._intel_thread.start()

    def _lab_block_selected(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            messagebox.showinfo("No host", "Select a row in the results table first.")
            return
        try:
            validate_private_host(ip)
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return

        confirm = messagebox.askyesno(
            "Lab isolation test (local only)",
            "This will configure the firewall on THIS machine to drop traffic to/from:\n\n"
            f"  {ip}\n\n"
            "It does not disconnect the device from the LAN for others — only affects connectivity "
            "from this PC. On Windows, run the app as Administrator.\n\n"
            "Continue?",
            icon="warning",
        )
        if not confirm:
            return

        try:
            msg = lab_block_local(ip)
            self._append_output(msg + "\n")
            messagebox.showinfo("Lab block", msg)
        except PermissionError as exc:
            messagebox.showerror("Permission denied", str(exc))
            self._append_output(f"Block failed: {exc}\n")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Block failed", str(exc))
            self._append_output(f"Block failed: {exc}\n")

    def _lab_unblock_selected(self) -> None:
        ip = self._get_selected_ip()
        if not ip:
            messagebox.showinfo("No host", "Select a row in the results table first.")
            return
        try:
            validate_private_host(ip)
        except ValueError as exc:
            messagebox.showerror("Invalid target", str(exc))
            return

        try:
            msg = lab_unblock_local(ip)
            self._append_output(msg + "\n")
            messagebox.showinfo("Lab unblock", msg)
        except PermissionError as exc:
            messagebox.showerror("Permission denied", str(exc))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Unblock failed", str(exc))
            self._append_output(f"Unblock failed: {exc}\n")

    def _export_intel_json(self) -> None:
        if not self._last_intel_payload:
            messagebox.showinfo("No intel", "Run Device info on a host first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._last_intel_payload, f, indent=2)
            messagebox.showinfo("Exported", f"Saved structured intel to {path}")
            self._append_output(f"Exported intel JSON to {path}\n")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def _copy_last_intel_report(self) -> None:
        if not self._last_intel_payload:
            messagebox.showinfo("Copy intel", "Run Device info on a host first.")
            return
        text = format_device_intel_report(self._last_intel_payload)
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self._append_output("Copied full intel report to clipboard.\n")
        except tk.TclError:
            messagebox.showerror("Copy failed", "Clipboard unavailable.")

    def _apply_port_preset(self, name: str) -> None:
        val = _PROBE_PORT_PRESETS.get(name)
        if not val:
            return
        self.probe_ports_var.set(val)
        self._append_output(f"TCP probe ports → preset '{name}'.\n")

    def _open_subnet_calc(self) -> None:
        win = tk.Toplevel(self)
        win.title("Subnet calculator (private lab)")
        win.geometry("540x380")
        win.configure(bg="#0b1220")
        win.transient(self)

        hint = ttk.Label(
            win,
            text="RFC1918 / ULA only — enter CIDR (e.g. 10.4.0.0/22)",
            foreground="#9eb1c8",
            background="#0b1220",
        )
        hint.pack(anchor="w", padx=14, pady=(14, 6))

        var = tk.StringVar(value=self.cidr_var.get().strip())
        entry = ttk.Entry(win, textvariable=var, width=52, font=("Segoe UI", 10))
        entry.pack(anchor="w", padx=14, pady=(0, 8))

        out = tk.Text(
            win,
            height=14,
            width=68,
            bg="#0b1220",
            fg="#e8eef5",
            font=("Consolas", 10),
            relief="flat",
            highlightthickness=1,
            highlightbackground="#223047",
        )
        out.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        def compute() -> None:
            out.delete("1.0", "end")
            try:
                out.insert("end", describe_lab_network(var.get()))
            except ValueError as exc:
                out.insert("end", str(exc))

        btn_row = ttk.Frame(win)
        btn_row.pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(btn_row, text="Compute", style="Accent.TButton", command=compute).pack(side="left")
        ttk.Button(btn_row, text="Apply to Target CIDR", style="Secondary.TButton", command=lambda: self._subnet_calc_apply(var, win)).pack(
            side="left", padx=(10, 0)
        )

        compute()

    def _subnet_calc_apply(self, var: tk.StringVar, win: tk.Toplevel) -> None:
        try:
            net = ipaddress.ip_network(var.get().strip(), strict=False)
            if not net.is_private:
                raise ValueError("Not a private range.")
            self.cidr_var.set(net.with_prefixlen)
            self._append_output(f"Target CIDR set to {net.with_prefixlen}\n")
            win.destroy()
        except ValueError as exc:
            messagebox.showerror("Invalid CIDR", str(exc))

    def _open_report(self) -> None:
        try:
            subprocess.Popen(
                [sys.executable, "report_generator.py"],
                cwd=".",
                **_hidden_subprocess_kwargs(),
            )
            self._append_output("Launched report_generator.py\n")
        except Exception as exc:
            messagebox.showerror("Failed to open report generator", str(exc))

    def _populate_adapters(self) -> None:
        vals = ["(auto)"]
        self._adapter_map = {"(auto)": None}
        found = self._get_local_adapters()
        for disp, cidr in found:
            vals.append(disp)
            self._adapter_map[disp] = cidr

        current = self.adapter_var.get()
        preferred_cidr = self.cidr_var.get().strip()
        if current not in self._adapter_map or current == "(auto)":
            current = next((disp for disp, cidr in found if cidr == preferred_cidr), current if current in self._adapter_map else "(auto)")

        try:
            self.adapter_combo['values'] = vals
            self.adapter_combo.set(current)
        except Exception:
            pass
        self._update_summary()

    def _on_adapter_select(self) -> None:
        sel = self.adapter_var.get()
        if not sel or sel == "(auto)":
            self.adapter_summary_var.set("Auto-detect")
            self._update_summary()
            return
        cidr = self._adapter_map.get(sel)
        if cidr:
            self.cidr_var.set(cidr)
            self.adapter_summary_var.set(sel)
            self._update_summary()

    def _update_summary(self) -> None:
        self.target_summary_var.set(self.cidr_var.get().strip() or "Not set")
        adapter_choice = self.adapter_var.get().strip()
        if adapter_choice and adapter_choice != "(auto)":
            self.adapter_summary_var.set(adapter_choice)
        else:
            self.adapter_summary_var.set("Auto-detect")
        self.scan_summary_var.set(self.status_var.get())

    def _export_csv(self) -> None:
        if not self._results:
            messagebox.showinfo("No results", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files","*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["ip", "hostname"])
                w.writeheader()
                for h in self._results:
                    w.writerow({"ip": h.ip, "hostname": h.hostname or ""})
            messagebox.showinfo("Exported", f"Exported {len(self._results)} hosts to {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _export_json(self) -> None:
        if not self._results:
            messagebox.showinfo("No results", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            ips = [h.ip for h in self._results]
            fp = session_bundle_fingerprint(self.cidr_var.get().strip(), sorted(ips))
            data: dict[str, Any] = {
                "meta": {
                    "app_version": app_version_string(),
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "session_fingerprint": fp,
                    "cidr": self.cidr_var.get().strip(),
                    "mitre_discovery_refs": [
                        {"id": tid, "name": name}
                        for tid, name, _ in MITRE_SCAN_TECHNIQUES
                        if not (tid.startswith("T1590") and not self.dns_var.get())
                        and not (tid == "T1016" and not self.arp_var.get())
                    ],
                },
                "hosts": [{"ip": h.ip, "hostname": h.hostname or None} for h in self._results],
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Exported", f"Exported {len(self._results)} hosts to {path}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _export_session_bundle(self) -> None:
        if not self._results:
            messagebox.showinfo("No results", "Run a scan first — nothing to bundle.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("ZIP bundle", "*.zip"), ("All files", "*.*")],
            title="Save session bundle",
        )
        if not path:
            return
        hosts = [{"ip": h.ip, "hostname": h.hostname or None} for h in self._results]
        meta = dict(self._last_scan_meta)
        meta.setdefault("exported_at", datetime.now(timezone.utc).isoformat())
        meta.setdefault("app_version", app_version_string())
        meta.setdefault("cidr", self.cidr_var.get().strip())
        meta.setdefault(
            "fingerprint",
            session_bundle_fingerprint(meta.get("cidr", ""), [h["ip"] for h in hosts]),
        )
        try:
            write_session_bundle_zip(
                path,
                hosts=hosts,
                intel=self._last_intel_payload,
                meta=meta,
                dns=self.dns_var.get(),
                arp=self.arp_var.get(),
                include_intel_techniques=bool(self._last_intel_payload),
            )
            messagebox.showinfo("Bundle saved", path)
            self._append_output(f"Session bundle written to {path}\n")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def _export_html(self) -> None:
        """Export scan results as HTML report."""
        if not ENHANCED_MODULES_AVAILABLE:
            messagebox.showinfo("Not available", "HTML export requires enhanced modules.")
            return
        if not self._results:
            messagebox.showinfo("No results", "No scan results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files","*.html"), ("All files", "*.*")])
        if not path:
            return
        try:
            hosts = [{"ip": h.ip, "hostname": h.hostname or None} for h in self._results]
            ips = [h.ip for h in self._results]
            meta = {
                "app_version": app_version_string(),
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "cidr": self.cidr_var.get().strip(),
                "fingerprint": session_bundle_fingerprint(self.cidr_var.get().strip(), sorted(ips)),
            }
            html = generate_html_report(hosts, meta, self._last_intel_payload)
            with open(path, 'w', encoding='utf-8') as f:
                f.write(html)
            messagebox.showinfo("Exported", f"HTML report saved to {path}")
            self._append_output(f"Exported HTML report to {path}\n")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            _logger.error(f"HTML export failed: {exc}")

    def _show_scan_history(self) -> None:
        """Show scan history dialog."""
        if not ENHANCED_MODULES_AVAILABLE or not _scan_history:
            messagebox.showinfo("Not available", "Scan history feature not available.")
            return
        
        scans = _scan_history.list_scans(limit=20)
        if not scans:
            messagebox.showinfo("Scan history", "No scans recorded yet.")
            return
        
        history_text = "Recent Scans:\n\n"
        for scan in scans:
            timestamp = scan.get("timestamp", "Unknown")
            cidr = scan.get("cidr", "Unknown")
            host_count = scan.get("host_count", 0)
            history_text += f"• {timestamp}\n  CIDR: {cidr} | Hosts: {host_count}\n\n"
        
        messagebox.showinfo("Scan History", history_text)

    def _clear_dns_cache(self) -> None:
        """Clear DNS cache."""
        if not ENHANCED_MODULES_AVAILABLE or not _dns_cache:
            messagebox.showinfo("Not available", "DNS cache not available.")
            return
        
        _dns_cache.clear()
        self._append_output("DNS cache cleared.\n")
        messagebox.showinfo("DNS Cache", "DNS cache has been cleared.")

    def _insert_results(self, results: list[HostResult]) -> None:
        self._results = list(results)
        self._clear_results()
        for index, host in enumerate(self._results):
            status = "Alive" if host.alive else "Down"
            hostname = host.hostname or "-"
            stripe = "even" if index % 2 == 0 else "odd"
            row_tags: list[str] = [stripe]
            if host.alive:
                row_tags.append("alive")
            if host.ip in self._highlight_new_ips:
                row_tags.append("new_host")
            self.results_tree.insert("", "end", values=(host.ip, status, hostname), tags=tuple(row_tags))
        self.count_var.set(f"{len(self._results)} responsive host{'s' if len(self._results) != 1 else ''}")
        self.scan_summary_var.set(f"{len(self._results)} hosts found")
        self._update_summary()

    def _sort_results(self, column: str) -> None:
        descending = self._sort_descending[column]
        self._sort_descending[column] = not descending

        if column == "ip":
            key = lambda host: ipaddress.ip_address(host.ip)
        elif column == "status":
            key = lambda host: host.alive
        else:
            key = lambda host: (host.hostname or "").lower()

        sorted_results = sorted(self._results, key=key, reverse=descending)
        self._insert_results(sorted_results)

    def _set_running(self, running: bool) -> None:
        self.run_button.configure(state="disabled" if running else "normal")
        self.status_var.set("Scanning..." if running else "Ready")
        self.scan_summary_var.set("Scanning" if running else "Idle")
        self._update_summary()

    def _auto_fill_cidr(self, log_errors: bool = True) -> None:
        try:
            cidr = auto_detect_private_cidr()
            self.cidr_var.set(cidr)
            self._append_output(f"Detected local subnet: {cidr}\n")
            # refresh adapter list after detection
            self._populate_adapters()
            self.target_summary_var.set(cidr)
        except ValueError as exc:
            if log_errors:
                messagebox.showerror("Auto detect failed", str(exc))
                self._append_output(f"Auto detect failed: {exc}\n")

    def _start_scan(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            return

        cidr = self.cidr_var.get().strip()
        timeout_text = self.timeout_var.get().strip()
        workers_text = self.workers_var.get().strip()

        try:
            float(timeout_text)
            int(workers_text)
            validate_private_network(cidr)
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        self.output.delete("1.0", "end")
        self._append_output(f"Scanning {cidr}...\n")
        self._clear_results()
        self.scan_summary_var.set(f"Scanning {cidr}")
        self._update_summary()
        self._set_running(True)

        def worker() -> None:
            try:
                t0 = time.perf_counter()
                result = run_scan(
                    cidr=cidr,
                    timeout=float(timeout_text),
                    workers=max(1, int(workers_text)),
                    dns=self.dns_var.get(),
                    arp=self.arp_var.get(),
                    auth_token=self.auth_token_var.get().strip() or None,
                )
                elapsed = time.perf_counter() - t0
                result = result.rstrip() + f"\n--- Sweep finished in {elapsed:.2f}s ---\n"
                self._queue.put(("ok", result))
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                self._queue.put(("err", str(exc)))

        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()

    def _poll_queue(self) -> None:
        try:
            kind, payload = self._queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_queue)
            return

        if kind == "ok":
            self._set_running(False)
            results: list[HostResult] = []
            for line in payload.splitlines():
                if not line.startswith("-"):
                    continue
                parts = line[1:].strip().split(maxsplit=1)
                ip = parts[0]
                hostname = parts[1].strip() if len(parts) > 1 else None
                results.append(HostResult(ip=ip, alive=True, hostname=hostname if hostname != "-" else None))

            current_ips = {h.ip for h in results}
            prev_snapshot = self._previous_scan_ips
            self._highlight_new_ips = current_ips - prev_snapshot if prev_snapshot else set()
            self._previous_scan_ips = set(current_ips)
            save_previous_scan_ips(current_ips)

            cidr = self.cidr_var.get().strip()
            fp = session_bundle_fingerprint(cidr, sorted(current_ips))
            self._last_scan_meta = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "app_version": app_version_string(),
                "fingerprint": fp,
                "cidr": cidr,
                "host_count": len(results),
                "reverse_dns": self.dns_var.get(),
                "arp_dump": self.arp_var.get(),
            }

            self._append_output(payload)
            self._append_output(format_mitre_session_block(self.dns_var.get(), self.arp_var.get()))
            self._append_output(format_scan_delta_block(prev_snapshot, current_ips))
            self._append_output(f"Session fingerprint: {fp}\n")
            self._append_output(f"Purple-team tip: {random.choice(PURPLE_TEAM_TIPS)}\n\n")

            self._insert_results(results)
        elif kind == "err":
            self._set_running(False)
            messagebox.showerror("Scan failed", payload)
            self._append_output(f"Error: {payload}\n")
        elif kind == "intel_ok":
            self._set_intel_busy(False)
            if isinstance(payload, dict):
                self._last_intel_payload = payload
                self._append_output(format_device_intel_report(payload) + "\n")
            else:
                self._append_output(str(payload) + "\n")
        elif kind == "intel_err":
            self._set_intel_busy(False)
            messagebox.showerror("Device intel failed", payload)
            self._append_output(f"Device intel error: {payload}\n")

        self.after(100, self._poll_queue)


def launch_gui() -> None:
    _logger.info(f"Launching GUI - NetworkRecon v{app_version_string()}")
    app = NetworkReconApp()
    app.mainloop()
    _logger.info("GUI closed")


def parse_cli_args(argv: list[str]) -> tuple[str, float, int, bool, bool]:
    cidr = ""
    timeout = 1.0
    workers = 64
    dns = False
    arp = False
    adapter_arg: str | None = None

    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--auto":
            cidr = auto_detect_private_cidr()
            index += 1
        elif arg == "--adapter" and index + 1 < len(argv):
            adapter_arg = argv[index + 1]
            index += 2
        elif arg == "--timeout" and index + 1 < len(argv):
            timeout = float(argv[index + 1])
            index += 2
        elif arg == "--workers" and index + 1 < len(argv):
            workers = int(argv[index + 1])
            index += 2
        elif arg == "--dns":
            dns = True
            index += 1
        elif arg == "--arp":
            arp = True
            index += 1
        elif arg.startswith("--"):
            raise ValueError(f"Unknown argument: {arg}")
        else:
            if cidr:
                raise ValueError("Only one CIDR target is supported.")
            cidr = arg
            index += 1

    if cidr and adapter_arg:
        raise ValueError("Use either a CIDR target or --adapter, not both.")

    if not cidr:
        if adapter_arg:
            if adapter_arg.lower() == "auto":
                cidr = auto_detect_private_cidr()
            elif "/" in adapter_arg:
                cidr = adapter_arg
            else:
                found = get_local_adapters()
                matched = None
                for disp, c in found:
                    if adapter_arg.lower() in disp.lower():
                        matched = c
                        break
                if matched:
                    cidr = matched
                else:
                    raise ValueError(f"Adapter not found: {adapter_arg}")
        else:
            raise ValueError("Missing CIDR. Example: 192.168.1.0/24 or use --auto")

    return cidr, timeout, workers, dns, arp


def main() -> int:
    # Initialize enhanced modules
    initialize_enhanced_modules()
    
    if len(sys.argv) == 1:
        launch_gui()
        return 0

    try:
        cidr, timeout, workers, dns, arp = parse_cli_args(sys.argv)
        output = run_scan(cidr, timeout, workers, dns, arp)
    except ValueError as exc:
        print(exc)
        _logger.error(f"CLI error: {exc}")
        return 2
    except Exception as exc:
        print(f"Error: {exc}")
        _logger.error(f"Unexpected error: {exc}", exc_info=True)
        return 1

    print(output, end="")
    _logger.info(f"Scan completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
