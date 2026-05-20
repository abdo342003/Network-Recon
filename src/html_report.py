"""HTML report generation for network scan results."""

from datetime import datetime, timezone
from typing import Any, Optional


def generate_html_report(
    hosts: list[dict[str, Any]],
    meta: dict[str, Any],
    intel: Optional[dict[str, Any]] = None,
) -> str:
    """Generate HTML report from scan results.
    
    Args:
        hosts: List of host dictionaries with ip, hostname, etc.
        meta: Metadata including cidr, app_version, exported_at
        intel: Optional device intelligence payload
        
    Returns:
        HTML report as string
    """
    cidr = meta.get("cidr", "Unknown")
    app_version = meta.get("app_version", "Unknown")
    exported_at = meta.get("exported_at", datetime.now(timezone.utc).isoformat())
    fingerprint = meta.get("fingerprint", "N/A")
    host_count = len(hosts)
    
    # Parse ISO timestamp for display
    try:
        dt = datetime.fromisoformat(exported_at.replace('Z', '+00:00'))
        readable_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        readable_time = str(exported_at)
    
    # Build host rows
    host_rows = ""
    for i, host in enumerate(hosts, 1):
        ip = host.get("ip", "N/A")
        hostname = host.get("hostname") or "-"
        row_class = "even" if i % 2 == 0 else "odd"
        host_rows += f"""    <tr class="host-row {row_class}">
      <td>{i}</td>
      <td><code>{ip}</code></td>
      <td>{hostname}</td>
    </tr>
"""
    
    # Intel section if available
    intel_section = ""
    if intel:
        intel_section = _build_intel_section(intel)
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Recon Report - {cidr}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            letter-spacing: 0.5px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .metadata {{
            background: #f8f9fa;
            padding: 30px 40px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .metadata-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .metadata-label {{
            font-size: 0.85em;
            color: #666;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        .metadata-value {{
            font-size: 1.2em;
            color: #333;
            font-weight: 500;
            word-break: break-all;
        }}
        .content {{
            padding: 40px;
        }}
        h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
            font-size: 1.8em;
        }}
        h3 {{
            color: #764ba2;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        thead {{
            background: #667eea;
            color: white;
        }}
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        tr.odd {{
            background: #f8f9fa;
        }}
        tr.even {{
            background: white;
        }}
        tr.host-row:hover {{
            background: #f0f0ff;
        }}
        code {{
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
        }}
        .authorized-badge {{
            display: inline-block;
            background: #ff6b6b;
            color: white;
            padding: 8px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            margin-top: 15px;
        }}
        .intel-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #ffc107;
        }}
        .intel-section h3 {{
            color: #ffc107;
            margin-top: 0;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            border-top: 1px solid #e0e0e0;
            font-size: 0.9em;
            color: #666;
        }}
        .section-spacing {{
            margin-bottom: 40px;
        }}
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
                border-radius: 0;
            }}
            .header {{
                page-break-after: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Recon Report</h1>
            <p>Authorized Lab Network Discovery</p>
        </div>
        
        <div class="metadata">
            <div class="metadata-item">
                <div class="metadata-label">Target CIDR</div>
                <div class="metadata-value">{cidr}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Hosts Found</div>
                <div class="metadata-value">{host_count}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">Export Time</div>
                <div class="metadata-value">{readable_time}</div>
            </div>
            <div class="metadata-item">
                <div class="metadata-label">App Version</div>
                <div class="metadata-value">v{app_version}</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section-spacing">
                <h2>📊 Summary</h2>
                <div class="summary-stats">
                    <div class="stat-card">
                        <div class="stat-number">{host_count}</div>
                        <div class="stat-label">Responsive Hosts</div>
                    </div>
                </div>
            </div>
            
            <div class="section-spacing">
                <h2>🖥️ Discovered Hosts</h2>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>IP Address</th>
                            <th>Hostname (PTR)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {host_rows}
                    </tbody>
                </table>
            </div>
            
            {intel_section}
            
            <div class="authorized-badge">✓ AUTHORIZED USE ONLY - Lab Environment</div>
        </div>
        
        <div class="footer">
            <p>Network Recon v{app_version} | Session Fingerprint: <code>{fingerprint}</code></p>
            <p>This report contains sensitive network information. Handle with appropriate security controls.</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


def _build_intel_section(intel: dict[str, Any]) -> str:
    """Build device intelligence HTML section."""
    ip = intel.get("ip", "Unknown")
    hostname = intel.get("reverse_dns") or "-"
    
    icmp = intel.get("icmp", {})
    alive = icmp.get("alive", False)
    latency = icmp.get("latency_ms")
    ttl = icmp.get("ttl")
    ttl_hint = icmp.get("ttl_hint", "unknown")
    
    arp = intel.get("arp", {})
    mac = arp.get("mac") or "-"
    oui_vendor = arp.get("oui_vendor_hint") or "-"
    
    tcp_ports = intel.get("tcp_ports", {})
    ssh_banner = intel.get("ssh_banner", "-")
    
    web_fingerprints = intel.get("web_fingerprints", [])
    web_section = ""
    if web_fingerprints:
        web_rows = ""
        for web in web_fingerprints:
            port = web.get("port")
            scheme = web.get("scheme", "http")
            status = web.get("status_code", "-")
            server = web.get("server_header") or "-"
            title = web.get("title") or "-"
            web_rows += f"""            <tr>
                <td>{scheme}://{ip}:{port}</td>
                <td>{status}</td>
                <td>{server}</td>
                <td>{title}</td>
            </tr>
"""
        web_section = f"""
            <h3>HTTP(S) Fingerprints</h3>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>
                    {web_rows}
                </tbody>
            </table>
"""
    
    tcp_rows = ""
    for port_str, state in sorted(tcp_ports.items(), key=lambda x: int(x[0])):
        tcp_rows += f"""            <tr>
                <td><code>{port_str}</code></td>
                <td>{state}</td>
            </tr>
"""
    
    return f"""
            <div class="intel-section">
                <h3>🔎 Device Intelligence: {ip}</h3>
                
                <table>
                    <thead>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Hostname (PTR)</strong></td>
                            <td>{hostname}</td>
                        </tr>
                        <tr>
                            <td><strong>ICMP Reachable</strong></td>
                            <td>{"✓ Yes" if alive else "✗ No"}</td>
                        </tr>
                        <tr>
                            <td><strong>Latency (ms)</strong></td>
                            <td>{latency if latency else "-"}</td>
                        </tr>
                        <tr>
                            <td><strong>TTL</strong></td>
                            <td>{ttl} ({ttl_hint})</td>
                        </tr>
                        <tr>
                            <td><strong>MAC Address</strong></td>
                            <td>{mac}</td>
                        </tr>
                        <tr>
                            <td><strong>OUI Vendor</strong></td>
                            <td>{oui_vendor}</td>
                        </tr>
                        <tr>
                            <td><strong>SSH Banner</strong></td>
                            <td><code>{ssh_banner}</code></td>
                        </tr>
                    </tbody>
                </table>
                
                <h4 style="margin-top: 20px; margin-bottom: 10px;">TCP Probes</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>State</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tcp_rows}
                    </tbody>
                </table>
                
                {web_section}
            </div>
"""
