"""Extended network discovery for multi-subnet scanning and larger networks."""

import ipaddress
import subprocess
import socket
import platform
import sys
from typing import Optional, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import concurrent.futures as futures


@dataclass
class SubnetDiscoveryResult:
    """Result of subnet discovery operation."""
    subnet: str
    responsive_hosts: int
    new_hosts: int
    scan_time: float
    status: str  # "completed", "in_progress", "failed"


class MultiSubnetScanner:
    """Scanner for discovering and mapping multiple subnets."""
    
    def __init__(self, max_workers: int = 4):
        """Initialize multi-subnet scanner.
        
        Args:
            max_workers: Maximum concurrent subnet scans
        """
        self.max_workers = max_workers
        self.discovered_subnets: dict[str, SubnetDiscoveryResult] = {}
    
    def discover_network_hierarchy(self, base_cidr: str) -> dict[str, Any]:
        """Discover network hierarchy and subnets.
        
        Args:
            base_cidr: Base network CIDR (e.g., 10.0.0.0/8, 172.16.0.0/12)
            
        Returns:
            Dict with network hierarchy information
        """
        try:
            network = ipaddress.ip_network(base_cidr, strict=False)
            
            # If too large, suggest subnetting strategy
            if network.prefixlen < 16:
                return {
                    "network": str(network),
                    "size": network.num_addresses,
                    "subnetting_suggestion": self._suggest_subnets(network),
                    "warning": "Network too large for direct scanning"
                }
            
            return {
                "network": str(network),
                "size": network.num_addresses,
                "subnets": self._enumerate_subnets(network)
            }
        except ValueError as e:
            return {"error": str(e)}
    
    def _suggest_subnets(self, network: ipaddress.IPv4Network) -> list[str]:
        """Suggest subnet breakdown for large networks.
        
        Args:
            network: Network to subnet
            
        Returns:
            List of suggested subnet CIDRs
        """
        suggested = []
        
        # Suggest /24 subnets (256 hosts each)
        if network.prefixlen <= 16:
            subnets = list(network.subnets(new_prefix=24))
            suggested.extend([str(s) for s in subnets[:10]])  # First 10 as examples
            if len(subnets) > 10:
                suggested.append(f"... and {len(subnets) - 10} more subnets")
        
        # Suggest /22 subnets (1024 hosts each)
        elif network.prefixlen <= 20:
            subnets = list(network.subnets(new_prefix=22))
            suggested.extend([str(s) for s in subnets[:5]])
        
        return suggested
    
    def _enumerate_subnets(self, network: ipaddress.IPv4Network) -> list[str]:
        """Enumerate subnets within network.
        
        Args:
            network: Network to enumerate
            
        Returns:
            List of subnet CIDRs
        """
        if network.prefixlen >= 24:
            return [str(network)]
        
        subnets = list(network.subnets(new_prefix=24))
        return [str(s) for s in subnets]
    
    def scan_multiple_subnets(self, subnets: list[str], timeout: float = 1.0,
                             workers: int = 4) -> dict[str, SubnetDiscoveryResult]:
        """Scan multiple subnets in parallel.
        
        Args:
            subnets: List of CIDR ranges to scan
            timeout: Ping timeout for each host
            workers: Number of concurrent subnet scans
            
        Returns:
            Dict mapping subnet to discovery result
        """
        results = {}
        
        with futures.ThreadPoolExecutor(max_workers=min(workers, self.max_workers)) as pool:
            future_map = {
                pool.submit(self._scan_subnet, subnet, timeout): subnet
                for subnet in subnets
            }
            
            for future in futures.as_completed(future_map):
                subnet = future_map[future]
                try:
                    result = future.result()
                    results[subnet] = result
                    self.discovered_subnets[subnet] = result
                except Exception as e:
                    results[subnet] = SubnetDiscoveryResult(
                        subnet=subnet,
                        responsive_hosts=0,
                        new_hosts=0,
                        scan_time=0,
                        status=f"failed: {e}"
                    )
        
        return results
    
    def _scan_subnet(self, cidr: str, timeout: float) -> SubnetDiscoveryResult:
        """Scan a single subnet.
        
        Args:
            cidr: Subnet CIDR to scan
            timeout: Ping timeout
            
        Returns:
            Subnet discovery result
        """
        start = datetime.now(timezone.utc)
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            responsive = []
            
            # Simple ping sweep
            for host in list(network.hosts())[:64]:  # Limit to first 64 hosts for speed
                if self._is_host_responsive(str(host), timeout):
                    responsive.append(str(host))
            
            elapsed = (datetime.now(timezone.utc) - start).total_seconds()
            
            return SubnetDiscoveryResult(
                subnet=cidr,
                responsive_hosts=len(responsive),
                new_hosts=len(responsive),
                scan_time=elapsed,
                status="completed"
            )
        except Exception as e:
            return SubnetDiscoveryResult(
                subnet=cidr,
                responsive_hosts=0,
                new_hosts=0,
                scan_time=0,
                status=f"failed: {str(e)}"
            )
    
    def _is_host_responsive(self, ip: str, timeout: float) -> bool:
        """Check if host responds to ping.
        
        Args:
            ip: IP address to ping
            timeout: Ping timeout in seconds
            
        Returns:
            True if host responds
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False


class NetworkHierarchyMapper:
    """Map and visualize network hierarchy and dependencies."""
    
    def __init__(self):
        """Initialize network hierarchy mapper."""
        self.hierarchy: dict[str, Any] = {}
        self.connections: list[tuple[str, str]] = []
    
    def build_hierarchy(self, base_network: str, scan_results: dict[str, Any]) -> dict[str, Any]:
        """Build network hierarchy from scan results.
        
        Args:
            base_network: Base network CIDR
            scan_results: Results from subnet scans
            
        Returns:
            Network hierarchy structure
        """
        hierarchy = {
            "root": base_network,
            "subnets": [],
            "summary": {
                "total_subnets_scanned": 0,
                "total_hosts_found": 0,
                "total_scan_time": 0.0
            }
        }
        
        for subnet, result in scan_results.items():
            if result.status == "completed":
                hierarchy["subnets"].append({
                    "network": subnet,
                    "responsive_hosts": result.responsive_hosts,
                    "scan_time": result.scan_time
                })
                hierarchy["summary"]["total_subnets_scanned"] += 1
                hierarchy["summary"]["total_hosts_found"] += result.responsive_hosts
                hierarchy["summary"]["total_scan_time"] += result.scan_time
        
        self.hierarchy = hierarchy
        return hierarchy
    
    def generate_text_map(self, hierarchy: dict[str, Any]) -> str:
        """Generate ASCII text representation of network.
        
        Args:
            hierarchy: Network hierarchy
            
        Returns:
            ASCII network map
        """
        lines = [
            "Network Hierarchy Map",
            "=" * 60,
            f"Root Network: {hierarchy.get('root')}",
            "",
            "Subnets:"
        ]
        
        for subnet in hierarchy.get("subnets", []):
            lines.append(f"  ├─ {subnet['network']}")
            lines.append(f"  │  └─ Hosts: {subnet['responsive_hosts']}")
            lines.append(f"  │  └─ Scan Time: {subnet['scan_time']:.2f}s")
        
        lines.extend([
            "",
            "Summary",
            "=" * 60,
            f"Total Subnets: {hierarchy.get('summary', {}).get('total_subnets_scanned')}",
            f"Total Hosts: {hierarchy.get('summary', {}).get('total_hosts_found')}",
            f"Total Time: {hierarchy.get('summary', {}).get('total_scan_time', 0):.2f}s"
        ])
        
        return "\n".join(lines)
    
    def generate_graphviz_dot(self, hierarchy: dict[str, Any]) -> str:
        """Generate Graphviz DOT representation.
        
        Args:
            hierarchy: Network hierarchy
            
        Returns:
            Graphviz DOT format string
        """
        root_net = hierarchy.get("root", "unknown")
        lines = [
            "digraph NetworkHierarchy {",
            "  rankdir=TB;",
            "  node [shape=box, style=rounded];",
            "",
            f'  root [label="{root_net}", color=blue, fontcolor=white];',
            ""
        ]
        
        for subnet in hierarchy.get("subnets", []):
            network = subnet["network"]
            hosts = subnet["responsive_hosts"]
            safe_network = network.replace("/", "_")
            lines.append(f'  subnet_{safe_network} [label="{network}\\n({hosts} hosts)"];')
            lines.append(f'  root -> subnet_{safe_network};')
        
        lines.append("}")
        return "\n".join(lines)


class LargeNetworkScanner:
    """Scanner optimized for large networks with sampling and estimation."""
    
    def __init__(self):
        """Initialize large network scanner."""
        self.sampling_rate = 0.1  # Scan 10% of hosts for estimation
        self.results: dict[str, Any] = {}
    
    def estimate_network_size(self, cidr: str, sample_size: int = 25) -> dict[str, Any]:
        """Estimate network size and active hosts using sampling.
        
        Args:
            cidr: Large network CIDR
            sample_size: Number of addresses to sample
            
        Returns:
            Estimation results with confidence intervals
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            total_addresses = network.num_addresses - 2  # Exclude network and broadcast
            
            # Sample hosts uniformly across the network
            step = max(1, total_addresses // sample_size)
            sample_ips = [str(ip) for ip in list(network.hosts())[::step]]
            
            responsive = 0
            for ip in sample_ips:
                if self._is_responsive(ip, timeout=0.5):
                    responsive += 1
            
            # Estimate total
            estimated_active = int((responsive / len(sample_ips)) * total_addresses)
            
            return {
                "network": str(network),
                "total_addresses": total_addresses,
                "sampled": len(sample_ips),
                "responsive_in_sample": responsive,
                "estimated_active_hosts": estimated_active,
                "confidence": f"{(responsive / len(sample_ips) * 100):.1f}%",
                "recommendation": self._get_scan_recommendation(estimated_active)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _is_responsive(self, ip: str, timeout: float = 0.5) -> bool:
        """Quick responsiveness check."""
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
            
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_scan_recommendation(self, estimated_hosts: int) -> str:
        """Get recommendation based on estimated size."""
        if estimated_hosts < 10:
            return "Full scan recommended"
        elif estimated_hosts < 100:
            return "Full scan feasible"
        elif estimated_hosts < 500:
            return "Consider subnet scanning"
        else:
            return "Large network - use hierarchical scanning"


def get_multi_subnet_scanner(max_workers: int = 4) -> MultiSubnetScanner:
    """Get multi-subnet scanner instance."""
    return MultiSubnetScanner(max_workers=max_workers)


def get_network_mapper() -> NetworkHierarchyMapper:
    """Get network hierarchy mapper instance."""
    return NetworkHierarchyMapper()


def get_large_network_scanner() -> LargeNetworkScanner:
    """Get large network scanner instance."""
    return LargeNetworkScanner()
