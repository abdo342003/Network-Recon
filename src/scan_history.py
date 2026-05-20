"""Scan history management for NetworkRecon."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class ScanHistory:
    """Manage and persist scan history."""
    
    def __init__(self, history_dir: Optional[str] = None, max_entries: int = 100):
        """Initialize scan history manager.
        
        Args:
            history_dir: Directory to store history. Defaults to ~/.config/NetworkRecon/history
            max_entries: Maximum number of scans to keep
        """
        if history_dir is None:
            if sys.platform == "win32":
                base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            else:
                base = Path.home() / ".config"
            history_dir = str(base / "NetworkRecon" / "history")
        
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = max_entries
        self.index_file = self.history_dir / "index.json"
        self._index = self._load_index()
    
    def _load_index(self) -> list[dict[str, Any]]:
        """Load scan history index."""
        if not self.index_file.exists():
            return []
        
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
    
    def _save_index(self) -> None:
        """Save scan history index."""
        try:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(self._index, f, indent=2)
        except OSError:
            pass
    
    def add_scan(self, cidr: str, hosts: list[dict[str, Any]], 
                 metadata: Optional[dict[str, Any]] = None) -> str:
        """Add a scan to history.
        
        Args:
            cidr: Target CIDR
            hosts: List of discovered hosts
            metadata: Optional metadata dict
            
        Returns:
            Scan ID
        """
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        
        scan_entry = {
            "id": scan_id,
            "cidr": cidr,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host_count": len(hosts),
            "metadata": metadata or {}
        }
        
        # Save scan data file
        scan_file = self.history_dir / f"{scan_id}.json"
        scan_data = {
            "scan": scan_entry,
            "hosts": hosts
        }
        
        try:
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(scan_data, f, indent=2)
        except OSError:
            return None
        
        # Update index
        self._index.insert(0, scan_entry)
        
        # Keep only max_entries
        if len(self._index) > self.max_entries:
            removed = self._index[self.max_entries]
            old_file = self.history_dir / f"{removed['id']}.json"
            try:
                old_file.unlink()
            except OSError:
                pass
            self._index = self._index[:self.max_entries]
        
        self._save_index()
        return scan_id
    
    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a specific scan by ID.
        
        Args:
            scan_id: ID of scan to retrieve
            
        Returns:
            Scan data dict or None if not found
        """
        scan_file = self.history_dir / f"{scan_id}.json"
        if not scan_file.exists():
            return None
        
        try:
            with open(scan_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
    
    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recent scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan index entries
        """
        return self._index[:limit]
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a specific scan.
        
        Args:
            scan_id: ID of scan to delete
            
        Returns:
            True if deleted, False otherwise
        """
        scan_file = self.history_dir / f"{scan_id}.json"
        
        try:
            if scan_file.exists():
                scan_file.unlink()
        except OSError:
            return False
        
        # Remove from index
        self._index = [s for s in self._index if s.get("id") != scan_id]
        self._save_index()
        
        return True
    
    def clear_history(self) -> None:
        """Clear all scan history."""
        try:
            for scan_file in self.history_dir.glob("*.json"):
                if scan_file != self.index_file:
                    scan_file.unlink()
            self._index = []
            self._save_index()
        except OSError:
            pass
    
    def search_scans(self, cidr: Optional[str] = None) -> list[dict[str, Any]]:
        """Search scans by CIDR.
        
        Args:
            cidr: CIDR to search for (partial match allowed)
            
        Returns:
            List of matching scan entries
        """
        if not cidr:
            return self._index
        
        return [s for s in self._index if cidr.lower() in s.get("cidr", "").lower()]
    
    def get_stats(self) -> dict[str, Any]:
        """Get statistics about scan history.
        
        Returns:
            Dict with stats
        """
        total_scans = len(self._index)
        total_hosts = sum(s.get("host_count", 0) for s in self._index)
        
        cidrs = {}
        for scan in self._index:
            cidr = scan.get("cidr", "unknown")
            cidrs[cidr] = cidrs.get(cidr, 0) + 1
        
        return {
            "total_scans": total_scans,
            "total_unique_hosts_found": total_hosts,
            "unique_cidrs": len(cidrs),
            "cidrs": cidrs
        }
