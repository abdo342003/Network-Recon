"""DNS lookup caching with TTL for improved performance."""

import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


class DNSCache:
    """Thread-safe DNS cache with TTL (Time To Live) support."""
    
    DEFAULT_TTL_SECONDS = 3600  # 1 hour
    
    def __init__(self, cache_file: Optional[str] = None, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        """Initialize DNS cache.
        
        Args:
            cache_file: Path to persistent cache JSON file. If None, cache is memory-only.
            ttl_seconds: Time to live for cached entries in seconds.
        """
        self.cache: dict = {}
        self.ttl = ttl_seconds
        self.cache_file = cache_file
        self._lock = threading.RLock()
        
        if cache_file:
            self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cached entries from disk."""
        if not self.cache_file:
            return
            
        try:
            path = Path(self.cache_file)
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.cache = data.get('entries', {})
        except (OSError, json.JSONDecodeError):
            pass  # Silently fail on corrupted cache
    
    def _save_cache(self) -> None:
        """Save cache to disk."""
        if not self.cache_file:
            return
            
        try:
            path = Path(self.cache_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'entries': self.cache, 'saved_at': datetime.now(timezone.utc).isoformat()}, f)
        except OSError:
            pass  # Silently fail on write errors
    
    def get(self, hostname: str) -> Optional[str]:
        """Get cached IP for hostname, returns None if not cached or expired.
        
        Args:
            hostname: Hostname to lookup
            
        Returns:
            IP address string or None if not found/expired
        """
        with self._lock:
            entry = self.cache.get(hostname)
            if not entry:
                return None
            
            # Check TTL
            cached_at = datetime.fromisoformat(entry.get('cached_at', datetime.now(timezone.utc).isoformat()))
            if datetime.now(timezone.utc) - cached_at > timedelta(seconds=self.ttl):
                del self.cache[hostname]
                self._save_cache()
                return None
            
            return entry.get('ip')
    
    def set(self, hostname: str, ip: str) -> None:
        """Cache a hostname->IP mapping.
        
        Args:
            hostname: Hostname to cache
            ip: IP address to associate
        """
        with self._lock:
            self.cache[hostname] = {
                'ip': ip,
                'cached_at': datetime.now(timezone.utc).isoformat()
            }
            self._save_cache()
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self.cache.clear()
            self._save_cache()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        with self._lock:
            expired = []
            now = datetime.now(timezone.utc)
            
            for hostname, entry in self.cache.items():
                cached_at = datetime.fromisoformat(entry.get('cached_at', now.isoformat()))
                if now - cached_at > timedelta(seconds=self.ttl):
                    expired.append(hostname)
            
            for hostname in expired:
                del self.cache[hostname]
            
            if expired:
                self._save_cache()
            
            return len(expired)


class CachedDNSResolver:
    """DNS resolver with caching wrapper."""
    
    def __init__(self, cache: Optional[DNSCache] = None):
        self.cache = cache or DNSCache()
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname with caching.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Hostname or None if not resolvable
        """
        # For reverse DNS, we cache by IP
        if self.cache.get(ip):
            return self.cache.get(ip)
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                self.cache.set(ip, hostname)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None
    
    def resolve_address(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP with caching.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            IP address or None if not resolvable
        """
        if cached_ip := self.cache.get(hostname):
            return cached_ip
        
        try:
            ip = socket.gethostbyname(hostname)
            if ip:
                self.cache.set(hostname, ip)
            return ip
        except (socket.gaierror, OSError):
            return None


def get_dns_cache_path() -> str:
    """Get default DNS cache file path."""
    import os
    import sys
    
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    else:
        base = Path.home() / ".config"
    
    return str(base / "NetworkRecon" / "dns_cache.json")
