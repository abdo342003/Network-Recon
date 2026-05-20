"""Configuration management for NetworkRecon."""

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


class ConfigManager:
    """Manage application configuration with JSON persistence."""
    
    DEFAULT_CONFIG = {
        "ui": {
            "geometry": "1040x760",
            "theme": "dark",
            "auto_detect_subnet": True,
            "show_tooltips": True,
        },
        "network": {
            "default_timeout": 1.0,
            "default_workers": 64,
            "default_ports": "22,80,443,445,3389,8080",
            "enable_dns": True,
            "enable_arp": False,
            "enable_web_fingerprint": True,
            "enable_traceroute": False,
        },
        "logging": {
            "enabled": True,
            "level": "INFO",
            "max_log_size_mb": 10,
            "backup_count": 5,
        },
        "cache": {
            "dns_cache_enabled": True,
            "dns_ttl_seconds": 3600,
            "persist_cache": True,
        },
        "history": {
            "enabled": True,
            "max_entries": 100,
            "auto_save_scans": True,
        },
    }
    
    def __init__(self, config_dir: Optional[str] = None):
        """Initialize config manager.
        
        Args:
            config_dir: Directory to store config. Defaults to ~/.config/NetworkRecon
        """
        if config_dir is None:
            if sys.platform == "win32":
                base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            else:
                base = Path.home() / ".config"
            config_dir = str(base / "NetworkRecon")
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / "config.json"
        self.config = self._load_config()
    
    def _load_config(self) -> dict[str, Any]:
        """Load configuration from file or create defaults."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # Merge with defaults (user config takes precedence)
                    return self._merge_configs(self.DEFAULT_CONFIG.copy(), user_config)
            except (OSError, json.JSONDecodeError):
                pass
        
        # Save defaults if no config exists
        self._save_config(self.DEFAULT_CONFIG)
        return self.DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, default: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
        """Recursively merge user config with defaults."""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                default[key] = self._merge_configs(default[key], value)
            else:
                default[key] = value
        return default
    
    def _save_config(self, config: dict[str, Any]) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        except OSError:
            pass
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by dot-notation key.
        
        Args:
            key: Key path (e.g., "network.default_timeout")
            default: Default value if key not found
            
        Returns:
            Config value or default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value if value is not None else default
    
    def set(self, key: str, value: Any) -> None:
        """Set config value by dot-notation key.
        
        Args:
            key: Key path (e.g., "network.default_timeout")
            value: Value to set
        """
        keys = key.split('.')
        target = self.config
        
        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]
        
        target[keys[-1]] = value
        self._save_config(self.config)
    
    def reset(self) -> None:
        """Reset to default configuration."""
        self.config = self.DEFAULT_CONFIG.copy()
        self._save_config(self.config)
    
    def export(self) -> str:
        """Export config as JSON string."""
        return json.dumps(self.config, indent=2)
    
    def import_config(self, json_str: str) -> bool:
        """Import configuration from JSON string.
        
        Args:
            json_str: JSON string to import
            
        Returns:
            True if successful, False otherwise
        """
        try:
            user_config = json.loads(json_str)
            self.config = self._merge_configs(self.DEFAULT_CONFIG.copy(), user_config)
            self._save_config(self.config)
            return True
        except (json.JSONDecodeError, TypeError):
            return False


def get_config_manager(config_dir: Optional[str] = None) -> ConfigManager:
    """Get or create a ConfigManager instance."""
    return ConfigManager(config_dir)
