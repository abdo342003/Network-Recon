"""Security framework for NetworkRecon - authorization, encryption, and audit logging."""

import json
import hashlib
import hmac
import secrets
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass
import logging


@dataclass
class AuthorizationContext:
    """Context for authorized network discovery."""
    user: str
    scope: str  # CIDR or network identifier
    timestamp: str
    authorization_token: str
    approved_subnets: list[str]
    expiry: str
    purpose: str  # "authorized_lab", "security_assessment", etc.


class AuthorizationManager:
    """Manage authorization tokens and scopes for network discovery."""
    
    def __init__(self, auth_dir: Optional[str] = None):
        """Initialize authorization manager.
        
        Args:
            auth_dir: Directory for auth files. Defaults to ~/.config/NetworkRecon/auth/
        """
        if auth_dir is None:
            if sys.platform == "win32":
                base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            else:
                base = Path.home() / ".config"
            auth_dir = str(base / "NetworkRecon" / "auth")
        
        self.auth_dir = Path(auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.auth_file = self.auth_dir / "authorizations.json"
        self._authorizations = self._load_authorizations()
        self._logger = logging.getLogger("network_recon.auth")
    
    def _load_authorizations(self) -> list[dict[str, Any]]:
        """Load authorization records."""
        if not self.auth_file.exists():
            return []
        
        try:
            with open(self.auth_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
    
    def _save_authorizations(self) -> None:
        """Save authorization records."""
        try:
            with open(self.auth_file, 'w', encoding='utf-8') as f:
                json.dump(self._authorizations, f, indent=2)
        except OSError as e:
            self._logger.error(f"Failed to save authorizations: {e}")
    
    def create_authorization(self, user: str, approved_subnets: list[str],
                           purpose: str, valid_days: int = 30) -> str:
        """Create authorization for network discovery.
        
        Args:
            user: User identifier
            approved_subnets: List of allowed CIDR ranges
            purpose: Purpose of scan (e.g., "authorized_lab", "security_assessment")
            valid_days: How long authorization is valid
            
        Returns:
            Authorization token
        """
        token = secrets.token_urlsafe(32)
        expiry = (datetime.now(timezone.utc) + timedelta(days=valid_days)).isoformat()
        
        auth = {
            "token": token,
            "user": user,
            "approved_subnets": approved_subnets,
            "purpose": purpose,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expiry,
            "active": True
        }
        
        self._authorizations.append(auth)
        self._save_authorizations()
        
        self._logger.info(f"Created authorization for user {user}: {purpose}")
        return token
    
    def verify_authorization(self, token: str, cidr: str) -> bool:
        """Verify authorization token for a CIDR range.
        
        Args:
            token: Authorization token
            cidr: CIDR to verify
            
        Returns:
            True if authorized, False otherwise
        """
        for auth in self._authorizations:
            if not auth.get("active"):
                continue
            
            if auth.get("token") != token:
                continue
            
            # Check expiry
            expires_at = datetime.fromisoformat(auth.get("expires_at", ""))
            if datetime.now(timezone.utc) > expires_at:
                self._logger.warning(f"Authorization token expired")
                return False
            
            # Check CIDR in approved list
            if cidr in auth.get("approved_subnets", []):
                self._logger.info(f"Authorization verified for {cidr}")
                return True
        
        self._logger.warning(f"Authorization verification failed for {cidr}")
        return False
    
    def list_authorizations(self, user: Optional[str] = None) -> list[dict[str, Any]]:
        """List active authorizations.
        
        Args:
            user: Filter by user (optional)
            
        Returns:
            List of active authorizations
        """
        auths = [a for a in self._authorizations if a.get("active")]
        
        if user:
            auths = [a for a in auths if a.get("user") == user]
        
        return auths
    
    def revoke_authorization(self, token: str) -> bool:
        """Revoke an authorization token.
        
        Args:
            token: Token to revoke
            
        Returns:
            True if revoked, False if not found
        """
        for auth in self._authorizations:
            if auth.get("token") == token:
                auth["active"] = False
                auth["revoked_at"] = datetime.now(timezone.utc).isoformat()
                self._save_authorizations()
                self._logger.info(f"Authorization revoked: {token[:8]}...")
                return True
        
        return False


class AuditLogger:
    """Security audit logging for network discovery operations."""
    
    def __init__(self, audit_dir: Optional[str] = None):
        """Initialize audit logger.
        
        Args:
            audit_dir: Directory for audit logs. Defaults to ~/.config/NetworkRecon/audit/
        """
        if audit_dir is None:
            if sys.platform == "win32":
                base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
            else:
                base = Path.home() / ".config"
            audit_dir = str(base / "NetworkRecon" / "audit")
        
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger("network_recon.audit")
    
    def log_scan_start(self, user: str, cidr: str, scope: str) -> None:
        """Log start of network scan.
        
        Args:
            user: User performing scan
            cidr: Target CIDR
            scope: Scan scope description
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "scan_start",
            "user": user,
            "cidr": cidr,
            "scope": scope
        }
        self._write_audit_event(event)
        self._logger.info(f"Scan started: {user} @ {cidr}")
    
    def log_scan_complete(self, user: str, cidr: str, host_count: int,
                         duration_seconds: float) -> None:
        """Log completion of network scan.
        
        Args:
            user: User performing scan
            cidr: Target CIDR
            host_count: Number of hosts discovered
            duration_seconds: Scan duration
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "scan_complete",
            "user": user,
            "cidr": cidr,
            "host_count": host_count,
            "duration_seconds": duration_seconds
        }
        self._write_audit_event(event)
        self._logger.info(f"Scan completed: {user} @ {cidr} ({host_count} hosts, {duration_seconds:.1f}s)")
    
    def log_authorization_attempt(self, user: str, token: str, cidr: str,
                                 success: bool) -> None:
        """Log authorization verification attempt.
        
        Args:
            user: User attempting access
            token: Token used
            cidr: Target CIDR
            success: Whether authorization succeeded
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "auth_attempt",
            "user": user,
            "token_hash": hashlib.sha256(token.encode()).hexdigest()[:16],
            "cidr": cidr,
            "success": success
        }
        self._write_audit_event(event)
        status = "SUCCESS" if success else "FAILED"
        self._logger.info(f"Auth attempt {status}: {user} @ {cidr}")
    
    def log_data_export(self, user: str, cidr: str, export_format: str,
                       host_count: int) -> None:
        """Log data export operation.
        
        Args:
            user: User exporting data
            cidr: Source CIDR
            export_format: Format (CSV, JSON, HTML, etc.)
            host_count: Number of hosts exported
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "data_export",
            "user": user,
            "cidr": cidr,
            "format": export_format,
            "host_count": host_count
        }
        self._write_audit_event(event)
        self._logger.info(f"Data export: {user} exported {host_count} hosts as {export_format}")
    
    def log_security_event(self, event_type: str, severity: str,
                          description: str, details: Optional[dict] = None) -> None:
        """Log security-related event.
        
        Args:
            event_type: Type of security event
            severity: Severity level (INFO, WARNING, CRITICAL)
            description: Event description
            details: Additional details
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "details": details or {}
        }
        self._write_audit_event(event)
        self._logger.warning(f"[{severity}] {event_type}: {description}")
    
    def _write_audit_event(self, event: dict[str, Any]) -> None:
        """Write audit event to file."""
        try:
            # Daily audit files
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            audit_file = self.audit_dir / f"audit-{today}.jsonl"
            
            with open(audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
        except OSError as e:
            self._logger.error(f"Failed to write audit event: {e}")
    
    def get_audit_events(self, days: int = 7, event_type: Optional[str] = None) -> list[dict]:
        """Retrieve audit events.
        
        Args:
            days: How many days of history to retrieve
            event_type: Filter by event type (optional)
            
        Returns:
            List of audit events
        """
        events = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        for audit_file in sorted(self.audit_dir.glob("audit-*.jsonl")):
            try:
                with open(audit_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            event = json.loads(line)
                            event_time = datetime.fromisoformat(event.get("timestamp", ""))
                            if event_time < cutoff:
                                continue
                            if event_type and event.get("event_type") != event_type:
                                continue
                            events.append(event)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
        
        return sorted(events, key=lambda e: e.get("timestamp", ""))


class DataEncryption:
    """Encryption utilities for sensitive network data."""
    
    @staticmethod
    def hash_ip(ip: str, salt: str = "") -> str:
        """Hash an IP address for de-identification.
        
        Args:
            ip: IP address to hash
            salt: Optional salt for hashing
            
        Returns:
            Hashed IP (first 16 chars of SHA256)
        """
        data = (ip + salt).encode('utf-8')
        return hashlib.sha256(data).hexdigest()[:16]
    
    @staticmethod
    def generate_scan_fingerprint(ips: list[str], cidr: str) -> str:
        """Generate unique fingerprint for scan.
        
        Args:
            ips: List of discovered IPs
            cidr: Target CIDR
            
        Returns:
            Unique scan fingerprint
        """
        data = "|".join(sorted(ips)) + "|" + cidr
        return hashlib.sha256(data.encode()).hexdigest()[:24]
    
    @staticmethod
    def verify_data_integrity(data: dict, signature: str, secret: str) -> bool:
        """Verify integrity of exported data using HMAC.
        
        Args:
            data: Data dict to verify
            signature: HMAC signature
            secret: Secret key for verification
            
        Returns:
            True if data is valid, False otherwise
        """
        data_str = json.dumps(data, sort_keys=True)
        computed_sig = hmac.new(
            secret.encode(),
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(computed_sig, signature)
    
    @staticmethod
    def sign_data(data: dict, secret: str) -> str:
        """Sign data using HMAC.
        
        Args:
            data: Data dict to sign
            secret: Secret key for signing
            
        Returns:
            HMAC signature
        """
        data_str = json.dumps(data, sort_keys=True)
        return hmac.new(
            secret.encode(),
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()


class SecurityCompliance:
    """Compliance and security policy enforcement."""
    
    MINIMUM_SUBNET_SIZE = 24  # Don't allow scanning larger than /24 by default
    MAXIMUM_SUBNET_SIZE = 16  # Allow up to /16 with proper authorization
    
    @staticmethod
    def validate_scan_scope(cidr: str, auth_level: str = "basic") -> tuple[bool, str]:
        """Validate if requested CIDR is within acceptable scope.
        
        Args:
            cidr: CIDR to validate
            auth_level: Authorization level ("basic", "advanced", "admin")
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            
            if not network.is_private:
                return False, "Only private RFC1918/ULA ranges allowed for security"
            
            # Check size based on auth level
            if auth_level == "basic":
                if network.prefixlen < SecurityCompliance.MINIMUM_SUBNET_SIZE:
                    return False, f"Basic auth limited to /{SecurityCompliance.MINIMUM_SUBNET_SIZE} or larger networks"
            elif auth_level == "advanced":
                if network.prefixlen < SecurityCompliance.MAXIMUM_SUBNET_SIZE:
                    return False, f"Advanced auth limited to /{SecurityCompliance.MAXIMUM_SUBNET_SIZE} or larger networks"
            
            return True, "Scope validated"
        except (ValueError, TypeError) as e:
            return False, f"Invalid CIDR: {e}"
    
    @staticmethod
    def validate_input(user_input: str, input_type: str = "text") -> tuple[bool, str]:
        """Validate user input for security issues.
        
        Args:
            user_input: Input to validate
            input_type: Type of input (text, cidr, port, etc.)
            
        Returns:
            Tuple of (is_valid, sanitized_input)
        """
        if input_type == "cidr":
            # Remove whitespace and validate CIDR format
            sanitized = user_input.strip()
            if not sanitized or not sanitized.replace(".", "").replace("/", "").isdigit():
                return False, ""
            return True, sanitized
        
        elif input_type == "port":
            try:
                port = int(user_input.strip())
                if 1 <= port <= 65535:
                    return True, str(port)
                return False, ""
            except ValueError:
                return False, ""
        
        elif input_type == "text":
            # Basic sanitization
            sanitized = user_input.strip()
            # Remove potentially dangerous characters
            dangerous_chars = ['`', '$', '|', '&', ';', '<', '>']
            for char in dangerous_chars:
                if char in sanitized:
                    return False, ""
            return True, sanitized
        
        return True, user_input


def get_authorization_manager() -> AuthorizationManager:
    """Get authorization manager instance."""
    return AuthorizationManager()


def get_audit_logger() -> AuditLogger:
    """Get audit logger instance."""
    return AuditLogger()
