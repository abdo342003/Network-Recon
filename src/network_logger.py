"""Centralized logging for NetworkRecon with file persistence and rotation."""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path


def setup_logger(name: str, log_dir: str | None = None) -> logging.Logger:
    """Initialize logger with file and console handlers.
    
    Args:
        name: Logger name (usually __name__)
        log_dir: Directory for log files. Defaults to ~/.config/NetworkRecon/logs
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger  # Already configured
    
    logger.setLevel(logging.DEBUG)
    
    # Determine log directory
    if log_dir is None:
        if sys.platform == "win32":
            base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
        else:
            base = Path.home() / ".config"
        log_dir = str(base / "NetworkRecon" / "logs")
    
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    
    # File handler with rotation (10MB per file, keep 5 backups)
    log_file = log_path / "network_recon.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10_485_760,  # 10MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler (INFO level)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get or create a logger."""
    return logging.getLogger(name)


class LogContext:
    """Context manager for logging operations with timing."""
    
    def __init__(self, logger: logging.Logger, message: str):
        self.logger = logger
        self.message = message
        self.start_time = None
        
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.info(f"Starting: {self.message}")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if exc_type is None:
            self.logger.info(f"Completed: {self.message} ({elapsed:.2f}s)")
        else:
            self.logger.error(
                f"Failed: {self.message} after {elapsed:.2f}s — {exc_type.__name__}: {exc_val}"
            )
        return False
