"""Centralized logging configuration with safety filtering and rotating file handler."""

import logging
from logging.handlers import RotatingFileHandler
import os
import re
from pathlib import Path
from typing import Optional
from config.settings import settings


class SensitiveDataFilter(logging.Filter):
    """Safety filter ensuring encryption keys, hex secrets, and sensitive tokens are not logged."""

    PATTERNS = [
        re.compile(r"(key|secret|nonce|aes_key|password)\s*[:=]\s*([0-9a-fA-F]{32,64})", re.IGNORECASE),
        re.compile(r"(key_bytes|raw_key)\s*[:=]\s*([^\s,]+)", re.IGNORECASE),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pat in self.PATTERNS:
                record.msg = pat.sub(r"\1: [REDACTED_FOR_SECURITY]", record.msg)
        return True


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[Path] = None,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """Initialize root logger with console and rotating file handlers."""
    level_name = (log_level or settings.LOG_LEVEL).upper()
    level = getattr(logging, level_name, logging.INFO)

    file_path = log_file or settings.LOG_FILE
    file_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("scada_security")
    logger.setLevel(level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s:%(module)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        safe_filter = SensitiveDataFilter()

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(safe_filter)
        logger.addHandler(console_handler)

        # Rotating File Handler
        try:
            file_handler = RotatingFileHandler(
                filename=str(file_path),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(safe_filter)
            logger.addHandler(file_handler)
        except (PermissionError, OSError) as e:
            logger.warning("Could not initialize file handler at %s: %s", file_path, e)

    return logger


logger = setup_logging()
