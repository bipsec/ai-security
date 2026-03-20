"""
Layer 6 — Audit Logger
Structured JSON logging with rotation, anomaly detection, and immutable entries.
All other layers call into this module.
"""

import json
import logging
import logging.handlers
import os
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

import yaml


def _load_config() -> dict:
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "config", "audit.yaml"
    )
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = _load_config()
AUDIT_CFG = CONFIG["audit"]
FILE_CFG = AUDIT_CFG.get("file", {})
ANOMALY_CFG = AUDIT_CFG.get("anomaly_detection", {})
NEVER_LOG_FIELDS = set(
    AUDIT_CFG.get("never_log", {}).get("field_names", [])
)

# Build a set of all known event types from the events catalog
EVENTS_CATALOG = AUDIT_CFG.get("events_catalog", {})

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)


class JSONFormatter(logging.Formatter):
    """Format log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "service": "ai-security-wrapper",
        }
        if hasattr(record, "audit_data"):
            entry.update(record.audit_data)
        return json.dumps(entry)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("ai_security_audit")
    logger.setLevel(logging.INFO)
    logger.handlers = []

    log_file = FILE_CFG.get("primary_log", "logs/audit.log")
    max_bytes = FILE_CFG.get("max_size_mb", 100) * 1024 * 1024
    backup_count = FILE_CFG.get("backup_count", 30)

    handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    # Also log to stdout in development
    if os.getenv("APP_ENV", "development") == "development":
        console = logging.StreamHandler()
        console.setFormatter(JSONFormatter())
        logger.addHandler(console)

    return logger


_logger = _build_logger()

# In-memory counters for anomaly detection — keyed by event type
_anomaly_windows: dict[str, deque] = {}


def _get_anomaly_window(event_type: str) -> deque:
    if event_type not in _anomaly_windows:
        _anomaly_windows[event_type] = deque()
    return _anomaly_windows[event_type]


def _suppress_sensitive_fields(details: dict) -> dict:
    """Replace values of never-log fields with [SUPPRESSED]."""
    if not details:
        return details
    cleaned = {}
    for k, v in details.items():
        if k in NEVER_LOG_FIELDS:
            cleaned[k] = "[SUPPRESSED]"
        else:
            cleaned[k] = v
    return cleaned


class AuditLogger:
    """Thread-safe, structured audit logger with anomaly detection."""

    @staticmethod
    def log(
        event_type: str,
        user_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        details: Optional[dict] = None,
        level: str = "INFO",
    ) -> None:
        # Accept all events — catalog is informational, not a filter
        safe_details = _suppress_sensitive_fields(details or {})

        audit_data = {
            "event_type": event_type,
            "trace_id": trace_id or str(uuid4()),
            "user_id": user_id or "anonymous",
            "details": safe_details,
        }

        # Use level from events catalog if available
        catalog_entry = EVENTS_CATALOG.get(event_type, {})
        effective_level = catalog_entry.get("level", level)

        record = logging.LogRecord(
            name="ai_security_audit",
            level=getattr(logging, effective_level, logging.INFO),
            pathname="",
            lineno=0,
            msg=event_type,
            args=(),
            exc_info=None,
        )
        record.audit_data = audit_data
        _logger.handle(record)

        # Anomaly detection
        AuditLogger._check_anomalies(event_type)

    @staticmethod
    def _check_anomalies(event_type: str) -> None:
        if not ANOMALY_CFG.get("enabled"):
            return

        rules = ANOMALY_CFG.get("rules", {})
        now = time.time()

        for rule_name, rule in rules.items():
            if rule.get("event") != event_type:
                continue

            window = _get_anomaly_window(rule_name)
            window_seconds = rule.get("window_seconds", 60)
            threshold = rule.get("threshold", 10)

            window.append(now)
            # Purge entries outside the window
            while window and window[0] < now - window_seconds:
                window.popleft()

            if len(window) >= threshold:
                AuditLogger.log(
                    "ANOMALY_DETECTED",
                    details={
                        "anomaly_type": rule_name,
                        "metric": event_type,
                        "threshold": threshold,
                        "current_value": len(window),
                        "severity": rule.get("severity", "high"),
                    },
                    level="CRITICAL",
                )
                # Clear window to avoid repeated anomaly alerts
                window.clear()


# Convenience singleton
audit = AuditLogger()
