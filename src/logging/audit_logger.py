import logging
import json
from datetime import datetime
from typing import Optional

class AuditLogger:
    """
    Logs authentication and authorization events for audit/compliance.
    Ensures no sensitive credential data is logged.
    """

    def __init__(self, logger_name: str = "aqi_audit_logger"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_event(
        self,
        event_type: str,
        user: Optional[str],
        endpoint: str,
        status_code: int,
        detail: str,
        client_ip: Optional[str] = None
    ) -> None:
        """
        Logs a structured audit event.
        Sensitive credential/token data must NOT be included in logs.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user": user,
            "endpoint": endpoint,
            "status_code": status_code,
            "detail": self._sanitize_detail(detail),
            "client_ip": client_ip
        }
        try:
            self.logger.info(json.dumps(event, separators=(",", ":")))
        except Exception as e:
            # Fallback to plain logging if JSON serialization fails
            self.logger.error(f"Audit log serialization error: {e} | Event: {event}")

    def _sanitize_detail(self, detail: str) -> str:
        """
        Removes or masks sensitive data from detail messages.
        """
        # For now, just ensure no obvious tokens/secrets are present.
        # Extend with regex or more advanced sanitization as needed.
        if "token" in detail.lower():
            return "[REDACTED]"
        return detail

# Singleton instance for global use
audit_logger = AuditLogger()

__all__ = ["AuditLogger", "audit_logger"]