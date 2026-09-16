"""Shared audit-logging helper.

Every security-relevant event (login, access attempt, config change,
credential revocation, alert) is written here as a structured record to a
dedicated InfluxDB bucket, so it is durable and queryable. This is what makes
the platform 'monitored' rather than merely 'displayed'.
"""
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_ADMIN_TOKEN")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "secure-iot")
AUDIT_BUCKET = os.getenv("INFLUXDB_AUDIT_BUCKET", "audit")


class AuditLogger:
    """Writes structured audit events to InfluxDB. Reusable across services."""

    def __init__(self):
        if not INFLUX_TOKEN or "change-me" in INFLUX_TOKEN:
            raise RuntimeError("INFLUXDB_ADMIN_TOKEN not set. Configure .env.")
        self._client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)

    def log(
        self,
        action: str,
        actor: str = "system",
        target: str = "",
        outcome: str = "success",
        detail: str = "",
    ) -> None:
        """Record one audit event.

        action  - what happened, e.g. 'login', 'revoke_device', 'view_devices'
        actor   - who did it, e.g. a username or 'system'
        target  - what it acted on, e.g. a device id (optional)
        outcome - 'success' or 'failure'
        detail  - free-text extra context (optional)
        """
        point = (
            Point("audit_event")
            .tag("action", action)
            .tag("actor", actor)
            .tag("outcome", outcome)
            .field("target", target)
            .field("detail", detail)
            .time(datetime.now(timezone.utc))
        )
        self._write_api.write(bucket=AUDIT_BUCKET, record=point)

    def close(self) -> None:
        self._client.close()


# Convenience singleton + module-level function for simple call sites.
_default_logger: AuditLogger | None = None


def audit(action: str, **kwargs) -> None:
    """Module-level shortcut: audit('login', actor='alice', outcome='success')."""
    global _default_logger
    if _default_logger is None:
        _default_logger = AuditLogger()
    _default_logger.log(action, **kwargs)