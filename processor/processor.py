import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

BROKER_HOST = "localhost"
BROKER_PORT = 8883
CERT_DIR = ROOT / "certs" / "out"
PROCESSOR_ID = "processor"

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_ADMIN_TOKEN")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "secure-iot")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "telemetry")

# Physical-plausibility bounds. Outside these = invalid reading -> REJECT.
TEMP_VALID_MIN, TEMP_VALID_MAX = -50.0, 100.0
HUM_VALID_MIN, HUM_VALID_MAX = 0.0, 100.0

# Normal operating band. Valid but outside this = anomaly -> STORE + FLAG.
TEMP_NORMAL_MIN, TEMP_NORMAL_MAX = 10.0, 40.0
HUM_NORMAL_MIN, HUM_NORMAL_MAX = 20.0, 80.0

REQUIRED_FIELDS = ("device_id", "timestamp", "temperature_c", "humidity_pct")

# --------------------------------------------------------------------------
# Logging (console + processor.log; rejections also go to a JSONL audit file)
# --------------------------------------------------------------------------
LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
REJECTIONS_LOG = LOG_DIR / "rejections.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "processor.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("processor")


class RejectedMessage(Exception):
    """Raised when a message fails validation or authorization."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def record_rejection(topic: str, reason: str, raw: bytes) -> None:
    """Log a rejected message loudly AND append it to a queryable JSONL file.
    The whole point of Phase 2: rejected messages are never silently dropped."""
    entry = {
        "rejected_at": datetime.now(timezone.utc).isoformat(),
        "topic": topic,
        "reason": reason,
        "raw_payload": raw.decode("utf-8", errors="replace")[:500],
    }
    log.warning("REJECTED [%s] %s", topic, reason)
    with REJECTIONS_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def validate_and_parse(topic: str, raw: bytes) -> dict:
    """Parse + validate + authorize. Raises RejectedMessage on any failure."""
    # 1. Must be valid JSON
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RejectedMessage(f"invalid JSON: {exc}")

    if not isinstance(data, dict):
        raise RejectedMessage("payload is not a JSON object")

    # 2. Required fields present
    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise RejectedMessage(f"missing fields: {', '.join(missing)}")

    # 3. Correct numeric types (bool is a subclass of int in Python — exclude it)
    for field in ("temperature_c", "humidity_pct"):
        value = data[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RejectedMessage(f"{field} is not a number")

    # 4. Timestamp must be ISO-8601 parseable
    try:
        ts = datetime.fromisoformat(str(data["timestamp"]))
    except ValueError:
        raise RejectedMessage("timestamp is not valid ISO-8601")

    # 5. Authorization: payload device_id MUST match the topic it arrived on.
    #    Topic form: devices/<device_id>/telemetry
    parts = topic.split("/")
    topic_device = parts[1] if len(parts) >= 2 else ""
    if data["device_id"] != topic_device:
        raise RejectedMessage(
            f"spoofed identity: payload device_id '{data['device_id']}' "
            f"!= topic device '{topic_device}'"
        )

    # 6. Physical-range validation (outside = invalid reading -> reject)
    temp = float(data["temperature_c"])
    hum = float(data["humidity_pct"])
    if not (TEMP_VALID_MIN <= temp <= TEMP_VALID_MAX):
        raise RejectedMessage(f"temperature {temp} outside physical range")
    if not (HUM_VALID_MIN <= hum <= HUM_VALID_MAX):
        raise RejectedMessage(f"humidity {hum} outside physical range")

    return {
        "device_id": topic_device,
        "timestamp": ts,
        "temperature_c": temp,
        "humidity_pct": hum,
    }


def is_anomalous(temp: float, hum: float) -> tuple[bool, str]:
    reasons = []
    if not (TEMP_NORMAL_MIN <= temp <= TEMP_NORMAL_MAX):
        reasons.append(f"temp {temp}C out of band")
    if not (HUM_NORMAL_MIN <= hum <= HUM_NORMAL_MAX):
        reasons.append(f"humidity {hum}% out of band")
    return (len(reasons) > 0, "; ".join(reasons))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    if not INFLUX_TOKEN or "change-me" in INFLUX_TOKEN:
        log.error("INFLUXDB_ADMIN_TOKEN not set/placeholder. Create .env from .env.example.")
        sys.exit(1)

    influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = influx.write_api(write_options=SYNCHRONOUS)

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=PROCESSOR_ID,
    )
    client.tls_set(
        ca_certs=str(CERT_DIR / "ca.crt"),
        certfile=str(CERT_DIR / f"{PROCESSOR_ID}.crt"),
        keyfile=str(CERT_DIR / f"{PROCESSOR_ID}.key"),
    )

    def on_connect(c, userdata, flags, reason_code, properties):
        if reason_code == 0:
            log.info("processor connected over mutual TLS")
            c.subscribe("devices/+/telemetry", qos=1)
            log.info("subscribed to devices/+/telemetry")
        else:
            log.error("connection refused: %s", reason_code)

    def on_message(c, userdata, msg):
        try:
            reading = validate_and_parse(msg.topic, msg.payload)
        except RejectedMessage as rej:
            record_rejection(msg.topic, rej.reason, msg.payload)
            return

        anomaly, why = is_anomalous(reading["temperature_c"], reading["humidity_pct"])
        point = (
            Point("telemetry")
            .tag("device_id", reading["device_id"])
            .tag("anomaly", "true" if anomaly else "false")
            .field("temperature_c", reading["temperature_c"])
            .field("humidity_pct", reading["humidity_pct"])
            .time(reading["timestamp"])
        )
        try:
            write_api.write(bucket=INFLUX_BUCKET, record=point)
        except Exception as exc:
            log.error("InfluxDB write failed for %s: %s", reading["device_id"], exc)
            return

        if anomaly:
            log.warning("ANOMALY %s: %s -> stored", reading["device_id"], why)
        else:
            log.info("ok %s temp=%.2f hum=%.2f -> stored",
                     reading["device_id"], reading["temperature_c"], reading["humidity_pct"])

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)

    log.info("processor running — Ctrl+C to stop")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        client.disconnect()
        influx.close()


if __name__ == "__main__":
    main()