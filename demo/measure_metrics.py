"""Measure real performance metrics for the README.

- Throughput: how many valid messages the processor ingests per second.
- Alert latency: time from a message being published to it being queryable
  in InfluxDB (publish -> stored).

Prereqs: secure stack up, processor NOT required (this script publishes and
reads InfluxDB directly). Run from project root: python demo/measure_metrics.py
"""
import json
import os
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
from dotenv import load_dotenv
from influxdb_client import InfluxDBClient

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
CERT_DIR = ROOT / "certs" / "out"

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_ADMIN_TOKEN")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "secure-iot")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "telemetry")

N = 100  # messages to send for the throughput test


def make_client(device):
    c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=f"{device}-metrics")
    c.tls_set(ca_certs=str(CERT_DIR / "ca.crt"),
              certfile=str(CERT_DIR / f"{device}.crt"),
              keyfile=str(CERT_DIR / f"{device}.key"))
    c.connect("localhost", 8883, keepalive=30)
    c.loop_start()
    time.sleep(1)
    return c


def measure_throughput():
    print(f"Throughput: publishing {N} messages as fast as possible...")
    c = make_client("sensor-001")
    start = time.time()
    for i in range(N):
        payload = json.dumps({
            "device_id": "sensor-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "temperature_c": 22.0 + (i % 5),
            "humidity_pct": 50.0,
        })
        info = c.publish("devices/sensor-001/telemetry", payload, qos=1)
        info.wait_for_publish(timeout=5)
    elapsed = time.time() - start
    c.loop_stop(); c.disconnect()
    rate = N / elapsed
    print(f"  Published {N} msgs in {elapsed:.2f}s -> {rate:.1f} msg/s "
          f"(publish-side, QoS 1)")
    return rate


def measure_latency():
    """Publish one uniquely-tagged message, poll InfluxDB until it appears."""
    print("Alert latency: publish -> queryable in InfluxDB...")
    marker = f"metric-{int(time.time())}"
    c = make_client("sensor-001")
    influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    query_api = influx.query_api()

    payload = json.dumps({
        "device_id": "sensor-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "temperature_c": 23.45,
        "humidity_pct": 55.55,
        "marker": marker,   # extra field is ignored by validation but harmless
    })
    t0 = time.time()
    c.publish("devices/sensor-001/telemetry", payload, qos=1).wait_for_publish(5)

    flux = f'''
from(bucket: "{INFLUX_BUCKET}")
  |> range(start: -2m)
  |> filter(fn: (r) => r._measurement == "telemetry")
  |> filter(fn: (r) => r.device_id == "sensor-001")
  |> filter(fn: (r) => r._field == "temperature_c")
  |> filter(fn: (r) => r._value == 23.45)
  |> last()
'''
    found_at = None
    for _ in range(100):  # up to ~10s
        tables = query_api.query(flux, org=INFLUX_ORG)
        if any(len(t.records) for t in tables):
            found_at = time.time()
            break
        time.sleep(0.1)
    c.loop_stop(); c.disconnect(); influx.close()

    if found_at:
        latency = found_at - t0
        print(f"  Latency publish -> stored & queryable: {latency*1000:.0f} ms")
        return latency
    print("  Message not found within 10s (is the processor running?)")
    return None


if __name__ == "__main__":
    print("Secure IoT — metrics measurement")
    print("NOTE: the processor MUST be running in another terminal.\n")
    rate = measure_throughput()
    time.sleep(2)
    lat = measure_latency()
    print("\nSummary:")
    print(f"  Throughput: ~{rate:.0f} msg/s (publish side)")
    if lat:
        print(f"  Alert latency (publish -> queryable): ~{lat*1000:.0f} ms")