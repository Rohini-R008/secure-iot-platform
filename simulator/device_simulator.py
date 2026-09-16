import json
import time
import random
import argparse
import itertools
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 8883
CERT_DIR = Path(__file__).resolve().parent.parent / "certs" / "out"


def build_client(device_id: str) -> mqtt.Client:
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        client_id=device_id,
    )
    # Mutual TLS: present this device's own certificate + key, trust our CA.
    client.tls_set(
        ca_certs=str(CERT_DIR / "ca.crt"),
        certfile=str(CERT_DIR / f"{device_id}.crt"),
        keyfile=str(CERT_DIR / f"{device_id}.key"),
    )
    return client


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normal_reading(device_id: str) -> str:
    return json.dumps({
        "device_id": device_id,
        "timestamp": now_iso(),
        "temperature_c": round(random.uniform(18, 30), 2),
        "humidity_pct": round(random.uniform(30, 70), 2),
    })


def anomaly_reading(device_id: str) -> str:
    # Valid numbers, but far outside the normal band -> stored & flagged anomaly.
    return json.dumps({
        "device_id": device_id,
        "timestamp": now_iso(),
        "temperature_c": round(random.uniform(55, 75), 2),
        "humidity_pct": round(random.uniform(90, 99), 2),
    })


def malformed_payloads(device_id: str):
    """Cycle through several kinds of bad message so the rejection log shows variety."""
    return itertools.cycle([
        "this is not json at all",                                     # not JSON
        json.dumps({"device_id": device_id, "temperature_c": 25}),     # missing fields
        json.dumps({"device_id": device_id, "timestamp": now_iso(),
                    "temperature_c": "hot", "humidity_pct": 50}),      # wrong type
        json.dumps({"device_id": device_id, "timestamp": now_iso(),
                    "temperature_c": 999, "humidity_pct": 50}),        # out of physical range
    ])


def spoof_reading(device_id: str) -> str:
    # Publishes on THIS device's own (authorized) topic, but claims to be
    # someone else. The broker allows it (correct topic); the processor must
    # reject it (payload identity != topic identity).
    return json.dumps({
        "device_id": "sensor-999-ATTACKER",
        "timestamp": now_iso(),
        "temperature_c": round(random.uniform(18, 30), 2),
        "humidity_pct": round(random.uniform(30, 70), 2),
    })


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated TLS IoT sensor")
    parser.add_argument("--device", required=True, help="device id, e.g. sensor-001")
    parser.add_argument("--interval", type=float, default=3.0, help="seconds between messages")
    parser.add_argument("--mode", default="normal",
                        choices=["normal", "anomaly", "malformed", "spoof"],
                        help="what kind of data to emit")
    args = parser.parse_args()

    client = build_client(args.device)

    def on_connect(c, userdata, flags, reason_code, properties):
        if reason_code == 0:
            print(f"[{args.device}] connected over mutual TLS (mode={args.mode})")
        else:
            print(f"[{args.device}] connection refused: {reason_code}")

    client.on_connect = on_connect
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
    client.loop_start()

    topic = f"devices/{args.device}/telemetry"
    bad_stream = malformed_payloads(args.device)

    try:
        while True:
            if args.mode == "normal":
                payload = normal_reading(args.device)
            elif args.mode == "anomaly":
                payload = anomaly_reading(args.device)
            elif args.mode == "spoof":
                payload = spoof_reading(args.device)
            else:  # malformed
                payload = next(bad_stream)

            info = client.publish(topic, payload, qos=1)
            info.wait_for_publish()
            print(f"[{args.device}] -> {topic}: {payload}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[{args.device}] stopping")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()