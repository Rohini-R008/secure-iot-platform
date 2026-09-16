import json
import time
import random
import argparse
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


def make_reading(device_id: str) -> dict:
    return {
        "device_id": device_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "temperature_c": round(random.uniform(18, 30), 2),
        "humidity_pct": round(random.uniform(30, 70), 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulated TLS IoT sensor")
    parser.add_argument("--device", required=True, help="device id, e.g. sensor-001")
    parser.add_argument("--interval", type=float, default=3.0, help="seconds between readings")
    args = parser.parse_args()

    client = build_client(args.device)

    def on_connect(c, userdata, flags, reason_code, properties):
        if reason_code == 0:
            print(f"[{args.device}] connected over mutual TLS")
        else:
            print(f"[{args.device}] connection refused: {reason_code}")

    client.on_connect = on_connect
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
    client.loop_start()

    topic = f"devices/{args.device}/telemetry"
    try:
        while True:
            payload = json.dumps(make_reading(args.device))
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