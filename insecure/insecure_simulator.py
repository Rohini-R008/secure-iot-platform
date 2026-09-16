"""DELIBERATELY INSECURE simulator — no TLS, no identity.
Connects anonymously to the plaintext broker and can publish as ANY device.
Used only to demonstrate attacks the secure stack blocks."""
import json
import time
import random
import argparse
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 1883  # plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description="Insecure IoT sensor (demo)")
    parser.add_argument("--device", required=True, help="device id to claim")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--spoof-as", default=None,
                        help="publish claiming to be a DIFFERENT device id")
    args = parser.parse_args()

    # No TLS, no certificate — just connect.
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                         client_id=args.device)
    client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
    client.loop_start()

    # An attacker can publish to ANY device's topic — no ACL stops them.
    target = args.spoof_as or args.device
    topic = f"devices/{target}/telemetry"

    print(f"[INSECURE {args.device}] connected anonymously (no TLS), "
          f"publishing to {topic}"
          + (f" while CLAIMING to be {args.spoof_as}" if args.spoof_as else ""))
    try:
        while True:
            payload = json.dumps({
                "device_id": target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "temperature_c": round(random.uniform(18, 30), 2),
                "humidity_pct": round(random.uniform(30, 70), 2),
            })
            client.publish(topic, payload, qos=0)
            print(f"[INSECURE {args.device}] -> {topic}: {payload}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[INSECURE {args.device}] stopping")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()