"""Side-by-side attack demonstration.

For each attack, runs it against the INSECURE stack (expected to SUCCEED)
and the SECURE stack (expected to be BLOCKED), and prints a verdict.
This is reproducible evidence for the security claims in the threat model.

Prereqs: both stacks up. Secure broker on 8883 (mTLS + ACL), insecure on 1883.
Run from the project root:  python demo/attack_runner.py
"""
import ssl
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

ROOT = Path(__file__).resolve().parent.parent
CERT_DIR = ROOT / "certs" / "out"

SECURE_HOST, SECURE_PORT = "localhost", 8883
INSECURE_HOST, INSECURE_PORT = "localhost", 1883

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; RESET = "\033[0m"


def try_publish(host, port, topic, payload, use_tls, cert_name=None, timeout=6):
    """Attempt to connect + publish. Returns (connected, published, detail)."""
    result = {"connected": False, "published": False, "detail": ""}
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)

    if use_tls:
        try:
            if cert_name:
                client.tls_set(
                    ca_certs=str(CERT_DIR / "ca.crt"),
                    certfile=str(CERT_DIR / f"{cert_name}.crt"),
                    keyfile=str(CERT_DIR / f"{cert_name}.key"),
                )
            else:
                # TLS but NO client certificate (anonymous attacker over TLS)
                client.tls_set(ca_certs=str(CERT_DIR / "ca.crt"))
        except Exception as exc:
            result["detail"] = f"tls setup failed: {exc}"
            return result

    def on_connect(c, u, f, rc, props):
        result["connected"] = (rc == 0)
        if rc != 0:
            result["detail"] = f"connect refused (rc={rc})"

    client.on_connect = on_connect
    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()
        # wait briefly for connect callback
        for _ in range(int(timeout * 10)):
            if result["connected"]:
                break
            time.sleep(0.1)
        if result["connected"]:
            info = client.publish(topic, payload, qos=1)
            info.wait_for_publish(timeout=3)
            result["published"] = info.is_published()
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}: {exc}"
    finally:
        client.loop_stop()
        client.disconnect()
    return result


def verdict(label, insecure_res, secure_res, success_means_published=True):
    key = "published" if success_means_published else "connected"
    ins_ok = insecure_res[key]           # attack SUCCEEDS on insecure = expected
    sec_blocked = not secure_res[key]    # attack BLOCKED on secure = expected
    print(f"\n{YELLOW}== {label} =={RESET}")
    print(f"  INSECURE (1883): {'SUCCEEDED' if ins_ok else 'failed'} "
          f"{insecure_res['detail']}")
    print(f"  SECURE   (8883): {'BLOCKED' if sec_blocked else 'SUCCEEDED (!!)'} "
          f"{secure_res['detail']}")
    good = ins_ok and sec_blocked
    print(f"  RESULT: {(GREEN+'PASS'+RESET) if good else (RED+'CHECK'+RESET)}"
          f" — attack works on insecure, blocked on secure"
          if good else
          f"  RESULT: {RED}CHECK{RESET} — unexpected outcome")
    return good


def main():
    print("Secure IoT — Side-by-side attack demonstration")
    print("=" * 50)

    results = []

    # ATTACK 1: Anonymous / no-credential publish (spoofed sensor, no identity)
    ins = try_publish(INSECURE_HOST, INSECURE_PORT,
                      "devices/sensor-001/telemetry", "anon-attack",
                      use_tls=False)
    sec = try_publish(SECURE_HOST, SECURE_PORT,
                      "devices/sensor-001/telemetry", "anon-attack",
                      use_tls=True, cert_name=None)
    results.append(verdict("Attack 1: Anonymous publish (no credentials)", ins, sec))

    # ATTACK 2: Cross-device spoofing — a valid device writing to another's topic
    # On insecure there is no identity at all, so 'attacker' writes sensor-002.
    ins = try_publish(INSECURE_HOST, INSECURE_PORT,
                      "devices/sensor-002/telemetry", "spoof-002",
                      use_tls=False)
    # On secure, sensor-001's cert tries to publish to sensor-002's topic (ACL should block).
    sec = try_publish(SECURE_HOST, SECURE_PORT,
                      "devices/sensor-002/telemetry", "spoof-002",
                      use_tls=True, cert_name="sensor-001")
    # Note: secure connects fine (valid cert) but ACL blocks the publish to
    # another device's topic. QoS1 publish to a denied topic won't confirm.
    results.append(verdict("Attack 2: Cross-device spoofing (ACL bypass attempt)",
                           ins, sec))

    print("\n" + "=" * 50)
    passed = sum(results)
    print(f"Summary: {passed}/{len(results)} attacks correctly blocked on the "
          f"secure stack while succeeding on the insecure stack.")
    print("Full threat model in README. Revocation + validation demos run "
          "separately (see demo script).")


if __name__ == "__main__":
    main()