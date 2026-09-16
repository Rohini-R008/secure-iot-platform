# Secure IoT Monitoring Platform

A monitoring platform for IoT sensor fleets with a security-first design:
per-device identity, encrypted transport, role-based access, full audit
logging, and a side-by-side insecure-vs-secure attack demo.

## Architecture (Phase 1)
Simulated devices --(MQTT over mutual TLS)--> Mosquitto broker

Each device authenticates with its own X.509 client certificate. The
certificate's Common Name is used as the device identity, and an ACL
restricts each device to its own topic subtree. There are no shared
passwords anywhere in the system.

## Status
- [x] Phase 1 — Broker & Identity Broker & Identity (verified: valid publish succeeds, anonymous refused, cross-device publish blocked by ACL)
- [x] Phase 2 — Processing & Storage (validation, anomaly flagging, rejection audit log, InfluxDB)
- [x] Phase 3 — Access Control & Observability (RBAC, audit logging, CRL revocation, Grafana dashboard)
- [ ] Phase 4 — Threat Model & Insecure/Secure Demo

## Quick start (Phase 1)
See `docs`/steps below. Generate certs, start the broker, run the simulator.