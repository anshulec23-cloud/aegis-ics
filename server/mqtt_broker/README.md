# MQTT Broker

This folder holds the Mosquitto broker configuration and the ACL updater.

## Files
- `mosquitto.conf` - broker settings, TLS, port, logging, and ACL path.
- `acl.conf` - current allow-list of topic permissions.
- `acl_manager.py` - adds or removes device entries and reloads the broker.

## Topic Layout
- `ics/telemetry/{device_id}` - device publishes, server subscribes.
- `ics/control/{device_id}` - server publishes, device subscribes.
- `ics/alerts/{device_id}` - device publishes alerts, server subscribes.

## What It Does
If a device is isolated, its ACL entry is removed and the broker is reloaded so it can no longer talk on its topics.
