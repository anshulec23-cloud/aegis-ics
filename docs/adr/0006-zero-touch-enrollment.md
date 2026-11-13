# 0006. Zero-touch device enrollment with one-click approval

- **Status:** Accepted
- **Date:** 2026-11-14
- **Supersedes:** the manual key-generation step introduced in v2.6 Phase 1 (`device_keys.py generate`)

## Context
Phase 1 removed the hard-coded HMAC keys, but replaced them with a manual step: run a script to generate keys and compile them into each slave's firmware. That doesn't fit the deployment:

- The bus is master/slave with an **unknown number of slaves**. Slaves are added and replaced in the field.
- The product ships as a packaged desktop/server application (`AegisICS.exe`, `.deb`). Operators won't run Python scripts or rebuild firmware per node.
- Zero trust still has to hold: a board someone plugs into the bus must not be able to join and inject data or receive commands.

## Decision
1. **One firmware image for all slaves.** On first boot a slave derives its device ID from its eFuse MAC (`ESP32_A1B2C3`), generates an X25519 key pair with the hardware RNG, and stores it in NVS. No per-node compile-time configuration remains.
2. **Discovery.** The master bridge polls known slaves and periodically opens a discovery slot. An unenrolled slave answers with `HELLO {id, pub, sensors, fw, boot}`.
3. **Pending state.** The host records the slave in the `devices` registry as `pending`, with a short fingerprint of its public key (shown on the dashboard and printed on the slave's USB console). Pending devices get no key, and their telemetry isn't accepted.
4. **One-click approval.** An operator clicks **Approve** (audited). The host computes `shared = X25519(host_priv, device_pub)` and `key = HKDF-SHA256(shared, salt="aegis-ics-v1", info=device_id|device_pub|host_pub)`, then sends `WELCOME {id, hpub, sig}`. The slave derives the same key, checks `sig` (proving the host holds it), stores the key in NVS and confirms with a signed `ACK`.
5. **Key changes are alarms.** If an approved device ID announces a *different* public key (reflashed board or impersonation), it drops back to `pending` with a `DEVICE_KEY_CHANGED` audit entry. An operator must approve it again.
6. **Host identity.** The host's X25519 key is generated on first start in the data directory (`host_identity.key`, 0600).
7. **Legacy path.** v0 firmware with compile-time keys keeps working through `DEVICE_KEY_<ID>` or a key file, for existing benches. New deployments don't need it.

## Consequences
- **+** No manual key handling anywhere; any number of slaves; one firmware binary.
- **+** Passive eavesdroppers on the bus never see the key. Rogue boards can't join without an operator click.
- **−** An active man-in-the-middle **during enrollment** could substitute keys. Mitigation: the fingerprint is shown on the dashboard and on the slave's USB console for comparison, and enrollment happens on the plant's own bus.
- **−** Keys live in the host database. That's acceptable for the threat model (host compromise is game over anyway); encrypting them at rest is a Phase 5 item.

## Alternatives considered
- **Fully automatic trust-on-first-use:** rejected by the project owner; any board on the bus could join.
- **Factory-provisioned keys / certificates:** right for a commercial product line, but too heavy for this project's manufacturing reality.
- **Sending a host-generated key in the clear during enrollment:** rejected; it exposes the key to anyone sniffing the bus.
