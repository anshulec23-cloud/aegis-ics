# TLS Certificates

Generate your own local TLS materials here. Do not commit private keys.

## Files
- `generate_certs.py` - helper script that creates the root CA, server cert, and device certs.
- `requirements.txt` - notes that only the system OpenSSL CLI is needed.

## Generate All Certs (run this once on the host)

# Step 1: Self-signed root certificate (replaces paid CA)
openssl req -x509 -newkey rsa:4096 -keyout root-ca.key -out root-ca.crt \
  -days 3650 -nodes -subj "/CN=ZeroTrust-ICS-Root"

# Step 2: Server certificate signed by root
openssl req -newkey rsa:2048 -keyout server.key -out server.csr \
  -nodes -subj "/CN=server.example"
openssl x509 -req -in server.csr -CA root-ca.crt -CAkey root-ca.key \
  -CAcreateserial -out server.crt -days 365

# Step 3: Per-device certificates (repeat for each simulated device)
openssl req -newkey rsa:2048 -keyout ESP32_001.key -out ESP32_001.csr \
  -nodes -subj "/CN=ESP32_001"
openssl x509 -req -in ESP32_001.csr -CA root-ca.crt -CAkey root-ca.key \
  -CAcreateserial -out ESP32_001.crt -days 365

## Files that will live here after generation
- `root-ca.crt`, `root-ca.key`
- `server.crt`, `server.key`
- `ESP32_001.crt`, `ESP32_001.key` - one pair per simulated device
