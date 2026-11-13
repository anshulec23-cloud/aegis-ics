"""Shared pytest configuration.

Runs before any test module is imported, so the environment set here is what
``src/database.py``, ``src/security.py`` and ``src/app.py`` see at import time.
No real secrets: every value below exists only for the test run.
"""

import os
import sys

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(TESTS_DIR, "..", "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Hermetic test database: start every session from an empty file.
TEST_DB = os.path.join(TESTS_DIR, "test_aegis.db")
for suffix in ("", "-wal", "-shm"):
    try:
        os.remove(TEST_DB + suffix)
    except FileNotFoundError:
        pass
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB}"

# Test-only credentials and keys.
TEST_ADMIN_PASSWORD = "test-admin-password-not-for-production"
TEST_GATEWAY_TOKEN = "test-gateway-token-not-for-production"
TEST_DEVICE_KEYS = {f"ESP32_00{i}": f"test-only-hmac-key-esp32-00{i}" for i in range(1, 5)}

os.environ["ADMIN_PASSWORD"] = TEST_ADMIN_PASSWORD
os.environ["AEGIS_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
for _dev, _key in TEST_DEVICE_KEYS.items():
    os.environ[f"DEVICE_KEY_{_dev}"] = _key

GATEWAY_HEADERS = {"X-Aegis-Gateway-Token": TEST_GATEWAY_TOKEN}
