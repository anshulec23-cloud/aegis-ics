from __future__ import annotations

import os


def load_device_key(device_id: str) -> str | None:
    return os.getenv(f"DEVICE_KEY_{device_id}")
