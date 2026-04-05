from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MicroSegmentationStore:
    path: Path
    isolated_devices: set[str] = field(default_factory=set)

    def load(self) -> None:
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.isolated_devices = set(data.get("isolated_devices", []))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"isolated_devices": sorted(self.isolated_devices)}
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def isolate(self, device_id: str) -> None:
        self.isolated_devices.add(device_id)
        self.save()

    def rejoin(self, device_id: str) -> None:
        self.isolated_devices.discard(device_id)
        self.save()

    def list_isolated(self) -> list[str]:
        return sorted(self.isolated_devices)

