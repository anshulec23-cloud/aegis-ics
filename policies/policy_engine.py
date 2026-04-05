from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    def __init__(self, policy_path: str | Path = "server_policy.json", device_policy_dir: str | Path = "device_policies") -> None:
        self.policy_path = Path(policy_path)
        self.device_policy_dir = Path(device_policy_dir)
        self.server_policy = self._load_json(self.policy_path)

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def load_device_policy(self, device_id: str) -> dict[str, Any]:
        path = self.device_policy_dir / f"{device_id}.json"
        return self._load_json(path) if path.exists() else {}

    def validate_outgoing_command(self, device_id: str, command: dict[str, Any]) -> PolicyDecision:
        if not isinstance(command, dict):
            return PolicyDecision(False, "command must be a JSON object")

        command_type = command.get("type")
        value = command.get("value")
        device_policy = self.load_device_policy(device_id)

        if command_type == "isolate":
            return PolicyDecision(bool(self.server_policy.get("can_isolate_devices", False)), "ok")

        if command_type == "grant_privileges":
            return PolicyDecision(bool(self.server_policy.get("can_grant_privileges", False)), "privilege escalation blocked")

        if command_type not in set(device_policy.get("allowed_commands", [])):
            return PolicyDecision(False, f"{command_type!r} not allowed for {device_id}")

        if command_type == "set_temp":
            low, high = self.server_policy.get("allowed_temp_setpoint_range", [0, 50])
        elif command_type == "set_pressure":
            low, high = self.server_policy.get("allowed_pressure_setpoint_range", [0, 8])
        else:
            return PolicyDecision(True, "ok")

        if not isinstance(value, (int, float)):
            return PolicyDecision(False, "command value must be numeric")
        if not (float(low) <= float(value) <= float(high)):
            return PolicyDecision(False, f"value {value} outside allowed range {low}-{high}")

        return PolicyDecision(True, "ok")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate server commands against zero-trust policies")
    parser.add_argument("device_id")
    parser.add_argument("command_json")
    parser.add_argument("--policy-path", default="server_policy.json")
    parser.add_argument("--device-policy-dir", default="device_policies")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    engine = PolicyEngine(args.policy_path, args.device_policy_dir)
    decision = engine.validate_outgoing_command(args.device_id, json.loads(args.command_json))
    print(json.dumps({"allowed": decision.allowed, "reason": decision.reason}, indent=2))
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
