"""Local device-side policy checks.

The simulator uses this to reject server commands before execution,
matching the zero-trust requirement in the project README.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, cast


@dataclass(frozen=True)
class DevicePolicy:
    temp_range: tuple[float, float]
    pressure_range: tuple[float, float]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "DevicePolicy":
        temp = tuple(data.get("temp_range", (0.0, 50.0)))
        pressure = tuple(data.get("pressure_range", (0.0, 8.0)))
        return cls(
            temp_range=cast(tuple[float, float], (float(temp[0]), float(temp[1]))),
            pressure_range=cast(tuple[float, float], (float(pressure[0]), float(pressure[1]))),
        )

    def validate_command(self, command: Mapping[str, Any]) -> tuple[bool, str]:
        """Return whether a server command is allowed.

        Supported commands are simple setpoint updates.
        """

        if not isinstance(command, Mapping):
            return False, "command must be an object"

        command_type = command.get("type")
        if command_type not in {"set_temp", "set_pressure", "ping"}:
            return False, f"unsupported command type: {command_type!r}"

        if command_type == "ping":
            return True, "ok"

        value = command.get("value")
        if not isinstance(value, (int, float)):
            return False, "command value must be numeric"

        low, high = self.temp_range if command_type == "set_temp" else self.pressure_range
        if not (low <= float(value) <= high):
            return False, f"value {value} outside allowed range {low}-{high}"

        return True, "ok"
