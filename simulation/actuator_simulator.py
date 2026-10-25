"""Actuator simulators for pumps, valves, and safety switches."""

from typing import Dict, Any
from datetime import datetime


class Pump:
    """Industrial water pump with ON/OFF binary states and safety interlock."""

    def __init__(self, pump_id: str = "PUMP_01", name: str = "Feed Pump"):
        self.pump_id = pump_id
        self.name = name
        self.is_running = True  # Default nominal state: Running
        self.rpm = 1750
        self.status = "NORMAL"

    def set_state(self, run: bool) -> bool:
        """Command pump state."""
        self.is_running = run
        self.rpm = 1750 if run else 0
        return self.is_running

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actuator_id": self.pump_id,
            "name": self.name,
            "state": "ON" if self.is_running else "OFF",
            "state_int": 1 if self.is_running else 0,
            "rpm": self.rpm,
            "status": self.status,
        }


class Valve:
    """Motorized flow control valve with OPEN/CLOSED states."""

    def __init__(self, valve_id: str = "VALVE_01", name: str = "Discharge Valve"):
        self.valve_id = valve_id
        self.name = name
        self.is_open = False  # Default nominal state: Closed
        self.position_percent = 0.0
        self.status = "NORMAL"

    def set_state(self, open_state: bool) -> bool:
        """Command valve state."""
        self.is_open = open_state
        self.position_percent = 100.0 if open_state else 0.0
        return self.is_open

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actuator_id": self.valve_id,
            "name": self.name,
            "state": "OPEN" if self.is_open else "CLOSED",
            "state_int": 1 if self.is_open else 0,
            "position_percent": self.position_percent,
            "status": self.status,
        }


class ActuatorSimulator:
    """Manages the full industrial actuator subsystem."""

    def __init__(self):
        self.pump = Pump()
        self.valve = Valve()

    def get_state(self) -> Dict[str, Any]:
        return {
            "pump": self.pump.to_dict(),
            "valve": self.valve.to_dict(),
            "pump_state_int": self.pump.to_dict()["state_int"],
            "valve_state_int": self.valve.to_dict()["state_int"],
        }
