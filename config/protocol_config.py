"""Modbus register maps, MQTT topics, and protocol constants."""

from typing import Dict, Any


class ModbusRegisterMap:
    """Documented Modbus register addresses and scaling factors."""

    # Holding Registers (16-bit unsigned integers)
    # Scaled integer representations for engineering decimals:
    REG_TEMPERATURE = 0    # e.g., 2811 = 28.11 deg C (scale factor 100)
    REG_PRESSURE = 1       # e.g., 2603 = 2.603 bar (scale factor 1000)
    REG_WATER_LEVEL = 2    # e.g., 9314 = 931.4 mm (scale factor 10)
    REG_FLOW_RATE = 3      # e.g., 3404 = 34.04 lpm (scale factor 100)
    REG_PUMP_STATE = 4     # 0 = OFF, 1 = ON
    REG_VALVE_STATE = 5    # 0 = CLOSED, 1 = OPEN
    REG_STATUS = 6         # 1 = NORMAL, 2 = WARNING, 3 = ALARM, 4 = ATTACK

    TOTAL_REGISTERS = 7

    # Scaling multipliers to convert physical engineering float -> 16-bit register int
    SCALE_FACTORS: Dict[int, float] = {
        REG_TEMPERATURE: 100.0,
        REG_PRESSURE: 1000.0,
        REG_WATER_LEVEL: 10.0,
        REG_FLOW_RATE: 100.0,
        REG_PUMP_STATE: 1.0,
        REG_VALVE_STATE: 1.0,
        REG_STATUS: 1.0,
    }

    # Engineering units
    UNITS: Dict[int, str] = {
        REG_TEMPERATURE: "°C",
        REG_PRESSURE: "bar",
        REG_WATER_LEVEL: "mm",
        REG_FLOW_RATE: "L/min",
        REG_PUMP_STATE: "state",
        REG_VALVE_STATE: "state",
        REG_STATUS: "code",
    }

    @classmethod
    def encode_value(cls, address: int, physical_value: float) -> int:
        """Encode physical float value into integer register representation."""
        factor = cls.SCALE_FACTORS.get(address, 1.0)
        int_val = int(round(physical_value * factor))
        return max(0, min(65535, int_val))

    @classmethod
    def decode_value(cls, address: int, register_value: int) -> float:
        """Decode integer register representation into physical float value."""
        factor = cls.SCALE_FACTORS.get(address, 1.0)
        return float(register_value) / factor if factor != 0 else float(register_value)


class MQTTTopics:
    """Documented MQTT topic definitions."""

    RTU_TELEMETRY = "scada/rtu1/telemetry"
    RTU_STATUS = "scada/rtu1/status"
    PLC_STATUS = "scada/plc1/status"
    SECURITY_ALERTS = "scada/security/alerts"
    QUANTUM_STATUS = "scada/quantum/status"
    ATTACK_EVENTS = "scada/attacks/events"

    ALL_TOPICS = [
        RTU_TELEMETRY,
        RTU_STATUS,
        PLC_STATUS,
        SECURITY_ALERTS,
        QUANTUM_STATUS,
        ATTACK_EVENTS,
    ]
