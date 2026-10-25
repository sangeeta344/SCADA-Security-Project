"""Master Terminal Unit (MTU) / SCADA Server simulation."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from config.protocol_config import ModbusRegisterMap
from database.repository import Repository, repo as default_repo
from database.models import SensorReading
from config.logging_config import logger


class MTUSimulator:
    """SCADA Central MTU supervisor that polls RTUs, maintains status, and logs telemetry."""

    def __init__(self, mtu_id: str = "MTU_01", repository: Optional[Repository] = None):
        self.mtu_id = mtu_id
        self.repo = repository or default_repo
        self.latest_readings: Dict[str, Any] = {}
        self.poll_count: int = 0
        self.is_connected: bool = True

    def process_telemetry(self, telemetry: Dict[str, Any], source: str = "SIMULATED") -> SensorReading:
        """Process received telemetry, persist to database, and update internal state."""
        self.poll_count += 1
        self.latest_readings = telemetry

        reading = SensorReading(
            sensor_id=telemetry.get("sensor_id", "SENSOR_01"),
            rtu_id=telemetry.get("rtu_id", "RTU_01"),
            temperature_c=float(telemetry.get("temperature_c", 0.0)),
            pressure_bar=float(telemetry.get("pressure_bar", 0.0)),
            water_level_mm=float(telemetry.get("water_level_mm", 0.0)),
            flow_rate_lpm=float(telemetry.get("flow_rate_lpm", 0.0)),
            operating_status=telemetry.get("operating_status", "NORMAL"),
            is_anomaly=telemetry.get("is_anomaly", 0),
            anomaly_score=float(telemetry.get("anomaly_score", 0.0)),
            source=source,
        )

        try:
            self.repo.insert_sensor_reading(reading)
        except Exception as e:
            logger.error("MTU failed to record sensor reading: %s", e)

        return reading

    def decode_modbus_registers(self, registers: List[int]) -> Dict[str, Any]:
        """Decode a 7-register Modbus block into engineering units."""
        if len(registers) < ModbusRegisterMap.TOTAL_REGISTERS:
            raise ValueError(f"Expected at least {ModbusRegisterMap.TOTAL_REGISTERS} registers, got {len(registers)}")

        temp = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_TEMPERATURE, registers[0])
        press = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_PRESSURE, registers[1])
        level = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_WATER_LEVEL, registers[2])
        flow = ModbusRegisterMap.decode_value(ModbusRegisterMap.REG_FLOW_RATE, registers[3])
        pump_state = "ON" if registers[4] == 1 else "OFF"
        valve_state = "OPEN" if registers[5] == 1 else "CLOSED"

        status_rev_map = {1: "NORMAL", 2: "WARNING", 3: "ALARM", 4: "ATTACK"}
        status = status_rev_map.get(registers[6], "UNKNOWN")

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "temperature_c": temp,
            "pressure_bar": press,
            "water_level_mm": level,
            "flow_rate_lpm": flow,
            "pump_state": pump_state,
            "valve_state": valve_state,
            "operating_status": status,
        }
