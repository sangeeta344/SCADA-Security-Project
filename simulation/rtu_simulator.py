"""Remote Terminal Unit (RTU) simulator mapping physical telemetry to Modbus registers."""

import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from config.protocol_config import ModbusRegisterMap
from config.settings import settings
from config.logging_config import logger


class RTUSimulator:
    """RTU that converts sensor and actuator data into Modbus register structures."""

    def __init__(self, rtu_id: str = "RTU_01", csv_path: Optional[Path] = None):
        self.rtu_id = rtu_id
        self.registers: List[int] = [0] * ModbusRegisterMap.TOTAL_REGISTERS
        self.latest_telemetry: Dict[str, Any] = {}
        self.csv_rows: List[Dict[str, str]] = []
        self.csv_index: int = 0
        self.csv_mode: bool = False

        target_csv = csv_path or settings.SENSOR_DATASET_PATH
        if target_csv and Path(target_csv).exists():
            try:
                with open(target_csv, "r", encoding="utf-8") as f:
                    self.csv_rows = list(csv.DictReader(f))
                if self.csv_rows:
                    logger.info("RTU loaded %d sensor records from %s", len(self.csv_rows), target_csv)
            except Exception as e:
                logger.warning("Could not load CSV records for RTU: %s", e)

    def update_from_telemetry(
        self, sensor_data: Dict[str, Any], actuator_data: Optional[Dict[str, Any]] = None
    ) -> List[int]:
        """Update internal 16-bit Modbus holding registers from live engineering units."""
        self.latest_telemetry = {**sensor_data}
        actuator_data = actuator_data or {}

        # 0: Temperature (scaled)
        self.registers[ModbusRegisterMap.REG_TEMPERATURE] = ModbusRegisterMap.encode_value(
            ModbusRegisterMap.REG_TEMPERATURE, float(sensor_data.get("temperature_c", 28.0))
        )
        # 1: Pressure (scaled)
        self.registers[ModbusRegisterMap.REG_PRESSURE] = ModbusRegisterMap.encode_value(
            ModbusRegisterMap.REG_PRESSURE, float(sensor_data.get("pressure_bar", 2.5))
        )
        # 2: Water Level (scaled)
        self.registers[ModbusRegisterMap.REG_WATER_LEVEL] = ModbusRegisterMap.encode_value(
            ModbusRegisterMap.REG_WATER_LEVEL, float(sensor_data.get("water_level_mm", 900.0))
        )
        # 3: Flow Rate (scaled)
        self.registers[ModbusRegisterMap.REG_FLOW_RATE] = ModbusRegisterMap.encode_value(
            ModbusRegisterMap.REG_FLOW_RATE, float(sensor_data.get("flow_rate_lpm", 35.0))
        )

        # 4: Pump state
        pump_state = actuator_data.get("pump_state_int", 1)
        self.registers[ModbusRegisterMap.REG_PUMP_STATE] = pump_state

        # 5: Valve state
        valve_state = actuator_data.get("valve_state_int", 0)
        self.registers[ModbusRegisterMap.REG_VALVE_STATE] = valve_state

        # 6: Operating status code (1=NORMAL, 2=WARNING, 3=ALARM, 4=ATTACK)
        status_str = sensor_data.get("operating_status", "NORMAL").upper()
        status_map = {"NORMAL": 1, "WARNING": 2, "ALARM": 3, "ATTACK": 4}
        self.registers[ModbusRegisterMap.REG_STATUS] = status_map.get(status_str, 1)

        return self.registers

    def step_csv(self) -> Dict[str, Any]:
        """Fetch next row from the CSV dataset if available."""
        if not self.csv_rows:
            return {}
        row = self.csv_rows[self.csv_index]
        self.csv_index = (self.csv_index + 1) % len(self.csv_rows)

        telemetry = {
            "timestamp": row.get("timestamp"),
            "sensor_id": row.get("sensor_id", "SENSOR_01"),
            "rtu_id": row.get("rtu_id", self.rtu_id),
            "temperature_c": float(row.get("temperature_c", 28.0)),
            "pressure_bar": float(row.get("pressure_bar", 2.5)),
            "water_level_mm": float(row.get("water_level_mm", 900.0)),
            "flow_rate_lpm": float(row.get("flow_rate_lpm", 35.0)),
            "operating_status": row.get("operating_status", "NORMAL"),
        }
        self.update_from_telemetry(telemetry)
        return telemetry

    def get_register(self, address: int) -> int:
        """Get holding register value by address."""
        if 0 <= address < len(self.registers):
            return self.registers[address]
        raise ValueError(f"Invalid register address {address}")

    def set_register(self, address: int, value: int) -> None:
        """Write holding register value by address."""
        if 0 <= address < len(self.registers):
            self.registers[address] = int(value) & 0xFFFF
        else:
            raise ValueError(f"Invalid register address {address}")
