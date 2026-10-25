"""Normal SCADA traffic generator simulating standard telemetry polling."""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import random

from config.protocol_config import ModbusRegisterMap


class NormalTrafficGenerator:
    """Generates standard industrial communication events."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.packet_counter = 0

    def generate_event(self, sensor_readings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a normal Modbus TCP read/status event."""
        self.packet_counter += 1
        event_id = f"ev_norm_{uuid.uuid4().hex[:8]}"

        # Normal Modbus packet characteristics:
        # function code 3 (Read Holding Registers), count 7, rate ~1.0 pkt/s, length ~12-64 bytes
        packet_rate = round(self.rng.uniform(0.8, 1.2), 2)
        payload_length = self.rng.randint(32, 64)

        return {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": "MTU_01",
            "dst_device": "RTU_01",
            "protocol": "MODBUS_TCP",
            "packet_rate": packet_rate,
            "payload_length": payload_length,
            "function_code": 3,  # Read Holding Registers
            "is_write": 0,
            "register_count": ModbusRegisterMap.TOTAL_REGISTERS,
            "is_duplicate": 0,
            "anomaly_flag": 0,
            "attack_category": "normal",
            "expected_label": "normal",
            "status": "PROCESSED",
        }
