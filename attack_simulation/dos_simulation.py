"""Simulated Denial-of-Service (DoS) flood scenario with strict safety limits."""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import random


class DoSSimulator:
    """Generates synthetic high-rate request bursts within strictly controlled local limits."""

    def __init__(self, max_burst_size: int = 50, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.max_burst_size = max_burst_size

    def generate_dos_event(self) -> Dict[str, Any]:
        """Generate a single packet event characteristic of a high-rate DoS flood."""
        event_id = f"ev_dos_{uuid.uuid4().hex[:8]}"

        # Typical DoS flood characteristics: high packet rate, small malformed payloads, rapid repeated queries
        packet_rate = round(self.rng.uniform(45.0, 120.0), 1)
        payload_length = self.rng.randint(8, 24)  # Small probe packets

        return {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": f"BOTNET_NODE_{self.rng.randint(100, 999)}",
            "dst_device": "RTU_01",
            "protocol": "MODBUS_TCP",
            "packet_rate": packet_rate,
            "payload_length": payload_length,
            "function_code": 3,
            "is_write": 0,
            "register_count": 1,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "dos",
            "expected_label": "dos",
            "status": "FLOODING",
        }
