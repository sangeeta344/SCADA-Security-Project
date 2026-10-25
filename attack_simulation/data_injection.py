"""Simulated False Data Injection Attack against SCADA sensors and actuators."""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import random


class DataInjectionSimulator:
    """Simulates malicious sensor tampering or unauthorized register write injections."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)

    def generate_injection_event(self) -> Dict[str, Any]:
        """Generate a malicious data injection or unauthorized write event."""
        event_id = f"ev_inj_{uuid.uuid4().hex[:8]}"
        is_write_attack = self.rng.choice([True, False])

        if is_write_attack:
            # Unauthorized write to registers (Modbus function code 6 or 16)
            fn_code = self.rng.choice([6, 16])
            is_write = 1
            payload_len = self.rng.randint(64, 128)
            packet_rate = round(self.rng.uniform(2.0, 5.0), 2)
        else:
            # Malicious sensor readout spoofing
            fn_code = 3
            is_write = 0
            payload_len = self.rng.randint(48, 80)
            packet_rate = round(self.rng.uniform(1.5, 3.5), 2)

        return {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": "ROGUE_CLIENT",
            "dst_device": "RTU_01",
            "protocol": "MODBUS_TCP",
            "packet_rate": packet_rate,
            "payload_length": payload_len,
            "function_code": fn_code,
            "is_write": is_write,
            "register_count": 4 if is_write else 7,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "injection",
            "expected_label": "injection",
            "status": "INJECTED",
            "spoofed_telemetry": {
                "temperature_c": round(self.rng.uniform(65.0, 95.0), 2),  # Dangerously high
                "pressure_bar": round(self.rng.uniform(5.0, 9.0), 2),      # Dangerously high
                "water_level_mm": round(self.rng.uniform(1200.0, 1500.0), 1),
            },
        }
