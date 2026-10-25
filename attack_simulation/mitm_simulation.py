"""Simulated Man-in-the-Middle (MITM) tampering scenario."""

import uuid
from datetime import datetime
from typing import Dict, Any, Optional
import random


class MITMSimulator:
    """Demonstrates in-memory tampering of SCADA telemetry/control packets."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)

    def generate_mitm_event(self) -> Dict[str, Any]:
        """Generate a intercepted and modified in-flight communication event."""
        event_id = f"ev_mitm_{uuid.uuid4().hex[:8]}"

        return {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": "INTERCEPTOR_NODE",
            "dst_device": "PLC_01",
            "protocol": "MODBUS_TCP",
            "packet_rate": round(self.rng.uniform(1.2, 2.5), 2),
            "payload_length": self.rng.randint(70, 110),
            "function_code": 16,  # Force modified register writes
            "is_write": 1,
            "register_count": 2,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "mitm",
            "expected_label": "mitm",
            "status": "TAMPERED",
            "tampered_action": "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
        }
