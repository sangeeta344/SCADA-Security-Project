"""Simulated Replay Attack scenario against SCADA telemetry."""

import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import random


class ReplayAttackSimulator:
    """Simulates replay of previously observed SCADA packets."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.recorded_buffer: List[Dict[str, Any]] = []

    def record_normal_event(self, event: Dict[str, Any]) -> None:
        """Capture a normal event to replay later."""
        if len(self.recorded_buffer) >= 20:
            self.recorded_buffer.pop(0)
        self.recorded_buffer.append(dict(event))

    def generate_replay_event(self) -> Dict[str, Any]:
        """Generate a replayed packet with duplicate sequence and stale timestamp."""
        event_id = f"ev_rep_{uuid.uuid4().hex[:8]}"

        if self.recorded_buffer:
            source_event = self.rng.choice(self.recorded_buffer)
            stale_timestamp = source_event.get("timestamp")
            payload_len = source_event.get("payload_length", 48)
            fn_code = source_event.get("function_code", 3)
        else:
            # Synthetic fallback if buffer is empty
            stale_time = datetime.now() - timedelta(minutes=self.rng.randint(15, 60))
            stale_timestamp = stale_time.strftime("%Y-%m-%d %H:%M:%S")
            payload_len = 48
            fn_code = 3

        return {
            "event_id": event_id,
            "timestamp": stale_timestamp,
            "src_device": "UNKNOWN_HOST (Attacker)",
            "dst_device": "RTU_01",
            "protocol": "MODBUS_TCP",
            "packet_rate": round(self.rng.uniform(1.0, 3.0), 2),
            "payload_length": payload_len,
            "function_code": fn_code,
            "is_write": 0,
            "register_count": 7,
            "is_duplicate": 1,        # Crucial replay marker
            "anomaly_flag": 1,
            "attack_category": "replay",
            "expected_label": "replay",
            "status": "REPLAYED",
        }
