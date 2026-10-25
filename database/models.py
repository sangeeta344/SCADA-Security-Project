"""Data models and entities for the SCADA security prototype."""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class Device:
    id: str
    name: str
    device_type: str
    protocol: str
    ip_address: Optional[str] = None
    port: Optional[int] = None
    status: str = "OFFLINE"
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    username: str
    email: str
    password_hash: str
    role: str = "Operator"
    created_at: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
        }


@dataclass
class SensorReading:
    sensor_id: str
    rtu_id: str
    temperature_c: float
    pressure_bar: float
    water_level_mm: float
    flow_rate_lpm: float
    operating_status: str = "NORMAL"
    is_anomaly: int = 0
    anomaly_score: float = 0.0
    source: str = "SIMULATED"
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkTrafficEvent:
    event_id: str
    src_device: str
    dst_device: str
    protocol: str
    packet_rate: float
    payload_length: int
    function_code: Optional[int] = None
    is_write: int = 0
    register_count: int = 0
    is_duplicate: int = 0
    anomaly_flag: int = 0
    predicted_class: str = "normal"
    confidence: float = 1.0
    attack_category: str = "normal"
    expected_label: str = "normal"
    status: str = "PROCESSED"
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackAlert:
    alert_id: str
    attack_type: str
    source_device: str
    severity: str
    predicted_label: str
    confidence: float
    details: str
    mitigation_action: str
    acknowledged: int = 0
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QuantumSession:
    session_id: str
    alice_id: str
    bob_id: str
    raw_bits_count: int
    sifted_bits_count: int
    disclosed_sample_count: int
    final_key_bits_count: int
    qber: float
    qber_threshold: float
    status: str  # ACCEPTED or REJECTED
    eavesdropper_present: int = 0
    noise_level: float = 0.0
    rejection_reason: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class QberMeasurement:
    session_id: str
    qber: float
    sample_size: int
    errors_detected: int
    noise_level: float
    eavesdropper_present: int
    threshold: float
    passed: int
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModelEvaluation:
    model_name: str
    model_type: str
    dataset_name: str
    train_samples: int
    test_samples: int
    metrics_json: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
