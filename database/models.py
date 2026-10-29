"""Data models and entities for the SCADA security prototype."""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
from datetime import datetime
import re


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
class SensorReading:
    sensor_id: str
    rtu_id: str
    temperature_c: float
    pressure_bar: float
    water_level_mm: float
    flow_rate_lpm: float
    operating_status: str = "NORMAL"
    is_anomaly: int = 0
    anomaly_score: Optional[float] = None
    source: str = "SIMULATION"
    timestamp: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActuatorState:
    actuator_id: str
    plc_id: str
    state: str
    manual_override: int = 0
    override_reason: Optional[str] = None
    last_changed: Optional[str] = None

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

    @property
    def target_display(self) -> str:
        """Target device or masked target operator account."""
        if self.attack_type and self.attack_type.lower() in ("password", "brute_force", "bruteforce"):
            m = re.search(r"account ['\"]([^'\"]+)['\"]", self.details or "")
            if m:
                return m.group(1)
            return "AUTH_SVC (Operator Login)"
        if self.source_device and "->" in self.source_device:
            return self.source_device.split("->")[-1].strip()
        return self.source_device or "SCADA_GATEWAY"

    @property
    def detection_method_display(self) -> str:
        """Categorize detector as ML (Isolation Forest, Random Forest) or Rule-Based Guard."""
        dt = self.details or ""
        if "IsolationForest" in dt:
            return "Isolation Forest (ML)"
        elif "RandomForest" in dt:
            return "Random Forest (ML)"
        elif "Freshness" in dt or "Replay Guard" in dt or "stale" in dt.lower():
            return "Freshness & Sequence (Rule)"
        elif "Brute-Force" in dt or "Authentication Guard" in dt or "Rate Guard" in dt:
            return "Auth Rate Guard (Rule)"
        return "Hybrid SCADA Guard"

    @property
    def status_display(self) -> str:
        """Operational incident status."""
        if self.attack_type and self.attack_type.lower() in ("password", "brute_force", "bruteforce"):
            return "LOCKOUT ACTIVE"
        return "RECORDED"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["target"] = self.target_display
        data["detection_method"] = self.detection_method_display
        data["incident_status"] = self.status_display
        return data


@dataclass
class EmailNotificationRecord:
    incident_id: str
    recipient: str
    subject: str
    status: str = "pending"  # pending, sent, failed, skipped
    attempt_count: int = 0
    created_at: Optional[str] = None
    last_attempt: Optional[str] = None
    sent_at: Optional[str] = None
    failure_reason: Optional[str] = None
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
    measured_at: Optional[str] = None
    id: Optional[int] = None

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
        d = asdict(self)
        d.pop("password_hash", None)
        return d


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

