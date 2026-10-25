"""Unit tests for SQLite database schema, connections, and repository queries."""

import pytest
from pathlib import Path
from database.db import Database
from database.repository import Repository
from database.models import Device, SensorReading, NetworkTrafficEvent, AttackAlert, QuantumSession


@pytest.fixture
def temp_db(tmp_path: Path):
    """Create isolated test database."""
    db_file = tmp_path / "test_scada.db"
    db_instance = Database(db_path=db_file)
    db_instance.init_db()
    return db_instance


def test_db_initialization_and_devices(temp_db):
    """Verify tables are created and default industrial devices are seeded."""
    repo = Repository(database=temp_db)
    devices = repo.get_all_devices()
    assert len(devices) == 10

    # Update status
    repo.update_device_status("RTU_01", "DEGRADED")
    updated = [d for d in repo.get_all_devices() if d.id == "RTU_01"][0]
    assert updated.status == "DEGRADED"


def test_sensor_readings_crud(temp_db):
    """Verify sensor reading insertion and chronological retrieval."""
    repo = Repository(database=temp_db)
    reading = SensorReading(
        sensor_id="TEMP_01",
        rtu_id="RTU_01",
        temperature_c=28.5,
        pressure_bar=2.6,
        water_level_mm=915.0,
        flow_rate_lpm=35.5,
        operating_status="NORMAL",
    )
    row_id = repo.insert_sensor_reading(reading)
    assert row_id > 0

    series = repo.get_sensor_time_series(limit=10)
    assert len(series) == 1
    assert series[0]["temperature_c"] == 28.5


def test_traffic_and_alert_crud(temp_db):
    """Verify traffic event insertion, summary aggregation, and alerts."""
    repo = Repository(database=temp_db)

    ev = NetworkTrafficEvent(
        event_id="test_ev_101",
        src_device="MTU_01",
        dst_device="RTU_01",
        protocol="MODBUS_TCP",
        packet_rate=1.0,
        payload_length=48,
        predicted_class="normal",
        confidence=0.98,
    )
    repo.insert_traffic_event(ev)

    summary = repo.get_traffic_summary()
    assert summary["total_messages"] == 1
    assert summary["normal_count"] == 1
    assert summary["attack_count"] == 0

    alert = AttackAlert(
        alert_id="alt_test_01",
        attack_type="dos",
        source_device="BOT_01",
        severity="HIGH",
        predicted_label="dos",
        confidence=0.95,
        details="Flooding detected",
        mitigation_action="Throttle IP",
    )
    alert_id = repo.insert_attack_alert(alert)
    assert alert_id > 0

    alerts = repo.get_recent_alerts(limit=5)
    assert len(alerts) == 1
    assert alerts[0].attack_type == "dos"
