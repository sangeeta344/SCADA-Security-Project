"""Unit tests for ML intrusion detection, sensor anomaly modeling, and dataset loaders."""

import pytest
from ml_detection.dataset_inspector import DatasetInspector
from ml_detection.network_dataset_loader import NetworkDatasetLoader
from ml_detection.sensor_dataset_loader import SensorDatasetLoader
from ml_detection.model_loader import model_loader
from ml_detection.predict_attack import attack_predictor


def test_dataset_discovery_and_schema():
    """Verify both datasets are discovered and have valid schemas."""
    inspector = DatasetInspector()
    report = inspector.inspect_all(output_report=False)

    net_info = report["network_dataset"]
    sens_info = report["sensor_dataset"]

    assert net_info["exists"] is True
    assert net_info["rows"] > 1000
    assert "label" in net_info["candidate_targets"]
    assert "type" in net_info["candidate_targets"]

    assert sens_info["exists"] is True
    assert sens_info["rows"] == 200
    assert "temperature_c" in sens_info["numeric_columns"]
    assert "pressure_bar" in sens_info["numeric_columns"]


def test_network_dataset_loader_and_stratification():
    """Verify network loader extracts clean feature matrix and target column."""
    loader = NetworkDatasetLoader()
    X, y, meta = loader.load_data(target_column="type", sample_size=500, random_state=42)

    assert len(X) == 500
    assert len(y) == 500
    assert "src_ip" not in X.columns, "src_ip must be dropped to prevent target leakage"
    assert "type" not in X.columns, "target must not be in feature matrix"
    assert len(meta["classes"]) >= 5


def test_sensor_dataset_loader():
    """Verify sensor dataset loader extracts 4 continuous numeric features."""
    loader = SensorDatasetLoader()
    full_df, X_numeric, meta = loader.load_data()

    assert len(full_df) == 200
    assert list(X_numeric.columns) == ["temperature_c", "pressure_bar", "water_level_mm", "flow_rate_lpm"]
    assert meta["has_timestamps"] is True


def test_trained_models_availability_and_inference():
    """Verify saved models load and perform reliable predictions."""
    status = model_loader.get_models_status()
    assert status["network_model"]["available"] is True
    assert status["sensor_model"]["available"] is True

    # 1. Network normal event
    norm_event = {
        "event_id": "test_norm_01",
        "protocol": "MODBUS_TCP",
        "packet_rate": 1.0,
        "payload_length": 48,
        "src_device": "MTU_01",
    }
    net_pred = attack_predictor.predict_network_event(norm_event)
    assert net_pred["model_available"] is True
    assert net_pred["predicted_class"] in status["network_model"]["metrics"]["classes"]

    # 2. Sensor normal vs anomaly
    norm_sensor = {"temperature_c": 28.0, "pressure_bar": 2.5, "water_level_mm": 910.0, "flow_rate_lpm": 35.0}
    sens_norm_res = attack_predictor.predict_sensor_telemetry(norm_sensor)
    assert sens_norm_res["is_anomaly"] == 0

    bad_sensor = {"temperature_c": 92.0, "pressure_bar": 7.8, "water_level_mm": 1450.0, "flow_rate_lpm": 95.0}
    sens_bad_res = attack_predictor.predict_sensor_telemetry(bad_sensor)
    assert sens_bad_res["is_anomaly"] == 1
    assert sens_bad_res["anomaly_score"] < 0.0
