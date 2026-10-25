"""Model evaluation utilities and benchmark reporting."""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from config.settings import settings
from config.logging_config import logger
from ml_detection.model_loader import model_loader
from ml_detection.network_dataset_loader import NetworkDatasetLoader
from ml_detection.sensor_dataset_loader import SensorDatasetLoader


class ModelEvaluator:
    """Evaluates and reports benchmarks for saved network and sensor models."""

    @staticmethod
    def get_summary_report() -> Dict[str, Any]:
        """Aggregate stored evaluation metrics into a unified summary."""
        net_metrics = model_loader.get_network_metrics()
        sensor_metrics = model_loader.get_sensor_metrics()

        return {
            "network_intrusion_model": net_metrics or {
                "status": "NOT_TRAINED",
                "message": "Run 'python -m ml_detection.network_train' to train model.",
            },
            "sensor_anomaly_model": sensor_metrics or {
                "status": "NOT_TRAINED",
                "message": "Run 'python -m ml_detection.sensor_train' to train model.",
            },
        }


def main():
    print("=" * 70)
    print("SCADA MACHINE LEARNING MODEL EVALUATION REPORT")
    print("=" * 70)
    report = ModelEvaluator.get_summary_report()

    net = report["network_intrusion_model"]
    print("\n--- 1. NETWORK INTRUSION DETECTION MODEL ---")
    if net.get("status") == "NOT_TRAINED":
        print("Status: NOT TRAINED. Use python -m ml_detection.network_train")
    else:
        print(f"Model: {net.get('model_type')} | Dataset: {net.get('dataset_name')}")
        print(f"Train Samples: {net.get('train_samples')} | Test Samples: {net.get('test_samples')}")
        print(f"Accuracy:  {net.get('accuracy')}")
        print(f"Precision: {net.get('precision')}")
        print(f"Recall:    {net.get('recall')}")
        print(f"F1-Score:  {net.get('f1_score')}")
        print("Per-class performance preview:")
        cr = net.get("classification_report", {})
        for cls_name in list(net.get("classes", []))[:6]:
            if cls_name in cr:
                c_stats = cr[cls_name]
                print(f"  * {cls_name:12s}: Precision={c_stats.get('precision', 0):.2f}, Recall={c_stats.get('recall', 0):.2f}, F1={c_stats.get('f1-score', 0):.2f}")

    sensor = report["sensor_anomaly_model"]
    print("\n--- 2. SENSOR ANOMALY DETECTION MODEL ---")
    if sensor.get("status") == "NOT_TRAINED":
        print("Status: NOT TRAINED. Use python -m ml_detection.sensor_train")
    else:
        print(f"Model: {sensor.get('model_type')} | Dataset: {sensor.get('dataset_name')}")
        print(f"Total Samples: {sensor.get('total_samples')}")
        print(f"Features: {sensor.get('features')}")
        print(f"Contamination: {sensor.get('contamination_parameter')}")
        print(f"Baseline Normals: {sensor.get('baseline_detected_normals')}, Anomalies: {sensor.get('baseline_detected_anomalies')}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
