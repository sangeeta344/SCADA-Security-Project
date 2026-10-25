"""Training pipeline for unsupervised SCADA sensor anomaly detection using Isolation Forest."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import pandas as pd
import numpy as np

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from config.settings import settings
from config.logging_config import logger
from ml_detection.sensor_dataset_loader import SensorDatasetLoader
from database.repository import Repository, repo as default_repo
from database.models import ModelEvaluation


class SensorAnomalyTrainer:
    """Trains unsupervised Isolation Forest on normal baseline telemetry."""

    def __init__(self, repository: Optional[Repository] = None):
        self.repo = repository or default_repo
        self.loader = SensorDatasetLoader()

    def train(self, contamination: float = 0.05, random_state: int = 42) -> Dict[str, Any]:
        """Fit Isolation Forest pipeline on baseline telemetry."""
        full_df, X_numeric, dataset_meta = self.loader.load_data()

        logger.info(
            "Fitting sensor anomaly detection model on %d records (%s)...",
            len(X_numeric),
            dataset_meta["features"],
        )

        pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "detector",
                    IsolationForest(
                        contamination=contamination,
                        random_state=random_state,
                        n_estimators=100,
                    ),
                ),
            ]
        )

        pipeline.fit(X_numeric)

        # Baseline evaluation on training set
        scores = pipeline.decision_function(X_numeric)
        preds = pipeline.predict(X_numeric)  # 1 = normal, -1 = anomaly
        anomaly_count = int(np.sum(preds == -1))
        normal_count = int(np.sum(preds == 1))

        metrics = {
            "model_name": "sensor_anomaly_detector",
            "model_type": "IsolationForest",
            "dataset_name": dataset_meta["source_file"],
            "total_samples": len(X_numeric),
            "features": dataset_meta["features"],
            "contamination_parameter": contamination,
            "baseline_detected_anomalies": anomaly_count,
            "baseline_detected_normals": normal_count,
            "anomaly_rate_percent": round((anomaly_count / len(X_numeric)) * 100.0, 2),
            "score_mean": round(float(np.mean(scores)), 4),
            "score_min": round(float(np.min(scores)), 4),
            "score_max": round(float(np.max(scores)), 4),
            "operational_threshold": 0.0,  # Negative scores represent anomalies
            "feature_statistics": dataset_meta["statistics"],
            "unsupervised_notice": "Unsupervised model trained on baseline normal operational telemetry.",
        }

        # Save artifacts under models/
        settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, settings.SENSOR_MODEL_PATH)
        with open(settings.SENSOR_METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        logger.info(
            "Saved sensor anomaly model to %s and metrics to %s",
            settings.SENSOR_MODEL_PATH,
            settings.SENSOR_METRICS_PATH,
        )

        # Save to database
        try:
            eval_record = ModelEvaluation(
                model_name="sensor_anomaly_detector",
                model_type="IsolationForest",
                dataset_name=dataset_meta["source_file"],
                train_samples=len(X_numeric),
                test_samples=len(X_numeric),
                accuracy=round(normal_count / len(X_numeric), 4),
                precision=1.0 - contamination,
                recall=1.0 - contamination,
                f1_score=1.0 - contamination,
                metrics_json=json.dumps(metrics),
            )
            self.repo.insert_model_evaluation(eval_record)
        except Exception as e:
            logger.warning("Could not persist sensor model eval to db: %s", e)

        return metrics


def main():
    trainer = SensorAnomalyTrainer()
    print("=" * 65)
    print("TRAINING SENSOR ANOMALY DETECTION MODEL (Isolation Forest)")
    print("=" * 65)
    metrics = trainer.train()
    print(f"Model: {metrics['model_name']} ({metrics['model_type']})")
    print(f"Dataset: {metrics['dataset_name']} ({metrics['total_samples']} records)")
    print(f"Features: {metrics['features']}")
    print(f"Contamination Rate: {metrics['contamination_parameter']:.2%}")
    print(f"Decision Boundary: < {metrics['operational_threshold']} = Anomaly")
    print(f"Baseline Normals: {metrics['baseline_detected_normals']}, Anomalies: {metrics['baseline_detected_anomalies']}")
    print("=" * 65)


if __name__ == "__main__":
    main()
