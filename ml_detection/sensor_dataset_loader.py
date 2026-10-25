"""Loader and validator for the SCADA sensor readings dataset."""

from pathlib import Path
from typing import Tuple, Optional, Dict, Any, List
import pandas as pd
import numpy as np

from config.settings import settings
from config.logging_config import logger


class SensorDatasetLoader:
    """Loads and validates historical sensor telemetry data."""

    NUMERIC_SENSOR_COLS = [
        "temperature_c",
        "pressure_bar",
        "water_level_mm",
        "flow_rate_lpm",
    ]

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = Path(dataset_path or settings.SENSOR_DATASET_PATH)

    def load_data(self) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
        """
        Load sensor dataset and extract numeric telemetry features.
        
        Returns:
            (full_df, X_features, metadata)
        """
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Sensor dataset not found at {self.dataset_path}")

        df = pd.read_csv(self.dataset_path)

        # Verify required columns exist
        missing_cols = [c for c in self.NUMERIC_SENSOR_COLS if c not in df.columns]
        if missing_cols:
            raise ValueError(f"Sensor dataset missing required telemetry columns: {missing_cols}")

        # Check for missing values and fill with median if any
        if df[self.NUMERIC_SENSOR_COLS].isnull().any().any():
            logger.warning("Missing values detected in sensor dataset; imputing with column medians.")
            df[self.NUMERIC_SENSOR_COLS] = df[self.NUMERIC_SENSOR_COLS].fillna(
                df[self.NUMERIC_SENSOR_COLS].median()
            )

        X_numeric = df[self.NUMERIC_SENSOR_COLS].copy()

        # Compute summary stats
        stats = {}
        for col in self.NUMERIC_SENSOR_COLS:
            stats[col] = {
                "min": float(X_numeric[col].min()),
                "mean": float(X_numeric[col].mean()),
                "max": float(X_numeric[col].max()),
                "std": float(X_numeric[col].std()),
            }

        status_counts = (
            df["operating_status"].value_counts().to_dict()
            if "operating_status" in df.columns
            else {"NORMAL": len(df)}
        )

        metadata = {
            "source_file": self.dataset_path.name,
            "total_records": len(df),
            "features": self.NUMERIC_SENSOR_COLS,
            "operating_status_counts": {str(k): int(v) for k, v in status_counts.items()},
            "statistics": stats,
            "has_timestamps": "timestamp" in df.columns,
            "has_labeled_anomalies": False,  # All 200 records are NORMAL baseline
        }

        return df, X_numeric, metadata
