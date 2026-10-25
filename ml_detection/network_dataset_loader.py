"""Loader and pre-cleaner for the TON_IoT network intrusion dataset."""

from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any
import pandas as pd
import numpy as np

from config.settings import settings
from config.logging_config import logger


class NetworkDatasetLoader:
    """Loads, validates, and prepares TON_IoT network traffic data."""

    # Features that could cause target leakage or overfit on specific environment strings
    DROP_COLUMNS = [
        "src_ip", "dst_ip", "weird_notice", "weird_name", "weird_addl",
        "http_uri", "http_user_agent", "http_orig_mime_types", "http_resp_mime_types",
        "ssl_subject", "ssl_issuer",
    ]

    def __init__(self, dataset_path: Optional[Path] = None):
        self.dataset_path = Path(dataset_path or settings.NETWORK_DATASET_PATH)

    def load_data(
        self,
        target_column: str = "type",
        sample_size: Optional[int] = 30000,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.Series, Dict[str, Any]]:
        """
        Load dataset, clean, and return (X, y, metadata).
        
        Args:
            target_column: 'type' (multiclass) or 'label' (binary)
            sample_size: Optional sample size for faster training while maintaining stratification
            random_state: Random seed for reproducibility
        """
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Network dataset not found at {self.dataset_path}")

        logger.info("Loading network dataset from %s ...", self.dataset_path)
        df = pd.read_csv(self.dataset_path)

        if target_column not in df.columns:
            raise ValueError(f"Target column '{target_column}' not found in dataset. Columns: {list(df.columns)}")

        # Clean target: lower and strip strings
        if df[target_column].dtype == object or pd.api.types.is_string_dtype(df[target_column]):
            df[target_column] = df[target_column].astype(str).str.strip().str.lower()

        # Handle duplicates and inf
        df = df.replace([np.inf, -np.inf], np.nan)

        # Stratified sampling if sample_size is smaller than total rows
        total_rows = len(df)
        if sample_size and sample_size < total_rows:
            logger.info("Stratified sampling %d rows from %d total rows...", sample_size, total_rows)
            from sklearn.model_selection import train_test_split
            df, _ = train_test_split(
                df,
                train_size=sample_size,
                stratify=df[target_column],
                random_state=random_state,
            )

        y = df[target_column].copy()

        # Drop target columns and leakage columns
        cols_to_drop = [c for c in self.DROP_COLUMNS if c in df.columns]
        if "label" in df.columns:
            cols_to_drop.append("label")
        if "type" in df.columns:
            cols_to_drop.append("type")

        X = df.drop(columns=cols_to_drop, errors="ignore").copy()

        # Class distribution
        class_dist = {str(k): int(v) for k, v in y.value_counts().items()}

        metadata = {
            "source_file": self.dataset_path.name,
            "total_samples": len(df),
            "feature_count": X.shape[1],
            "feature_names": list(X.columns),
            "target_column": target_column,
            "classes": sorted(list(class_dist.keys())),
            "class_distribution": class_dist,
        }

        logger.info(
            "Network data loaded: %d rows, %d features, %d classes",
            len(df),
            X.shape[1],
            len(class_dist),
        )

        return X, y, metadata
