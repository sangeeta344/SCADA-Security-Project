"""Dataset inspector for SCADA network intrusion and sensor telemetry datasets."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd
import numpy as np

from config.settings import settings
from config.logging_config import logger


class DatasetInspector:
    """Discovers and inspects dataset properties, schemas, and label distributions."""

    def __init__(
        self,
        network_path: Optional[Path] = None,
        sensor_path: Optional[Path] = None,
    ):
        self.network_path = Path(network_path or settings.NETWORK_DATASET_PATH)
        self.sensor_path = Path(sensor_path or settings.SENSOR_DATASET_PATH)

    def inspect_file(self, file_path: Path, max_sample_rows: Optional[int] = None) -> Dict[str, Any]:
        """Inspect a single CSV dataset without assumptions."""
        if not file_path.exists():
            return {
                "exists": False,
                "file_path": str(file_path),
                "error": f"File not found at {file_path}",
            }

        try:
            # For network dataset which may be large (~211k rows), load full or sampled
            df = pd.read_csv(file_path, nrows=max_sample_rows)
            num_rows, num_cols = df.shape

            # Column data types
            dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}

            # Missing values
            missing = df.isnull().sum().to_dict()
            total_missing = int(df.isnull().sum().sum())

            # Duplicates
            duplicate_count = int(df.duplicated().sum())

            # Numeric vs categorical
            # Use select_dtypes without string alias warnings
            numeric_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
            categorical_cols = [c for c in df.columns if not pd.api.types.is_numeric_dtype(df[c])]

            # Candidate label / target identification
            candidate_targets = {}
            for col in ["label", "type", "attack", "operating_status", "status", "class", "target"]:
                if col in df.columns:
                    val_counts = df[col].value_counts(dropna=False).head(20).to_dict()
                    # Convert any numpy integers to python int for JSON serialization
                    clean_counts = {str(k): int(v) for k, v in val_counts.items()}
                    candidate_targets[col] = {
                        "unique_count": int(df[col].nunique(dropna=False)),
                        "distribution": clean_counts,
                    }

            # Check timestamp and device ID indicators
            has_timestamp = any("time" in c.lower() or "date" in c.lower() for c in df.columns)
            has_device_id = any(
                term in c.lower()
                for c in df.columns
                for term in ["sensor", "rtu", "plc", "dev", "ip", "host"]
            )

            # Numerical statistics for numeric columns (min, mean, max, std)
            summary_stats = {}
            for col in numeric_cols[:10]:  # Limit to first 10 for compact report
                summary_stats[col] = {
                    "min": float(df[col].min()) if not df[col].empty else None,
                    "mean": float(df[col].mean()) if not df[col].empty else None,
                    "max": float(df[col].max()) if not df[col].empty else None,
                }

            return {
                "exists": True,
                "file_path": str(file_path),
                "file_name": file_path.name,
                "file_size_mb": round(file_path.stat().st_size / (1024 * 1024), 2),
                "rows": int(num_rows),
                "columns": int(num_cols),
                "column_names": list(df.columns),
                "data_types": dtypes,
                "numeric_columns": numeric_cols,
                "categorical_columns": categorical_cols,
                "missing_values": missing,
                "total_missing_values": total_missing,
                "duplicate_rows": duplicate_count,
                "candidate_targets": candidate_targets,
                "has_timestamp": has_timestamp,
                "has_device_id": has_device_id,
                "numerical_summary": summary_stats,
            }
        except Exception as e:
            logger.error("Error inspecting %s: %s", file_path, e, exc_info=True)
            return {
                "exists": True,
                "file_path": str(file_path),
                "error": str(e),
            }

    def inspect_all(self, output_report: bool = True) -> Dict[str, Any]:
        """Inspect both datasets and compile full report."""
        report = {
            "network_dataset": self.inspect_file(self.network_path),
            "sensor_dataset": self.inspect_file(self.sensor_path),
        }

        if output_report:
            out_path = settings.BASE_DIR / "data" / "processed" / "dataset_inspection_report.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info("Inspection report saved to %s", out_path)

        return report


def main():
    """CLI runner for dataset inspection."""
    inspector = DatasetInspector()
    print("=" * 70)
    print("SCADA PROJECT: DATASET INSPECTION")
    print("=" * 70)

    report = inspector.inspect_all()

    for ds_name, info in report.items():
        print(f"\n--- {ds_name.upper()} ---")
        if not info.get("exists"):
            print(f"Error: {info.get('error')}")
            continue
        print(f"File: {info['file_name']} ({info['file_size_mb']} MB)")
        print(f"Path: {info['file_path']}")
        print(f"Shape: {info['rows']} rows x {info['columns']} columns")
        print(f"Duplicates: {info['duplicate_rows']}, Missing values: {info['total_missing_values']}")
        print(f"Numeric features ({len(info['numeric_columns'])}): {info['numeric_columns'][:6]}...")
        print(f"Categorical features ({len(info['categorical_columns'])}): {info['categorical_columns'][:6]}...")
        print("Candidate targets found:")
        for tgt, tgt_info in info.get("candidate_targets", {}).items():
            print(f"  * {tgt} (Unique: {tgt_info['unique_count']}) -> {tgt_info['distribution']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
