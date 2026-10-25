"""Model training pipeline for network intrusion detection using TON_IoT dataset."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support

from config.settings import settings
from config.logging_config import logger
from ml_detection.network_dataset_loader import NetworkDatasetLoader
from database.repository import Repository, repo as default_repo
from database.models import ModelEvaluation


class NetworkModelTrainer:
    """Trains, benchmarks, and persists network intrusion classification pipeline."""

    def __init__(self, repository: Optional[Repository] = None):
        self.repo = repository or default_repo
        self.loader = NetworkDatasetLoader()

    def train(
        self,
        sample_size: int = 40000,
        test_size: float = 0.2,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """Train Random Forest network intrusion detection pipeline."""
        X, y, dataset_meta = self.loader.load_data(
            target_column="type",
            sample_size=sample_size,
            random_state=random_state,
        )

        # Identify numeric vs categorical feature columns
        numeric_features = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
        categorical_features = [c for c in X.columns if not pd.api.types.is_numeric_dtype(X[c])]

        logger.info(
            "Feature decomposition: %d numeric, %d categorical",
            len(numeric_features),
            len(categorical_features),
        )

        # Preprocessing Transformers
        numeric_transformer = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )

        categorical_transformer = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
                ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
            ]
        )

        preprocessor = ColumnTransformer(
            transformers=[
                ("num", numeric_transformer, numeric_features),
                ("cat", categorical_transformer, categorical_features),
            ]
        )

        # Baseline Classifier: Random Forest
        rf_classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            random_state=random_state,
            n_jobs=-1,
        )

        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", rf_classifier),
            ]
        )

        # Stratified train/test split to avoid leakage
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=random_state,
            stratify=y,
        )

        logger.info("Fitting pipeline on %d training samples...", len(X_train))
        pipeline.fit(X_train, y_train)

        # Evaluation on test set
        logger.info("Evaluating pipeline on %d held-out test samples...", len(X_test))
        y_pred = pipeline.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
        report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        classes = sorted(list(np.unique(y)))
        cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

        metrics = {
            "model_name": "network_intrusion_classifier",
            "model_type": "RandomForestClassifier",
            "dataset_name": dataset_meta["source_file"],
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "total_samples": len(X),
            "features": list(X.columns),
            "numeric_features": numeric_features,
            "categorical_features": categorical_features,
            "classes": classes,
            "accuracy": round(acc, 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm,
            "classification_report": report_dict,
        }

        # Save artifacts under models/
        settings.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, settings.NETWORK_MODEL_PATH)
        with open(settings.NETWORK_METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

        logger.info(
            "Saved network model to %s and metrics to %s",
            settings.NETWORK_MODEL_PATH,
            settings.NETWORK_METRICS_PATH,
        )

        # Save to database
        try:
            eval_record = ModelEvaluation(
                model_name="network_intrusion_classifier",
                model_type="RandomForest",
                dataset_name=dataset_meta["source_file"],
                train_samples=len(X_train),
                test_samples=len(X_test),
                accuracy=acc,
                precision=float(prec),
                recall=float(rec),
                f1_score=float(f1),
                metrics_json=json.dumps(metrics),
            )
            self.repo.insert_model_evaluation(eval_record)
        except Exception as e:
            logger.warning("Could not persist model evaluation to db: %s", e)

        return metrics


def main():
    trainer = NetworkModelTrainer()
    print("=" * 65)
    print("TRAINING NETWORK INTRUSION DETECTION MODEL (TON_IoT)")
    print("=" * 65)
    metrics = trainer.train(sample_size=35000, n_estimators=60)
    print(f"Model: {metrics['model_name']} ({metrics['model_type']})")
    print(f"Dataset: {metrics['dataset_name']} ({metrics['train_samples']} train, {metrics['test_samples']} test)")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1-Score:  {metrics['f1_score']:.4f}")
    print(f"Classes ({len(metrics['classes'])}): {metrics['classes']}")
    print("=" * 65)


if __name__ == "__main__":
    main()
