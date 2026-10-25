import unittest
from pathlib import Path
import joblib
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent

class TestSCADASystem(unittest.TestCase):

    def test_01_required_imports(self):
        """Verify all critical libraries can be imported."""
        import pymodbus
        import sklearn
        import shap
        import streamlit
        import matplotlib
        self.assertIsNotNone(pymodbus.__version__)
        self.assertIsNotNone(sklearn.__version__)

    def test_02_dataset_schema(self):
        """Verify TON_IoT dataset exists, has 44 columns, and valid labels."""
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
        self.assertTrue(dataset_path.exists(), f"Dataset not found at {dataset_path}")
        
        # Read header and first 5 rows to verify schema quickly
        sample_df = pd.read_csv(dataset_path, nrows=5)
        self.assertEqual(sample_df.shape[1], 44)
        self.assertIn("label", sample_df.columns)
        self.assertIn("type", sample_df.columns)
        self.assertIn("src_ip", sample_df.columns)
        self.assertIn("dst_ip", sample_df.columns)

    def test_03_sensor_dataset_schema(self):
        """Verify simulated sensor dataset exists and has expected columns."""
        sensor_csv = BASE_DIR / "datasets" / "scada_sensor_dataset_200_rows.csv"
        self.assertTrue(sensor_csv.exists(), f"Sensor dataset not found at {sensor_csv}")
        df_sensor = pd.read_csv(sensor_csv, nrows=5)
        expected_cols = [
            "timestamp", "sensor_id", "rtu_id", "temperature_c",
            "pressure_bar", "water_level_mm", "flow_rate_lpm", "operating_status"
        ]
        self.assertListEqual(df_sensor.columns.tolist(), expected_cols)

    def test_04_model_loading_and_features(self):
        """Verify saved model loads and exposes exactly the 40 expected features."""
        model_path = BASE_DIR / "scada_attack_model.joblib"
        self.assertTrue(model_path.exists(), f"Model file not found at {model_path}")
        
        model = joblib.load(model_path)
        self.assertTrue(hasattr(model, "feature_names_in_"))
        self.assertEqual(len(model.feature_names_in_), 40)
        
        expected_features = [
            "src_port", "dst_port", "proto", "service", "duration", "src_bytes",
            "dst_bytes", "conn_state", "missed_bytes", "src_pkts", "src_ip_bytes",
            "dst_pkts", "dst_ip_bytes", "dns_query", "dns_qclass", "dns_qtype",
            "dns_rcode", "dns_AA", "dns_RD", "dns_RA", "dns_rejected",
            "ssl_version", "ssl_cipher", "ssl_resumed", "ssl_established",
            "ssl_subject", "ssl_issuer", "http_trans_depth", "http_method",
            "http_uri", "http_version", "http_request_body_len",
            "http_response_body_len", "http_status_code", "http_user_agent",
            "http_orig_mime_types", "http_resp_mime_types", "weird_name",
            "weird_addl", "weird_notice"
        ]
        self.assertListEqual(list(model.feature_names_in_), expected_features)

    def test_05_single_and_batch_prediction(self):
        """Verify inference works on single rows and batches with valid outputs."""
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
        
        df_sample = pd.read_csv(dataset_path, nrows=5)
        X_sample = df_sample.drop(columns=["label", "type", "src_ip", "dst_ip"])
        
        # Single-row prediction
        row = X_sample.iloc[[0]]
        single_pred = model.predict(row)
        self.assertIn(single_pred[0], [0, 1])
        
        # Batch prediction
        batch_pred = model.predict(X_sample)
        self.assertEqual(len(batch_pred), 5)
        for p in batch_pred:
            self.assertIn(p, [0, 1])

    def test_06_model_missing_value_and_unseen_category_handling(self):
        """Verify preprocessor handles NaNs and unseen categorical tokens safely."""
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
        
        row = pd.read_csv(dataset_path, nrows=1).drop(columns=["label", "type", "src_ip", "dst_ip"]).copy()
        
        # Inject NaNs in numeric and categorical fields
        row.loc[0, "duration"] = np.nan
        row.loc[0, "src_bytes"] = np.nan
        row.loc[0, "proto"] = "unseen_test_protocol_xyz"
        row.loc[0, "service"] = None
        
        # Prediction should succeed thanks to median and most_frequent SimpleImputer + ignore OneHotEncoder
        pred = model.predict(row)
        self.assertIn(pred[0], [0, 1])

    def test_07_scada_monitor_offline_behavior(self):
        """Verify scada_monitor.read_sensor_data returns connected=False when RTU offline."""
        import asyncio
        from scada_monitor import read_sensor_data
        
        # When RTU is offline, should return dict with connected: False and error message
        result = asyncio.run(read_sensor_data())
        self.assertIsInstance(result, dict)
        self.assertIn("connected", result)
        if not result["connected"]:
            self.assertIn("error", result)

    def test_08_train_model_path_resolution(self):
        """Verify train_model.py defines robust Path objects for dataset and model."""
        import train_model
        self.assertTrue(train_model.DATA_PATH.is_absolute())
        self.assertTrue(train_model.MODEL_SAVE_PATH.is_absolute())
        self.assertTrue(train_model.DATA_PATH.exists())

    def test_09_traffic_distribution_calculation(self):
        """Verify traffic distribution aggregation works correctly on dataset."""
        from dashboard import get_traffic_distribution
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
        df_sample = pd.read_csv(dataset_path, nrows=100)
        counts, attack_counts = get_traffic_distribution(df_sample)
        self.assertIn("Normal", counts.index)
        self.assertIn("Attack", counts.index)
        self.assertEqual(counts.sum(), 100)

    def test_10_shap_pipeline_integrity(self):
        """Verify SHAP TreeExplainer calculation produces valid feature-importance shape."""
        import shap
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"
        
        sample = pd.read_csv(dataset_path, nrows=5).drop(columns=["label", "type", "src_ip", "dst_ip"])
        preprocessor = model.named_steps["preprocessor"]
        classifier = model.named_steps["classifier"]
        
        transformed = preprocessor.transform(sample)
        if hasattr(transformed, "toarray"):
            transformed = transformed.toarray()
            
        feature_names = preprocessor.get_feature_names_out()
        self.assertEqual(transformed.shape[1], len(feature_names))
        
        explainer = shap.TreeExplainer(classifier)
        shap_values = explainer.shap_values(transformed)
        
        # Verify shape
        if isinstance(shap_values, list):
            attack_vals = shap_values[1]
        elif getattr(shap_values, "ndim", 0) == 3:
            attack_vals = shap_values[:, :, 1]
        else:
            attack_vals = shap_values
            
        self.assertEqual(attack_vals.shape[0], 5)
        self.assertEqual(attack_vals.shape[1], len(feature_names))
        self.assertFalse(np.isnan(attack_vals).any())

    def test_11_feature_extractor_compliance(self):
        """Verify feature extractor output matches exact 40 features expected by model."""
        from feature_extractor import build_feature_vector, validate_feature_dataframe
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)

        dummy_conn = {
            "src_ip": "127.0.0.1", "src_port": 50000,
            "dst_ip": "127.0.0.1", "dst_port": 5020,
            "proto": "tcp", "service": "modbus",
            "duration": 0.005, "src_bytes": 12, "dst_bytes": 17,
            "conn_state": "SF", "src_pkts": 1, "dst_pkts": 1
        }

        df_feat, metadata = build_feature_vector(dummy_conn)
        self.assertTrue(validate_feature_dataframe(df_feat))
        self.assertEqual(list(df_feat.columns), list(model.feature_names_in_))
        self.assertTrue(metadata["is_out_of_domain"])
        
        # Verify model can predict without error
        pred = model.predict(df_feat)
        self.assertIn(pred[0], [0, 1])

    def test_12_live_network_monitor_lifecycle(self):
        """Verify live network monitor records observations, limits memory, and starts/stops cleanly."""
        from live_network_monitor import LiveNetworkMonitor
        monitor = LiveNetworkMonitor(max_records=5)
        
        # Test ring buffer limit
        for i in range(10):
            monitor.log_connection(
                src_ip="127.0.0.1", src_port=50000 + i,
                dst_ip="127.0.0.1", dst_port=5020,
                duration=0.001 * i
            )
        
        obs = monitor.get_recent_observations()
        self.assertEqual(len(obs), 5)  # Enforces max_records=5
        
        # Test background collector lifecycle
        self.assertFalse(monitor.is_running())
        monitor.start_background_collector(target_host="127.0.0.1", target_port=5020, interval=0.1)
        self.assertTrue(monitor.is_running())
        monitor.stop_background_collector()
        self.assertFalse(monitor.is_running())

    def test_13_edge_case_robustness_and_malformed_inputs(self):
        """Verify feature_extractor handles malformed types, empty inputs, and unknown protocols."""
        from feature_extractor import build_feature_vector, _safe_int, _safe_float
        
        # Test safe parsers
        self.assertEqual(_safe_int("invalid_str", default=99), 99)
        self.assertEqual(_safe_int(None, default=10), 10)
        self.assertEqual(_safe_float("invalid_float", default=0.5), 0.5)

        # Test malformed input dict
        malformed = {
            "src_port": "not_a_port",
            "dst_port": None,
            "duration": "NaN",
            "proto": "alien_protocol_xyz",
            "service": None
        }
        df_feat, meta = build_feature_vector(malformed)
        self.assertEqual(df_feat.shape, (1, 40))
        self.assertFalse(meta["is_compatible"])

    def test_14_domain_compatibility_blocking(self):
        """Verify live_network_monitor blocks out-of-domain Modbus predictions by default."""
        from live_network_monitor import LiveNetworkMonitor
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)
        monitor = LiveNetworkMonitor(max_records=5)

        # Default: allow_experimental_prediction = False -> prediction blocked
        rec_blocked = monitor.log_connection(
            src_ip="127.0.0.1", src_port=52000,
            dst_ip="127.0.0.1", dst_port=5020,
            proto="tcp", service="modbus",
            model=model, allow_experimental_prediction=False
        )
        self.assertTrue(rec_blocked["prediction_blocked"])
        self.assertIsNone(rec_blocked["prediction"])
        self.assertEqual(rec_blocked["prediction_label"], "Blocked (Incompatible Domain)")

        # Explicit: allow_experimental_prediction = True -> runs prediction
        rec_allowed = monitor.log_connection(
            src_ip="127.0.0.1", src_port=52001,
            dst_ip="127.0.0.1", dst_port=5020,
            proto="tcp", service="modbus",
            model=model, allow_experimental_prediction=True
        )
        self.assertFalse(rec_allowed["prediction_blocked"])
        self.assertIn(rec_allowed["prediction"], [0, 1])

    def test_15_evaluation_metrics_integrity(self):
        """Verify model evaluation calculation (accuracy, precision, recall, F1, confusion matrix)."""
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        model_path = BASE_DIR / "scada_attack_model.joblib"
        model = joblib.load(model_path)
        dataset_path = BASE_DIR / "datasets" / "TON_IoT" / "train_test_network.csv"

        df_eval = pd.read_csv(dataset_path, nrows=200)
        X_eval = df_eval.drop(columns=["label", "type", "src_ip", "dst_ip"])
        y_eval = df_eval["label"].astype(int)

        preds = model.predict(X_eval)
        acc = accuracy_score(y_eval, preds)
        prec = precision_score(y_eval, preds, zero_division=0)
        rec = recall_score(y_eval, preds, zero_division=0)
        f1 = f1_score(y_eval, preds, zero_division=0)
        cm = confusion_matrix(y_eval, preds, labels=[0, 1])

        self.assertGreaterEqual(acc, 0.0)
        self.assertLessEqual(acc, 1.0)
        self.assertEqual(cm.shape, (2, 2))
        self.assertEqual(cm.sum(), 200)

if __name__ == "__main__":
    unittest.main()
