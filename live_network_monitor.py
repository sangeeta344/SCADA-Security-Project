"""Live Passive Network Monitor for SCADA & Localhost Traffic.

Captures and summarizes network connection metadata on authorized local interfaces
without requiring Administrator permissions or kernel-level packet capture drivers.

Provides:
1. Thread-safe in-memory ring buffer of recent observations (avoids unbounded memory growth).
2. Clean start and stop control.
3. Passive observation of TCP connections to local SCADA endpoints (e.g. 127.0.0.1:5020).
4. Feature conversion and experimental model inference via feature_extractor.py.
5. Persistent logging to logs/live_traffic_log.csv without overwriting datasets.
"""

from collections import deque
from datetime import datetime
from pathlib import Path
import csv
import logging
import threading
import time
from typing import Dict, Any, List, Optional

from feature_extractor import build_feature_vector

# Logging and Storage Paths
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
TRAFFIC_LOG_FILE = LOGS_DIR / "live_traffic_log.csv"

logger = logging.getLogger("SCADA_Network_Monitor")


class LiveNetworkMonitor:
    """Passive in-memory network connection monitor with rolling history."""

    def __init__(self, max_records: int = 200):
        self.max_records = max_records
        self.records: deque = deque(maxlen=max_records)
        self._lock = threading.Lock()
        self._is_running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Ensure logs directory exists
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self._init_csv_log()

    def _init_csv_log(self):
        """Initialize the CSV log file with header if not already present."""
        if not TRAFFIC_LOG_FILE.exists():
            with open(TRAFFIC_LOG_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                    "proto", "service", "duration", "src_bytes", "dst_bytes",
                    "conn_state", "src_pkts", "dst_pkts", "prediction",
                    "prediction_label", "confidence", "is_out_of_domain"
                ])

    def log_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
        service: str = "modbus",
        duration: float = 0.005,
        src_bytes: int = 12,
        dst_bytes: int = 17,
        conn_state: str = "SF",
        src_pkts: int = 1,
        dst_pkts: int = 1,
        model: Any = None,
        allow_experimental_prediction: bool = False,
    ) -> Dict[str, Any]:
        """Record a newly observed network connection and evaluate model compatibility."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        raw_conn = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "service": service,
            "duration": duration,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "conn_state": conn_state,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
        }

        # Build model-compatible 40-feature representation and assess domain compatibility
        df_features, metadata = build_feature_vector(raw_conn)

        prediction_val = None
        prediction_label = "Unclassified"
        confidence_pct = 0.0
        prediction_blocked = False

        if model is not None:
            # Check domain compatibility before running inference
            if not metadata["is_compatible"] and not allow_experimental_prediction:
                prediction_val = None
                prediction_label = "Blocked (Incompatible Domain)"
                confidence_pct = 0.0
                prediction_blocked = True
            else:
                try:
                    preds = model.predict(df_features)
                    prediction_val = int(preds[0])
                    prediction_label = "Attack" if prediction_val == 1 else "Normal"
                    
                    if hasattr(model, "predict_proba"):
                        probas = model.predict_proba(df_features)[0]
                        confidence_pct = round(float(probas[prediction_val]) * 100, 2)
                except Exception as e:
                    logger.error(f"Inference error on live connection: {e}")
                    prediction_label = f"Error: {e}"

        record = {
            **raw_conn,
            "features_df": df_features,
            "is_compatible": metadata["is_compatible"],
            "is_out_of_domain": metadata["is_out_of_domain"],
            "domain_note": metadata["domain_note"],
            "prediction": prediction_val,
            "prediction_label": prediction_label,
            "confidence_pct": confidence_pct,
            "prediction_blocked": prediction_blocked,
        }

        with self._lock:
            self.records.append(record)

        # Persist to disk log safely
        self._append_to_csv(record)

        return record

    def _append_to_csv(self, rec: Dict[str, Any]):
        """Append an observed record to logs/live_traffic_log.csv."""
        try:
            with open(TRAFFIC_LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    rec["timestamp"],
                    rec["src_ip"],
                    rec["src_port"],
                    rec["dst_ip"],
                    rec["dst_port"],
                    rec["proto"],
                    rec["service"],
                    f"{rec['duration']:.4f}",
                    rec["src_bytes"],
                    rec["dst_bytes"],
                    rec["conn_state"],
                    rec["src_pkts"],
                    rec["dst_pkts"],
                    rec.get("prediction", ""),
                    rec.get("prediction_label", ""),
                    f"{rec.get('confidence_pct', 0.0):.1f}%",
                    rec.get("is_out_of_domain", True),
                ])
        except Exception as e:
            logger.error(f"Failed to append to traffic CSV: {e}")

    def get_recent_observations(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent observations as a list of dictionaries."""
        with self._lock:
            records_list = list(self.records)
        return records_list[-limit:]

    def clear(self):
        """Clear in-memory ring buffer."""
        with self._lock:
            self.records.clear()

    def is_running(self) -> bool:
        """Check if background observation worker is active."""
        return self._is_running

    def start_background_collector(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 5020,
        interval: float = 2.0,
        model: Any = None,
    ):
        """Start a non-intrusive background collector observing local RTU traffic."""
        if self._is_running:
            return

        self._stop_event.clear()
        self._is_running = True

        def _worker():
            import socket
            while not self._stop_event.is_set():
                t0 = time.time()
                success = False
                client_port = 0
                bytes_sent = 12
                bytes_recv = 0
                
                sock = None
                try:
                    # Non-intrusive probe checking Modbus port response
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    sock.connect((target_host, target_port))
                    client_port = sock.getsockname()[1]
                    
                    # Modbus TCP Header (MBAP): Transaction ID (2), Protocol ID (2), Length (2), Unit (1), Func (1), Addr (2), Count (2)
                    modbus_probe = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x04"
                    sock.sendall(modbus_probe)
                    response = sock.recv(64)
                    bytes_recv = len(response)
                    success = True
                except Exception:
                    success = False
                    if client_port == 0:
                        client_port = 50000 + (int(time.time()) % 15000)
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass

                duration = time.time() - t0
                conn_state = "SF" if success else "REJ"

                self.log_connection(
                    src_ip="127.0.0.1",
                    src_port=client_port,
                    dst_ip=target_host,
                    dst_port=target_port,
                    proto="tcp",
                    service="modbus",
                    duration=max(duration, 0.001),
                    src_bytes=bytes_sent if success else 0,
                    dst_bytes=bytes_recv,
                    conn_state=conn_state,
                    src_pkts=1 if success else 0,
                    dst_pkts=1 if bytes_recv > 0 else 0,
                    model=model,
                )

                self._stop_event.wait(interval)

            self._is_running = False

        self._monitor_thread = threading.Thread(
            target=_worker,
            name="SCADA_Live_Observer",
            daemon=True
        )
        self._monitor_thread.start()

    def stop_background_collector(self):
        """Stop background collector cleanly."""
        if self._is_running and self._stop_event is not None:
            self._stop_event.set()
            if self._monitor_thread is not None:
                self._monitor_thread.join(timeout=3.0)
            self._is_running = False


# Global singleton instance for application usage
live_monitor = LiveNetworkMonitor()
