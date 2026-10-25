"""SCADA Intrusion Detection & Quantum-Secure Communication System entry point."""

import sys
import time
import threading
import signal
from pathlib import Path
from typing import Optional

from config.settings import settings
from config.logging_config import logger, setup_logging
from database.db import db
from database.repository import repo
from database.models import NetworkTrafficEvent

from simulation.industrial_process import IndustrialProcess
from simulation.plc_simulator import PLCSimulator
from simulation.rtu_simulator import RTUSimulator
from simulation.mtu_simulator import MTUSimulator
from protocols.protocol_adapter import ProtocolAdapter
from security.key_manager import key_manager
from attack_simulation.attack_controller import attack_controller
from ml_detection.predict_attack import attack_predictor
from ml_detection.model_loader import model_loader
from dashboard.app import create_app


class SCADASystemRunner:
    """Orchestrates industrial simulation, protocol networking, ML detection, and Flask dashboard."""

    def __init__(self):
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None

        # Core subsystems
        self.process = IndustrialProcess(seed=settings.RANDOM_SEED)
        self.plc = PLCSimulator(self.process.actuators)
        self.rtu = RTUSimulator()
        self.mtu = MTUSimulator()
        self.protocol_adapter = ProtocolAdapter()

    def initialize_subsystems(self) -> None:
        """Initialize database, check models, and establish baseline BB84 quantum session."""
        logger.info("Initializing SCADA Security & Quantum System...")

        # 1. Database
        db.init_db()

        # 2. Check ML models
        model_status = model_loader.get_models_status()
        if not model_status["all_models_ready"]:
            logger.warning("One or more ML models missing. Run 'python -m ml_detection.network_train' or 'sensor_train'")
        else:
            logger.info("ML Models verified: Network Intrusion (RandomForest) & Sensor Anomaly (IsolationForest) ready.")

        # 3. Establish initial BB84 Quantum Session (Alice=MTU, Bob=RTU)
        logger.info("Establishing baseline BB84 Quantum Key Distribution session...")
        q_result = key_manager.initiate_bb84_exchange(
            raw_bits=settings.BB84_RAW_BITS,
            noise_level=0.0,
            eavesdropper=False,
            seed=settings.RANDOM_SEED,
        )
        logger.info("Baseline Quantum Session status: %s (QBER=%.2f%%)", q_result["session_status"], q_result.get("latest_bb84", {}).get("qber_percentage", 0.0))

        # 4. Attempt starting network protocols (Modbus TCP & MQTT)
        proto_status = self.protocol_adapter.start_services()
        logger.info("Modbus TCP status: %s | MQTT Broker status: %s", proto_status["modbus_tcp"], proto_status["mqtt"])
        if not proto_status["mqtt"]:
            logger.info("Note: MQTT Broker (Mosquitto) is not currently connected on %s:%d. System will operate in Modbus/in-memory mode.", settings.MQTT_HOST, settings.MQTT_PORT)

    def _simulation_loop(self) -> None:
        """Background worker generating continuous physical telemetry and ML monitoring."""
        logger.info("Background industrial telemetry loop started (Interval: %.1fs)", settings.SIMULATION_INTERVAL)
        while self.running:
            try:
                # 1. Advance physical process
                step_data = self.process.step()
                sensors = step_data["sensor_readings"]
                actuators = step_data["actuators"]

                # 2. Execute PLC ladder logic
                self.plc.execute_logic(sensors)

                # 3. Evaluate Sensor Anomaly Detection (Unsupervised Isolation Forest)
                sensor_eval = attack_predictor.predict_sensor_telemetry(sensors)
                sensors["is_anomaly"] = sensor_eval["is_anomaly"]
                sensors["anomaly_score"] = sensor_eval["anomaly_score"]

                # 4. RTU updates registers & MTU records telemetry
                self.rtu.update_from_telemetry(sensors, actuators)
                self.mtu.process_telemetry(sensors, source="LIVE_SIMULATION")

                # 5. Protocol telemetry transmission
                self.protocol_adapter.transfer_telemetry(sensors, actuators)

                # 6. Generate next network observation (normal or active attack)
                net_event = attack_controller.produce_next_event()

                # 7. Evaluate Network Intrusion Classification (Random Forest)
                pred_result = attack_predictor.predict_network_event(net_event)

                # 8. Record traffic event to SQLite
                traffic_record = NetworkTrafficEvent(
                    event_id=net_event["event_id"],
                    src_device=net_event["src_device"],
                    dst_device=net_event["dst_device"],
                    protocol=net_event["protocol"],
                    packet_rate=net_event["packet_rate"],
                    payload_length=net_event["payload_length"],
                    function_code=net_event.get("function_code"),
                    is_write=net_event.get("is_write", 0),
                    register_count=net_event.get("register_count", 0),
                    is_duplicate=net_event.get("is_duplicate", 0),
                    anomaly_flag=net_event.get("anomaly_flag", 0),
                    predicted_class=pred_result["predicted_class"],
                    confidence=pred_result["confidence"],
                    attack_category=net_event.get("attack_category", "normal"),
                    expected_label=net_event.get("expected_label", "normal"),
                    status="ANALYZED",
                )
                repo.insert_traffic_event(traffic_record)

            except Exception as e:
                logger.error("Error in simulation loop: %s", e)

            time.sleep(settings.SIMULATION_INTERVAL)

    def start_background_simulation(self) -> None:
        """Start simulation worker thread."""
        if self.running:
            return
        self.running = True
        self.worker_thread = threading.Thread(
            target=self._simulation_loop,
            daemon=True,
            name="SimulationWorkerThread",
        )
        self.worker_thread.start()

    def shutdown(self) -> None:
        """Gracefully terminate background workers and network protocols."""
        logger.info("Shutting down SCADA Security System...")
        self.running = False
        attack_controller.stop_all()
        self.protocol_adapter.stop_services()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=2.0)
        logger.info("SCADA Security System cleanly stopped.")


def main():
    """Main application CLI launcher."""
    print("=" * 75)
    print("  SCADA INTRUSION DETECTION & QUANTUM-SECURE COMMUNICATION SYSTEM")
    print("=" * 75)

    runner = SCADASystemRunner()
    runner.initialize_subsystems()
    runner.start_background_simulation()

    app = create_app()

    def signal_handler(sig, frame):
        print("\nShutdown signal received. Stopping servers...")
        runner.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("\n[+] Dashboard URL: http://{}:{}".format(settings.FLASK_HOST, settings.FLASK_PORT))
    print("[+] Press Ctrl+C to stop the application.\n" + "=" * 75 + "\n")

    try:
        app.run(
            host=settings.FLASK_HOST,
            port=settings.FLASK_PORT,
            debug=False,
            use_reloader=False,
        )
    finally:
        runner.shutdown()


if __name__ == "__main__":
    main()
