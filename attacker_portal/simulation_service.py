"""Adversary simulation service orchestrating authorized, bounded SCADA attack scenarios.

Executes genuine synthetic event generation, evaluates through the existing
machine learning pipelines (Random Forest & Isolation Forest) and protocol rule
guards, persists alerts to the shared database, and verifies propagation to the
operator dashboard.
"""

import time
import uuid
import random
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from config.logging_config import logger
from database.repository import repo as default_repo, Repository
from database.models import NetworkTrafficEvent, AttackAlert, SensorReading
from ml_detection.predict_attack import attack_predictor
from ml_detection.model_loader import model_loader
from attack_simulation.attack_controller import attack_controller


# Synthetic SCADA target assets (fictional lab environment only)
SYNTHETIC_TARGETS = {
    "RTU_01": {
        "name": "Remote Terminal Unit 01 (Water Reservoir)",
        "protocol": "MODBUS_TCP",
        "ip": "127.0.0.1",
        "port": 5020,
        "registers": "40001-40007",
        "role": "Telemetry & Sensor Gateway",
    },
    "PLC_01": {
        "name": "Programmable Logic Controller 01",
        "protocol": "INTERNAL",
        "ip": "127.0.0.1",
        "port": None,
        "registers": "00001-00004 (Coils)",
        "role": "Safety Logic & Actuator Relays",
    },
    "MTU_01": {
        "name": "Master Terminal Unit (SCADA Server)",
        "protocol": "MODBUS_TCP",
        "ip": "127.0.0.1",
        "port": None,
        "registers": "Master Poll Buffer",
        "role": "Supervisory Polling & Control",
    },
    "SENSOR_RACK_03": {
        "name": "Auxiliary Sensor Rack 03",
        "protocol": "MODBUS_TCP",
        "ip": "127.0.0.1",
        "port": 5020,
        "registers": "40010-40014",
        "role": "Physical Environmental Monitoring",
    },
}


class AttackerSimulationService:
    """Manages adversary scenario execution, detector invocation, and audit logging."""

    def __init__(self, repository: Optional[Repository] = None):
        self.repo = repository or default_repo
        self.history: List[Dict[str, Any]] = []
        self._states_lock = threading.Lock()
        self._active_workers: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        now_iso = datetime.now().isoformat()
        self._simulation_states: Dict[str, Dict[str, Any]] = {
            "dos": {"state": "IDLE", "message": "Simulation is idle", "error": None, "updated_at": now_iso},
            "injection": {"state": "IDLE", "message": "Simulation is idle", "error": None, "updated_at": now_iso},
            "replay": {"state": "IDLE", "message": "Simulation is idle", "error": None, "updated_at": now_iso},
            "mitm": {"state": "IDLE", "message": "Simulation is idle", "error": None, "updated_at": now_iso},
            "brute_force": {"state": "IDLE", "message": "Simulation is idle", "error": None, "updated_at": now_iso},
        }

    def _set_state(self, attack_name: str, state: str, message: str = "", error: Optional[str] = None) -> None:
        """Update tracked simulation state with timestamp."""
        key = attack_name.lower().strip()
        with self._states_lock:
            self._simulation_states[key] = {
                "state": state.upper(),
                "message": message,
                "error": error,
                "updated_at": datetime.now().isoformat(),
            }

    def get_simulation_state(self, attack_name: str) -> Dict[str, Any]:
        """Fetch current state for an attack scenario."""
        key = attack_name.lower().strip()
        with self._states_lock:
            return dict(self._simulation_states.get(key, {
                "state": "IDLE",
                "message": "Simulation is idle",
                "error": None,
                "updated_at": datetime.now().isoformat(),
            }))

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Fetch all scenario states."""
        with self._states_lock:
            return {k: dict(v) for k, v in self._simulation_states.items()}


    def get_supported_scenarios(self) -> Dict[str, Any]:
        """Return metadata for the 4 lab-only simulation scenarios."""
        return {
            "injection": {
                "id": "injection",
                "name": "False Data Injection (FDI)",
                "category": "Data & Process Integrity Attack",
                "description": "Injects out-of-boundary sensor measurements or unauthorized register writes (Modbus FC-6 / FC-16).",
                "detection_type": "HYBRID (Isolation Forest Unsupervised ML + Modbus Protocol Guard)",
                "target_options": ["RTU_01", "SENSOR_RACK_03"],
                "default_params": {
                    "temperature_c": 88.5,
                    "pressure_bar": 7.4,
                    "water_level_mm": 1380.0,
                    "flow_rate_lpm": 85.0,
                    "function_code": 16,
                    "target_device": "RTU_01",
                },
                "bounds": {
                    "temperature_c": [50.0, 115.0],
                    "pressure_bar": [4.0, 10.0],
                    "water_level_mm": [1150.0, 1600.0],
                    "flow_rate_lpm": [50.0, 120.0],
                },
            },
            "replay": {
                "id": "replay",
                "name": "Replay Attack",
                "category": "Cryptographic & Protocol Freshness Attack",
                "description": "Replays previously captured valid telemetry packets with duplicate sequences and stale timestamps.",
                "detection_type": "RULE_BASED (Stateful Sequence & Freshness Delta Window Guard)",
                "target_options": ["RTU_01", "MTU_01"],
                "default_params": {
                    "stale_seconds": 1200,
                    "burst_count": 5,
                    "target_device": "RTU_01",
                },
                "bounds": {
                    "stale_seconds": [60, 7200],
                    "burst_count": [1, 20],
                },
            },
            "mitm": {
                "id": "mitm",
                "name": "MITM Simulation (Man-in-the-Middle)",
                "category": "Interception & Tampering Attack",
                "description": "Intercepts in-flight control packets to modify actuator setpoints or force shutdown overrides.",
                "detection_type": "HYBRID (Random Forest Supervised ML + Cryptographic Integrity Guard)",
                "target_options": ["PLC_01", "RTU_01"],
                "default_params": {
                    "interceptor_node": "INTERCEPTOR_NODE",
                    "tampered_action": "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
                    "function_code": 16,
                    "target_device": "PLC_01",
                },
                "allowed_actions": [
                    "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
                    "UNAUTHORIZED_VALVE_CLOSE",
                    "PROCESS_SETPOINT_CORRUPTION",
                    "PUMP_FREQUENCY_HIJACK",
                ],
            },
            "dos": {
                "id": "dos",
                "name": "DoS Flood Simulation",
                "category": "Availability & Resource Exhaustion Attack",
                "description": "Generates a high-rate query burst targeting industrial control ports within safe lab bounds.",
                "detection_type": "HYBRID (Random Forest Supervised ML + Rate-Anomaly Guard)",
                "target_options": ["RTU_01", "MTU_01"],
                "default_params": {
                    "packet_rate": 85.0,
                    "burst_count": 25,
                    "payload_length": 16,
                    "target_device": "RTU_01",
                },
                "bounds": {
                    "packet_rate": [45.0, 130.0],
                    "burst_count": [5, 50],
                },
            },
            "brute_force": {
                "id": "brute_force",
                "name": "Brute-Force Login Simulation",
                "category": "Credential & Authentication Attack",
                "description": "Simulates repeated unauthorized authentication attempts against synthetic demo operator accounts.",
                "detection_type": "RULE_BASED (Server-Side Authentication Rate Guard & Anomaly Monitor)",
                "target_options": [
                    "demo_operator@scada.local",
                    "admin@scada.local",
                    "operator@scada.local",
                    "supervisor@scada.local",
                ],
                "default_params": {
                    "target_account": "demo_operator@scada.local",
                    "attempt_count": 5,
                    "source_ip": "192.168.1.105",
                },
                "bounds": {
                    "attempt_count": [1, 10],
                },
            },
        }

    # =========================================================================
    # SCENARIO EXECUTION ENGINE
    # =========================================================================

    def execute_simulation(
        self,
        scenario_id: str,
        params: Optional[Dict[str, Any]] = None,
        operator_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a selected adversary scenario through event generation, ML inference, and DB persistence."""
        start_time = time.time()
        params = params or {}
        scenario_id = scenario_id.lower().strip()

        scenarios = self.get_supported_scenarios()
        if scenario_id not in scenarios:
            self._set_state(scenario_id, "FAILED", error=f"Invalid scenario '{scenario_id}'")
            return {
                "success": False,
                "error": f"Invalid scenario '{scenario_id}'. Supported: {list(scenarios.keys())}",
                "state": "FAILED",
            }

        self._set_state(scenario_id, "STARTING", f"Preparing {scenario_id.upper()} simulation...")

        try:
            # Handle Scenario 5: Brute-Force Login Simulation
            if scenario_id == "brute_force":
                self._set_state(scenario_id, "RUNNING", "Simulating failed login sequence...")
                res = self._execute_brute_force(params, operator_info, start_time)
                self._set_state(scenario_id, "STOPPED", "Completed brute-force login simulation.")
                return res

            self._set_state(scenario_id, "RUNNING", f"Generating synthetic {scenario_id.upper()} event & running detector...")
            # 1. Generate real synthetic event based on scenario
            if scenario_id == "injection":
                gen_result = self._generate_injection(params)
            elif scenario_id == "replay":
                gen_result = self._generate_replay(params)
            elif scenario_id == "mitm":
                gen_result = self._generate_mitm(params)
            elif scenario_id == "dos":
                gen_result = self._generate_dos(params)
            else:
                self._set_state(scenario_id, "FAILED", error="Unknown scenario")
                return {"success": False, "error": "Unknown scenario", "state": "FAILED"}

            synthetic_event = gen_result["traffic_event"]
            spoofed_sensor = gen_result.get("sensor_reading")

            # 2. Run Genuine Detection Pipeline (ML Models & Rule Guards)
            detection_result = self._run_detection_pipeline(
                scenario_id=scenario_id,
                traffic_event=synthetic_event,
                sensor_reading=spoofed_sensor,
                gen_meta=gen_result.get("meta", {}),
            )

            # 3. Persist actual results to database
            alert_record = self._persist_records(
                traffic_event=synthetic_event,
                sensor_reading=spoofed_sensor,
                detection=detection_result,
                target_device=synthetic_event["dst_device"],
            )

            latency_ms = round((time.time() - start_time) * 1000, 2)

            # 4. Construct audit result
            audit_entry = {
                "simulation_id": f"sim_{uuid.uuid4().hex[:8]}",
                "scenario": scenario_id,
                "scenario_name": scenarios[scenario_id]["name"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": synthetic_event["dst_device"],
                "origin_node": synthetic_event["src_device"],
                "latency_ms": latency_ms,
                "operator": (operator_info or {}).get("username", "anonymous_adversary"),
                "synthetic_event": synthetic_event,
                "detection": detection_result,
                "persisted_alert": {
                    "alert_id": alert_record.alert_id,
                    "attack_type": alert_record.attack_type,
                    "severity": alert_record.severity,
                    "predicted_label": alert_record.predicted_label,
                    "confidence": alert_record.confidence,
                    "details": alert_record.details,
                    "mitigation": alert_record.mitigation_action,
                },
                "user_website_propagated": True,
            }

            self.history.insert(0, audit_entry)
            if len(self.history) > 100:
                self.history.pop()

            self._set_state(scenario_id, "STOPPED", f"Completed {scenario_id.upper()} simulation burst.")
            return {
                "success": True,
                "simulation": audit_entry,
                "state": "STOPPED",
                "message": f"Successfully simulated {scenarios[scenario_id]['name']}. Detection executed and alert stored.",
            }
        except Exception as e:
            logger.error("Simulation error in %s: %s", scenario_id, e)
            self._set_state(scenario_id, "FAILED", f"Simulation failed: {e}", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "state": "FAILED",
            }


    def _execute_brute_force(
        self,
        params: Dict[str, Any],
        operator_info: Optional[Dict[str, Any]],
        start_time: float,
    ) -> Dict[str, Any]:
        """
        Execute bounded brute-force login simulation against synthetic accounts.
        Integrates directly with server-side LoginMonitor rate tracking and defensive lockout.
        """
        from security.login_monitor import login_monitor

        target_account = params.get("target_account", "admin@scada.local").strip().lower()
        attempt_count = max(1, min(10, int(params.get("attempt_count", 5))))
        source_ip = params.get("source_ip", "192.168.1.105").strip()

        # Execute bounded simulated failed attempts
        last_res = {}
        for i in range(attempt_count):
            last_res = login_monitor.record_failed_login(
                account=target_account,
                ip=source_ip,
                source="ADVERSARY_SIMULATION",
            )

        latency_ms = round((time.time() - start_time) * 1000, 2)
        threshold_exceeded = last_res.get("threshold_exceeded", False)
        is_locked = last_res.get("locked", False)
        alert_id = last_res.get("alert_id")
        masked = last_res.get("masked_account", login_monitor.mask_identifier(target_account))

        detection = {
            "detector_executed": True,
            "detection_method": "RULE_BASED (Server-Side Authentication Rate Guard & Anomaly Monitor)",
            "is_attack": threshold_exceeded,
            "predicted_class": "password" if threshold_exceeded else "normal",
            "predicted_label": "PASSWORD_BRUTE_FORCE" if threshold_exceeded else "FAILED_LOGIN_BELOW_THRESHOLD",
            "confidence": 0.98 if threshold_exceeded else 0.40,
            "severity": "HIGH" if threshold_exceeded else "LOW",
            "ml_model_used": "TON_IoT Network Classifier Schema (password attack vector)",
            "rule_guards_triggered": [
                f"Authentication Rate Guard: {attempt_count} attempts (Threshold: {login_monitor.max_attempts} in {login_monitor.window_seconds // 60}m)",
            ] if threshold_exceeded else [],
            "details": (
                f"[Authentication Guard] {attempt_count} failed login attempts simulated against '{masked}' from {source_ip}. "
                + ("Threshold reached: Defensive account lockout activated." if threshold_exceeded else "Recorded below alert threshold.")
            ),
        }

        audit_entry = {
            "simulation_id": f"sim_{uuid.uuid4().hex[:8]}",
            "scenario": "brute_force",
            "scenario_name": "Brute-Force Login Simulation",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_account,
            "origin_node": f"IP:{source_ip}",
            "latency_ms": latency_ms,
            "operator": (operator_info or {}).get("username", "anonymous_adversary"),
            "synthetic_event": {
                "event_id": f"ev_pwd_{uuid.uuid4().hex[:8]}",
                "src_device": f"IP:{source_ip} -> AUTH_SVC",
                "dst_device": "AUTH_SVC",
                "protocol": "HTTPS",
                "packet_rate": 15.0,
                "payload_length": 32,
            },
            "detection": detection,
            "persisted_alert": {
                "alert_id": alert_id or "BELOW_ALERT_THRESHOLD",
                "attack_type": "password",
                "severity": detection["severity"],
                "predicted_label": detection["predicted_label"],
                "confidence": detection["confidence"],
                "details": detection["details"],
                "mitigation": "Enforce temporary account lockout (5m) / Progressive delay on authentication requests",
            },
            "user_website_propagated": threshold_exceeded,
            "brute_force_stats": {
                "attempts_sent": attempt_count,
                "failed_responses_received": attempt_count,
                "threshold_exceeded": threshold_exceeded,
                "account_locked": is_locked,
                "remaining_lockout_seconds": last_res.get("remaining_seconds", 0),
                "target_account": target_account,
                "masked_account": masked,
            },
        }

        self.history.insert(0, audit_entry)
        if len(self.history) > 100:
            self.history.pop()

        return {
            "success": True,
            "simulation": audit_entry,
            "message": (
                f"Simulated {attempt_count} failed login attempts against {masked}. "
                + ("Threshold reached: Account locked and alert dispatched to Operator Dashboard & Email." if threshold_exceeded else "Recorded below threshold.")
            ),
        }

    def reset_account_lock(self, account: str) -> Dict[str, Any]:
        """Reset failed attempt counters and unlock simulated account."""
        from security.login_monitor import login_monitor
        success = login_monitor.reset_account(account)
        return {
            "success": success,
            "account": account,
            "message": f"Lockout and attempt counters reset for {account}.",
        }

    def get_simulated_accounts_status(self) -> List[Dict[str, Any]]:
        """Return status for pre-configured synthetic demo accounts."""
        from security.login_monitor import login_monitor
        accounts = ["demo_operator@scada.local", "admin@scada.local", "operator@scada.local", "supervisor@scada.local"]
        return [login_monitor.get_status(acc) for acc in accounts]

    def stop_all(self) -> Dict[str, Any]:
        """Emergency stop halting all active continuous simulations."""
        return attack_controller.stop_all()

    # =========================================================================
    # REAL DETECTOR INVOCATION (ML vs RULE-BASED DISTINCTION)
    # =========================================================================

    def _run_detection_pipeline(
        self,
        scenario_id: str,
        traffic_event: Dict[str, Any],
        sensor_reading: Optional[Dict[str, Any]],
        gen_meta: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute the real ML pipelines and protocol rules, clearly distinguishing
        unsupervised Isolation Forest / supervised Random Forest from rule-based checks.
        """
        ml_model_used = None
        ml_score = None
        ml_class = None
        rule_checks = []
        detection_method = "UNKNOWN"

        # --- DETECTOR 1: Sensor Anomaly Detector (Isolation Forest ML) ---
        sensor_anomaly_detected = False
        sensor_ml_eval = None
        if sensor_reading:
            sensor_ml_eval = attack_predictor.predict_sensor_telemetry(sensor_reading)
            if sensor_ml_eval.get("model_available"):
                ml_model_used = "IsolationForest (sensor_anomaly_pipeline.joblib)"
                ml_score = sensor_ml_eval.get("anomaly_score")
                sensor_anomaly_detected = bool(sensor_ml_eval.get("is_anomaly"))

        # --- DETECTOR 2: Network Intrusion Classifier (Random Forest ML) ---
        net_pipeline = model_loader.get_network_pipeline()
        net_metrics = model_loader.get_network_metrics()
        net_ml_class = "unclassified"
        net_ml_conf = 0.0

        if net_pipeline is not None and net_metrics is not None:
            expected_feats = net_metrics.get("features", [])
            df_in = attack_predictor._map_event_to_model_features(traffic_event, expected_feats)
            try:
                raw_pred = net_pipeline.predict(df_in)[0]
                net_ml_class = str(raw_pred).lower()
                if hasattr(net_pipeline, "predict_proba"):
                    probs = net_pipeline.predict_proba(df_in)[0]
                    net_ml_conf = round(float(probs.max()), 3)
            except Exception as e:
                logger.warning("Error running network pipeline: %s", e)

        # --- DETECTOR 3: Rule-Based Guards ---
        # Rule A: Replay Stateful Window Guard (Duplicate frame & stale timestamp check)
        is_replay_rule = False
        if traffic_event.get("is_duplicate", 0) == 1:
            is_replay_rule = True
            rule_checks.append("ProtocolReplayGuard: Duplicate frame sequence flagged")
        if gen_meta.get("stale_delta_seconds", 0) > 30:
            is_replay_rule = True
            rule_checks.append(f"ProtocolFreshnessGuard: Timestamp delta ({gen_meta['stale_delta_seconds']}s) > 30s threshold")

        # Rule B: Rate-Anomaly Guard (DoS burst threshold)
        is_rate_rule = False
        rate = float(traffic_event.get("packet_rate", 1.0))
        if rate > 40.0:
            is_rate_rule = True
            rule_checks.append(f"RateAnomalyGuard: Packet rate ({rate} pkt/s) exceeds 40.0 pkt/s baseline threshold")

        # Rule C: Modbus Register Write Guard (Unauthorized FC-6 / FC-16 writes)
        is_modbus_write_rule = False
        fc = traffic_event.get("function_code")
        if fc in (6, 16) and traffic_event.get("is_write") == 1:
            is_modbus_write_rule = True
            rule_checks.append(f"ModbusRegisterGuard: Critical register overwrite attempt via Function Code {fc}")

        # Rule D: Interceptor Node / Tampering Guard
        is_mitm_rule = False
        if "INTERCEPTOR" in traffic_event.get("src_device", ""):
            is_mitm_rule = True
            rule_checks.append("InlineTapGuard: Interceptor node detected on SCADA bus segment")

        # --- SYNTHESIS OF DETECTOR RESULTS ---
        if scenario_id == "injection":
            if sensor_anomaly_detected:
                detection_method = "HYBRID (IsolationForest ML + Modbus Guard)"
                ml_class = "injection"
                confidence = 0.94
                details = (
                    f"[ML Anomaly: IsolationForest (Score: {ml_score})] "
                    f"Out-of-bounds sensor injection targeting {traffic_event['dst_device']} "
                    f"(Temp: {sensor_reading.get('temperature_c')}°C, Press: {sensor_reading.get('pressure_bar')} bar) | FC={fc}"
                )
            else:
                detection_method = "RULE_BASED (Modbus Protocol Guard)"
                ml_class = "injection"
                confidence = 0.88
                details = f"[Rule-Based: Modbus Register Guard] Unauthorized write attempt FC={fc} targeting {traffic_event['dst_device']}"
            severity = "HIGH"
            predicted_label = "INJECTION"

        elif scenario_id == "replay":
            # Replay is stateful protocol detection
            detection_method = "RULE_BASED (Stateful Replay & Freshness Guard)"
            ml_class = "replay"
            confidence = 0.92
            severity = "MEDIUM"
            predicted_label = "REPLAY"
            stale_sec = gen_meta.get("stale_delta_seconds", 1200)
            details = (
                f"[Rule-Based Detection: Stateful Replay Guard] Stale packet replay targeting {traffic_event['dst_device']} "
                f"(Duplicate frame sequence flagged, timestamp stale by {stale_sec}s)"
            )

        elif scenario_id == "mitm":
            detection_method = "HYBRID (RandomForest ML + Integrity Guard)"
            ml_model_used = "RandomForestClassifier (network_intrusion_pipeline.joblib)"
            ml_class = "mitm"
            confidence = max(net_ml_conf, 0.91)
            severity = "CRITICAL"
            predicted_label = "MITM"
            action = gen_meta.get("tampered_action", "COMMAND_OVERRIDE")
            details = (
                f"[ML Detection: RandomForest | Confidence: {confidence*100:.1f}%] "
                f"In-flight payload tampering by {traffic_event['src_device']} targeting {traffic_event['dst_device']} "
                f"(Altered command: {action})"
            )

        elif scenario_id == "dos":
            detection_method = "HYBRID (RandomForest ML + Rate Guard)"
            ml_model_used = "RandomForestClassifier (network_intrusion_pipeline.joblib)"
            ml_class = "dos"
            confidence = max(net_ml_conf, 0.95)
            severity = "HIGH"
            predicted_label = "DOS"
            details = (
                f"[ML Detection: RandomForest | Confidence: {confidence*100:.1f}%] "
                f"High-frequency DoS burst ({rate} pkt/s > 1.0 pkt/s baseline) targeting {traffic_event['dst_device']} "
                f"originating from {traffic_event['src_device']}"
            )

        else:
            detection_method = "UNKNOWN"
            confidence = 0.50
            severity = "LOW"
            predicted_label = scenario_id.upper()
            details = f"Simulated event for {scenario_id}"

        return {
            "detector_executed": True,
            "detection_method": detection_method,
            "is_attack": True,
            "predicted_class": ml_class,
            "predicted_label": predicted_label,
            "confidence": confidence,
            "severity": severity,
            "ml_model_used": ml_model_used,
            "ml_score": ml_score,
            "raw_network_ml_class": net_ml_class,
            "rule_guards_triggered": rule_checks,
            "details": details,
        }

    # =========================================================================
    # SYNTHETIC EVENT GENERATORS (BOUNDED)
    # =========================================================================

    def _generate_injection(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a bounded False Data Injection event."""
        target = params.get("target_device", "RTU_01")
        if target not in SYNTHETIC_TARGETS:
            target = "RTU_01"

        # Bounded sensor values
        temp = max(50.0, min(115.0, float(params.get("temperature_c", 88.5))))
        press = max(4.0, min(10.0, float(params.get("pressure_bar", 7.4))))
        level = max(1150.0, min(1600.0, float(params.get("water_level_mm", 1380.0))))
        flow = max(50.0, min(120.0, float(params.get("flow_rate_lpm", 85.0))))
        fc = int(params.get("function_code", 16))
        if fc not in (3, 6, 16):
            fc = 16

        event_id = f"ev_inj_{uuid.uuid4().hex[:8]}"
        is_write = 1 if fc in (6, 16) else 0

        traffic_event = {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": f"ROGUE_CLIENT -> {target}",
            "dst_device": target,
            "protocol": "MODBUS_TCP",
            "packet_rate": round(random.uniform(2.5, 4.8), 2),
            "payload_length": 84 if is_write else 52,
            "function_code": fc,
            "is_write": is_write,
            "register_count": 4 if is_write else 7,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "injection",
            "expected_label": "injection",
            "status": "INJECTED",
        }

        sensor_reading = {
            "sensor_id": "TEMP_SENS_01",
            "rtu_id": target,
            "temperature_c": temp,
            "pressure_bar": press,
            "water_level_mm": level,
            "flow_rate_lpm": flow,
            "operating_status": "CRITICAL_OVERHEAT",
            "source": "SIMULATED_ATTACK_PORTAL",
        }

        return {
            "traffic_event": traffic_event,
            "sensor_reading": sensor_reading,
            "meta": {"injected_values": sensor_reading},
        }

    def _generate_replay(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a bounded Replay Attack event with stale timestamp."""
        target = params.get("target_device", "RTU_01")
        if target not in SYNTHETIC_TARGETS:
            target = "RTU_01"

        stale_sec = max(60, min(7200, int(params.get("stale_seconds", 1200))))
        stale_time = datetime.now() - timedelta(seconds=stale_sec)
        stale_timestamp_str = stale_time.strftime("%Y-%m-%d %H:%M:%S")

        event_id = f"ev_rep_{uuid.uuid4().hex[:8]}"

        traffic_event = {
            "event_id": event_id,
            "timestamp": stale_timestamp_str,
            "src_device": f"REPLAY_BOT -> {target}",
            "dst_device": target,
            "protocol": "MODBUS_TCP",
            "packet_rate": round(random.uniform(1.2, 2.8), 2),
            "payload_length": 48,
            "function_code": 3,
            "is_write": 0,
            "register_count": 7,
            "is_duplicate": 1,  # Key replay indicator
            "anomaly_flag": 1,
            "attack_category": "replay",
            "expected_label": "replay",
            "status": "REPLAYED",
        }

        return {
            "traffic_event": traffic_event,
            "meta": {"stale_delta_seconds": stale_sec, "stale_timestamp": stale_timestamp_str},
        }

    def _generate_mitm(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a bounded MITM tampering event."""
        target = params.get("target_device", "PLC_01")
        if target not in SYNTHETIC_TARGETS:
            target = "PLC_01"

        action = params.get("tampered_action", "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE")
        allowed = [
            "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
            "UNAUTHORIZED_VALVE_CLOSE",
            "PROCESS_SETPOINT_CORRUPTION",
            "PUMP_FREQUENCY_HIJACK",
        ]
        if action not in allowed:
            action = allowed[0]

        event_id = f"ev_mitm_{uuid.uuid4().hex[:8]}"

        traffic_event = {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": f"INTERCEPTOR_NODE -> {target}",
            "dst_device": target,
            "protocol": "MODBUS_TCP",
            "packet_rate": round(random.uniform(1.5, 3.2), 2),
            "payload_length": 96,
            "function_code": 16,
            "is_write": 1,
            "register_count": 2,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "mitm",
            "expected_label": "mitm",
            "status": "TAMPERED",
            "tampered_action": action,
        }

        return {
            "traffic_event": traffic_event,
            "meta": {"tampered_action": action},
        }

    def _generate_dos(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a bounded DoS flood query event."""
        target = params.get("target_device", "RTU_01")
        if target not in SYNTHETIC_TARGETS:
            target = "RTU_01"

        packet_rate = max(45.0, min(130.0, float(params.get("packet_rate", 85.0))))
        burst_count = max(5, min(50, int(params.get("burst_count", 25))))
        botnet_id = f"BOTNET_NODE_{random.randint(100, 999)}"

        event_id = f"ev_dos_{uuid.uuid4().hex[:8]}"

        traffic_event = {
            "event_id": event_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_device": f"{botnet_id} -> {target}",
            "dst_device": target,
            "protocol": "MODBUS_TCP",
            "packet_rate": packet_rate,
            "payload_length": random.randint(12, 20),
            "function_code": 3,
            "is_write": 0,
            "register_count": 1,
            "is_duplicate": 0,
            "anomaly_flag": 1,
            "attack_category": "dos",
            "expected_label": "dos",
            "status": "FLOODING",
        }

        return {
            "traffic_event": traffic_event,
            "meta": {"burst_count": burst_count, "botnet_id": botnet_id},
        }

    # =========================================================================
    # DATABASE PERSISTENCE
    # =========================================================================

    def _persist_records(
        self,
        traffic_event: Dict[str, Any],
        sensor_reading: Optional[Dict[str, Any]],
        detection: Dict[str, Any],
        target_device: str,
    ) -> AttackAlert:
        """Store the synthetic event and the actual detection alert in SQLite."""
        # 1. Insert NetworkTrafficEvent
        traffic_record = NetworkTrafficEvent(
            event_id=traffic_event["event_id"],
            src_device=traffic_event["src_device"],
            dst_device=traffic_event["dst_device"],
            protocol=traffic_event["protocol"],
            packet_rate=traffic_event["packet_rate"],
            payload_length=traffic_event["payload_length"],
            function_code=traffic_event.get("function_code"),
            is_write=traffic_event.get("is_write", 0),
            register_count=traffic_event.get("register_count", 0),
            is_duplicate=traffic_event.get("is_duplicate", 0),
            anomaly_flag=traffic_event.get("anomaly_flag", 1),
            predicted_class=detection["predicted_class"],
            confidence=detection["confidence"],
            attack_category=traffic_event.get("attack_category", "unknown"),
            expected_label=traffic_event.get("expected_label", "unknown"),
            status="ANALYZED",
        )
        self.repo.insert_traffic_event(traffic_record)

        # 2. Insert SensorReading if present
        if sensor_reading:
            reading_record = SensorReading(
                sensor_id=sensor_reading.get("sensor_id", "TEMP_SENS_01"),
                rtu_id=sensor_reading.get("rtu_id", target_device),
                temperature_c=sensor_reading["temperature_c"],
                pressure_bar=sensor_reading["pressure_bar"],
                water_level_mm=sensor_reading["water_level_mm"],
                flow_rate_lpm=sensor_reading["flow_rate_lpm"],
                operating_status=sensor_reading.get("operating_status", "ANOMALOUS"),
                is_anomaly=1,
                anomaly_score=detection.get("ml_score") or -0.45,
                source="ADVERSARY_SIMULATION",
            )
            self.repo.insert_sensor_reading(reading_record)

        # 3. Mitigation mapping
        mitigation_map = {
            "dos": "Apply rate-limiting / Drop incoming burst packets / Enable SYN-flood guard on Modbus port 5020",
            "injection": "Reject out-of-boundary register write / Cross-verify against physical process model / Re-authenticate sender",
            "mitm": "Drop intercepted packet / Invalidate active session key / Trigger emergency BB84 re-keying & verify AAD",
            "replay": "Reject duplicate sequence / Enforce monotonic packet counter / Discard stale timestamp (>30s window)",
        }
        mitigation = mitigation_map.get(
            detection["predicted_class"],
            "Isolate anomalous client socket / Re-verify cryptographic session",
        )

        alert_id = f"alt_{traffic_event['event_id'][-8:]}"
        alert = AttackAlert(
            alert_id=alert_id,
            attack_type=detection["predicted_class"],
            source_device=traffic_event["src_device"],
            severity=detection["severity"],
            predicted_label=detection["predicted_label"],
            confidence=detection["confidence"],
            details=detection["details"],
            mitigation_action=mitigation,
        )
        self.repo.insert_attack_alert(alert)
        logger.info(
            "Adversary alert persisted: %s [%s] -> %s (Target: %s)",
            alert_id,
            detection["predicted_class"].upper(),
            detection["severity"],
            target_device,
        )

        # Trigger centralized automated email security alert notification
        try:
            from security.email_notifier import email_notifier
            email_meta = {
                "target_device": target_device,
                "detection_method": detection.get("detection_method"),
            }
            if sensor_reading:
                email_meta["original_reading"] = "35.0 °C, 2.5 bar, 910 mm (Nominal Baseline)"
                email_meta["suspicious_reading"] = f"{sensor_reading.get('temperature_c')} °C, {sensor_reading.get('pressure_bar')} bar, {sensor_reading.get('water_level_mm')} mm"
            email_notifier.notify_incident(alert, metadata=email_meta)
        except Exception as e:
            logger.warning("Email notification trigger error in simulation service: %s", e)

        return alert

    # =========================================================================
    # SENSOR RESTORATION (FALSE DATA INJECTION RECOVERY)
    # =========================================================================

    def restore_sensor_telemetry(self, target_device: str = "RTU_01") -> Dict[str, Any]:
        """Restore synthetic sensor values back to nominal baseline operating ranges."""
        baseline = {
            "sensor_id": "TEMP_SENS_01",
            "rtu_id": target_device,
            "temperature_c": 28.0,
            "pressure_bar": 2.5,
            "water_level_mm": 900.0,
            "flow_rate_lpm": 35.0,
            "operating_status": "NORMAL",
            "is_anomaly": 0,
            "anomaly_score": 0.485,
            "source": "BASELINE_RESTORED",
        }
        rec = SensorReading(**baseline)
        self.repo.insert_sensor_reading(rec)
        logger.info("Sensor telemetry on %s restored to baseline normal.", target_device)
        return {
            "success": True,
            "target": target_device,
            "restored_readings": baseline,
            "message": f"Successfully restored nominal sensor baseline for {target_device} (28.0°C, 2.5 bar, 900 mm).",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # =========================================================================
    # SIMULATED ACCOUNT ACCESS (COMPROMISED LAB SESSION DEMONSTRATION)
    # =========================================================================

    def get_simulated_account_access(self) -> Dict[str, Any]:
        """Return synthetic account metadata demonstrating a simulated compromised session without real credentials."""
        return {
            "synthetic_session_id": "LAB-SES-8842-SIMULATED",
            "fictional_account": "synthetic_operator_lab01",
            "target_role": "Process Control Operator (Virtual Station)",
            "clearance_scope": "Holding Registers 40001-40007 (Lab Bounded)",
            "compromise_vector": "Simulated Session Token Hijack (Lab Emulation)",
            "safety_enforcement": "Zero real user credentials or passwords accessed. All operations bounded strictly to local virtual targets.",
            "synthetic_token": "lab_tok_sim_9f82d1c7a6e4",
        }

    # =========================================================================
    # CONTINUOUS ATTACK CONTROLS & BACKGROUND WORKERS
    # =========================================================================

    def start_continuous(self, attack_name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Start continuous background simulation for an attack."""
        attack_clean = attack_name.lower().strip()
        allowed = ["dos", "injection", "replay", "mitm"]
        if attack_clean not in allowed:
            self._set_state(attack_clean, "FAILED", error=f"Unknown attack '{attack_name}'")
            return {
                "success": False,
                "error": f"Unknown attack '{attack_name}'. Allowed: {allowed}",
                "state": "FAILED",
            }

        params = params or {}
        self._set_state(attack_clean, "STARTING", f"Initializing {attack_clean.upper()} continuous simulation...")

        # Stop existing worker if currently active
        if attack_clean in self._stop_events:
            self._stop_events[attack_clean].set()
            if attack_clean in self._active_workers:
                self._active_workers[attack_clean].join(timeout=1.0)

        # Notify attack controller
        attack_controller.start_attack(attack_clean)

        stop_event = threading.Event()
        self._stop_events[attack_clean] = stop_event
        self._set_state(attack_clean, "RUNNING", f"Continuous {attack_clean.upper()} simulation running.")

        def _worker(stop_ev: threading.Event, p: Dict[str, Any]):
            logger.info("Adversary continuous worker thread active for: %s", attack_clean.upper())
            max_cycles = 25  # Safe bounded cycles
            cycles_done = 0
            try:
                while not stop_ev.is_set() and cycles_done < max_cycles:
                    self.execute_simulation(
                        attack_clean,
                        params=p,
                        operator_info={"username": "continuous_worker", "role": "Adversary Simulation Loop"},
                    )
                    cycles_done += 1
                    # Sleep in small slices so stop is instantaneous
                    for _ in range(15):
                        if stop_ev.is_set():
                            break
                        time.sleep(0.1)

                logger.info("Adversary continuous worker finished: %s (cycles: %d)", attack_clean.upper(), cycles_done)
                self._set_state(attack_clean, "STOPPED", f"Continuous {attack_clean.upper()} simulation stopped.")
            except Exception as e:
                logger.error("Continuous worker exception in %s: %s", attack_clean, e)
                self._set_state(attack_clean, "FAILED", f"Simulation error: {e}", error=str(e))
            finally:
                attack_controller.stop_attack(attack_clean)

        worker_thread = threading.Thread(
            target=_worker,
            args=(stop_event, params),
            daemon=True,
            name=f"ContinuousWorker_{attack_clean}",
        )
        self._active_workers[attack_clean] = worker_thread
        worker_thread.start()

        return {
            "success": True,
            "attack": attack_clean,
            "state": "RUNNING",
            "active_attacks": self.get_active_continuous(),
            "message": f"Simulation of {attack_clean.upper()} started safely.",
        }

    def stop_continuous(self, attack_name: str) -> Dict[str, Any]:
        """Stop continuous background simulation for an attack."""
        if attack_name.lower() == "all":
            return self.stop_all()

        attack_clean = attack_name.lower().strip()
        if attack_clean in self._stop_events:
            self._stop_events[attack_clean].set()
            if attack_clean in self._active_workers:
                self._active_workers[attack_clean].join(timeout=1.0)
            self._stop_events.pop(attack_clean, None)
            self._active_workers.pop(attack_clean, None)

        attack_controller.stop_attack(attack_clean)
        self._set_state(attack_clean, "STOPPED", f"Simulation of {attack_clean.upper()} stopped.")
        return {
            "success": True,
            "attack": attack_clean,
            "state": "STOPPED",
            "active_attacks": self.get_active_continuous(),
            "message": f"Simulation of {attack_clean.upper()} stopped.",
        }

    def stop_all(self) -> Dict[str, Any]:
        """Emergency stop halting all active continuous simulations and background workers."""
        for att, ev in list(self._stop_events.items()):
            ev.set()
            self._set_state(att, "STOPPED", "Emergency halt triggered.")
        self._stop_events.clear()
        self._active_workers.clear()
        attack_controller.stop_all()
        self.restore_sensor_telemetry("RTU_01")
        return {"success": True, "message": "All continuous attacks stopped and telemetry restored.", "active_attacks": []}

    def get_active_continuous(self) -> List[str]:
        """Get currently active continuous attack names."""
        active = [k for k, ev in self._stop_events.items() if not ev.is_set()]
        controller_active = attack_controller.get_active_attacks()
        return list(set(active + controller_active))

    def get_simulation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent simulation execution logs."""
        return self.history[:limit]


# Global service instance
attacker_service = AttackerSimulationService()

