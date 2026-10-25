# Quantum-Enhanced SCADA Intrusion Detection and Secure Communication 

A comprehensive cybersecurity and quantum communication laboratory prototype designed for critical infrastructure SCADA systems.

---

## 1. Project Overview

Industrial Control Systems (ICS) and Supervisory Control and Data Acquisition (SCADA) networks monitor and automate physical industrial operations including power generation, water purification plants, manufacturing pipelines, and oil refineries. Modern industrial digitization has interconnected previously isolated operational technology (OT) networks with corporate IT networks and the Internet, exposing critical infrastructure to sophisticated cyber threats.

This project delivers a working, end-to-end cybersecurity prototype that integrates:
1. **Machine Learning-Based Intrusion Detection**: A dual-pipeline ML system consisting of:
   - A **Random Forest Classifier** trained on 211,043 network records from the **TON_IoT** industrial network dataset, categorizing 10 classes (`normal`, `dos`, `injection`, `mitm`, `backdoor`, `ddos`, `password`, `ransomware`, `scanning`, `xss`).
   - An unsupervised **Isolation Forest Anomaly Detector** trained on baseline normal operational telemetry from `scada_sensor_dataset_200_rows.csv` to detect physical variable tampering.
2. **BB84 Quantum Key Distribution (QKD) Simulation**: An educational simulation of the BB84 single-photon polarization protocol between the Master Terminal Unit (MTU, Alice) and Remote Terminal Unit (RTU, Bob). Features random basis matching (+ / x), key sifting, configurable environmental noise modeling, and an eavesdropper (Eve) intercept-resend attack simulator. Calculates the Quantum Bit Error Rate (QBER) and enforces an 11% error threshold cutoff.
3. **Authenticated AES-256-GCM Session Encryption**: Derives 256-bit symmetric session keys from successfully verified BB84 key material via HKDF-SHA256, protecting Modbus and MQTT telemetry with unique 96-bit nonces, Authenticated Associated Data (AAD), and tamper-evident authentication tags.
4. **Industrial Protocols (Modbus TCP & MQTT)**: Real local Modbus TCP server/client running on port 5020 with documented register maps, plus Paho MQTT telemetry publishing on port 1883 with clear disconnected-broker fallback.
5. **Interactive Web Dashboard**: A Flask-based industrial monitoring console styled in a dark navy theme featuring 5 dedicated pages, live Chart.js graphs, attack simulation controls, and dataset analysis.

---

## 2. Problem Statement

Legacy SCADA protocols like standard Modbus TCP transmit sensor readings and control commands in plaintext without authentication or encryption, making them susceptible to eavesdropping, packet replay, unauthorized register writing (false data injection), and denial of service.

Standard cryptographic protocols (such as RSA or ECC) are vulnerable to future quantum computing decryption attacks (Shor's algorithm). Quantum Key Distribution (QKD) provides information-theoretic security guarantees under quantum mechanics. By integrating ML-based traffic anomaly detection with BB84 session key establishment and authenticated AES-GCM encryption, SCADA networks can detect network-level attacks while ensuring confidentiality and message integrity.

---

## 3. System Architecture

```text
+-----------------------------------------------------------------------------------+
|                            PHYSICAL PROCESS SIMULATION                            |
|        [Industrial Process: Tank Water Level, Temperature, Pressure, Flow Rate]   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                      REMOTE TERMINAL UNIT (RTU) & PLC LOGIC                       |
|   * RTUSimulator: Encodes physical telemetry to Modbus Holding Registers (0..6)   |
|   * PLCSimulator: Automated safety ladder logic (Overflow & Dry-Run Cutoffs)      |
+-----------------------------------------+-----------------------------------------+
                                          |
                +-------------------------+-------------------------+
                | Modbus TCP (Port 5020)                            | MQTT (Port 1883)
                v                                                   v
+--------------------------------+                 +--------------------------------+
|     MODBUS TCP COMM LAYER      |                 |       MQTT TELEMETRY LAYER     |
|   * ModbusServer (PyModbus)    |                 |   * MQTTPublisher (Paho)       |
|   * ModbusClient (Polling MTU) |                 |   * MQTTSubscriber (Validated) |
+---------------+----------------+                 +---------------+----------------+
                |                                                   |
                +-------------------------+-------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        CENTRAL SCADA SERVER / MTU SUPERVISOR                      |
|                                                                                   |
|  +------------------------------+             +--------------------------------+  |
|  |     ML INTRUSION DETECTOR    |             |       BB84 QKD SIMULATION      |  |
|  |  * Random Forest (TON_IoT)   |             |  * Alice (MTU) <-> Bob (RTU)   |  |
|  |  * Isolation Forest (Sensors)|             |  * Bases (+ / x), Key Sifting  |  |
|  |  * Feature Extraction Engine |             |  * QBER vs 11% Limit           |  |
|  +--------------+---------------+             +---------------+----------------+  |
|                 |                                             |                   |
|                 v                                             v                   |
|  +------------------------------+             +--------------------------------+  |
|  |    ATTACK ALERT DISPATCH     |             |    KEY MANAGER & AES-256-GCM   |  |
|  |  * Alerts logged to SQLite   |             |  * HKDF Key Derivation         |  |
|  |  * Severity & Mitigations    |             |  * Authenticated Encryption    |  |
|  +------------------------------+             +--------------------------------+  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           FLASK CYBERSECURITY DASHBOARD                           |
|       * Overview Console        * Network Traffic Monitor     * Attack Detection  |
|       * BB84 Quantum Security   * ML Models & Dataset Status  * Chart.js Charts   |
+-----------------------------------------------------------------------------------+
```

---

## 4. Technologies Used

- **Python**: 3.11 / 3.12 / 3.13
- **Web Framework**: Flask 3.1
- **Machine Learning**: Scikit-Learn 1.9, Pandas 3.1, NumPy 2.5, Joblib 1.6
- **SCADA Protocol**: PyModbus 3.16 (Modbus TCP Client & Server)
- **Telemetry Protocol**: Paho MQTT 2.1
- **Cryptographic Security**: Python `cryptography` (AES-256-GCM, HKDF-SHA256, HMAC)
- **Database**: SQLite 3 with parameterized queries and WAL mode
- **Frontend**: HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4
- **Testing**: Pytest 9.1

---

## 5. Folder Structure

```
SCADA_Quantum_Security/
|-- main.py                               # Application entry point & simulation orchestrator
|-- requirements.txt                      # Project Python dependencies
|-- README.md                             # Comprehensive project documentation
|-- .env.example                          # Environment configuration template
|-- .env                                  # Active local environment settings
|-- .gitignore                            # Git exclusion rules
|-- pytest.ini                            # Pytest test discovery & execution configuration
|-- mosquitto.conf                        # Mosquitto broker configuration
|-- docker-compose.yml                    # Docker container definition for Mosquitto
|
|-- config/
|   |-- __init__.py
|   |-- settings.py                       # System-wide configuration loader
|   |-- logging_config.py                 # Centralized rotating logger with secret redaction
|   |-- protocol_config.py                # Modbus register maps and MQTT topics
|
|-- simulation/
|   |-- __init__.py
|   |-- sensor_simulator.py               # Temperature, Pressure, Water Level, Flow Rate sensors
|   |-- actuator_simulator.py             # Pump and Valve states and controls
|   |-- rtu_simulator.py                  # Remote Terminal Unit Modbus register encoding
|   |-- plc_simulator.py                  # PLC safety ladder logic & automated cutoffs
|   |-- mtu_simulator.py                  # Master Terminal Unit telemetry receiver & decoder
|   |-- industrial_process.py             # Coupled mass/heat balance physical simulation
|
|-- protocols/
|   |-- __init__.py
|   |-- modbus_server.py                  # PyModbus 3.x TCP server with dynamic callback datastore
|   |-- modbus_client.py                  # PyModbus 3.x TCP polling client with fast pre-check
|   |-- mqtt_publisher.py                 # Paho MQTT publisher with disconnected reporting
|   |-- mqtt_subscriber.py                # Paho MQTT subscriber with payload validation
|   |-- protocol_adapter.py               # Protocol coordinator with automatic fallback
|
|-- security/
|   |-- __init__.py
|   |-- bb84_protocol.py                  # BB84 Quantum Key Distribution mathematical simulator
|   |-- key_sifting.py                    # Classical basis reconciliation & test sampling
|   |-- qber_calculator.py                # Quantum Bit Error Rate calculation & thresholding
|   |-- key_manager.py                    # HKDF-SHA256 key derivation & session lifecycle
|   |-- encryption.py                     # Authenticated AES-256-GCM with unique nonces & AAD
|   |-- integrity_check.py                # HMAC-SHA256 payload integrity verifier
|
|-- attack_simulation/
|   |-- __init__.py
|   |-- normal_traffic.py                 # Baseline normal telemetry generator
|   |-- replay_attack.py                  # Replay packet simulator with stale timestamps
|   |-- data_injection.py                 # Out-of-bounds sensor injection & write spoofing
|   |-- mitm_simulation.py                # In-memory packet interceptor & payload tamperer
|   |-- dos_simulation.py                 # Rate-anomaly flood burst simulator
|   |-- attack_controller.py              # Safe local attack controller & scenario manager
|
|-- dataset/                              # Existing project datasets
|   |-- train_test_network.csv            # TON_IoT dataset (211,043 rows, 44 columns)
|   |-- scada_sensor_dataset_200_rows.csv # SCADA sensor readings (200 rows, 4 variables)
|
|-- ml_detection/
|   |-- __init__.py
|   |-- dataset_inspector.py              # Discovers and reports schema & class distributions
|   |-- network_dataset_loader.py         # TON_IoT loader with stratified sampling & leak prevention
|   |-- sensor_dataset_loader.py          # Sensor CSV loader & continuous feature validator
|   |-- network_train.py                  # Random Forest training & test evaluation pipeline
|   |-- sensor_train.py                   # Isolation Forest unsupervised anomaly trainer
|   |-- evaluate_model.py                 # Benchmark reporter (Accuracy, Precision, Recall, F1)
|   |-- predict_attack.py                 # Real-time inference engine with feature adapter
|   |-- model_loader.py                   # Model pipeline caching & readiness verification
|
|-- models/
|   |-- network_intrusion_pipeline.joblib # Trained Random Forest model binary
|   |-- sensor_anomaly_pipeline.joblib    # Trained Isolation Forest model binary
|   |-- network_metrics.json              # Full classification report & confusion matrix
|   |-- sensor_metrics.json               # Contamination and outlier threshold metrics
|
|-- database/
|   |-- __init__.py
|   |-- db.py                             # SQLite connection context & schema runner
|   |-- models.py                         # Dataclasses for Devices, Readings, Events, Alerts
|   |-- repository.py                     # Parameterized query repository with WAL mode
|   |-- schema.sql                        # SQL table definitions and performance indexes
|
|-- dashboard/
|   |-- __init__.py
|   |-- app.py                            # Flask application factory
|   |-- routes.py                         # Web views and secured REST API endpoints
|   |-- templates/
|   |   |-- base.html                     # Responsive dark navy theme layout
|   |   |-- index.html                    # Page 1: System Overview & Live Telemetry
|   |   |-- network_monitor.html          # Page 2: Live Network Traffic Stream
|   |   |-- attack_alerts.html            # Page 3: Intrusion Alerts & Attack Controls
|   |   |-- quantum_security.html         # Page 4: BB84 Simulator & QBER Chart
|   |   |-- model_metrics.html            # Page 5: ML Benchmarks & Dataset Inspection
|   |-- static/
|       |-- css/
|       |   |-- style.css                 # Industrial cybersecurity dark theme CSS
|       |-- js/
|           |-- dashboard.js              # Chart.js integrations & auto-refresh AJAX
|
|-- tests/
|   |-- __init__.py
|   |-- test_simulation.py                # Sensor, actuator, PLC logic tests
|   |-- test_modbus.py                    # Register scaling, server datastore, offline handling
|   |-- test_mqtt.py                      # JSON serialization, offline publisher handling
|   |-- test_bb84.py                      # Bases matching, state transmission, sifting
|   |-- test_qber.py                      # QBER error computation, noise, Eve rejection
|   |-- test_encryption.py                # AES-256-GCM, unique nonces, tamper rejection
|   |-- test_ml_detection.py              # Dataset discovery, feature pipelines, inference
|   |-- test_database.py                  # SQLite CRUD, indexes, parameterized queries
|   |-- test_dashboard.py                 # View routes, REST API, attack start/stop
```

---

## 6. Installation & Setup (Windows PowerShell)

### Step 1: Create and Activate Virtual Environment
Open Windows PowerShell in the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If script execution is disabled on your system, enable it for the current process: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 2: Install Dependencies
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env` (already pre-configured for localhost):
```powershell
Copy-Item .env.example .env
```

---

## 7. Mosquitto MQTT Broker (Optional)

The application automatically connects to Mosquitto on `127.0.0.1:1883` if available. If Mosquitto is not installed, the application runs normally in Modbus/in-memory mode and clearly indicates `MQTT Broker: Standby/Disconnected` on the dashboard.

To run Mosquitto locally:
- **Option A (Docker)**:
  ```powershell
  docker compose up -d
  ```
- **Option B (Windows Installer)**:
  Download and install from [mosquitto.org](https://mosquitto.org/download/). Start the service:
  ```powershell
  net start mosquitto
  ```

---

## 8. Dataset Inspection & ML Model Training

Inspect both existing datasets:
```powershell
python -m ml_detection.dataset_inspector
```

Train the unsupervised Sensor Anomaly Detector on `dataset/scada_sensor_dataset_200_rows.csv`:
```powershell
python -m ml_detection.sensor_train
```

Train the Random Forest Network Intrusion Detector on `dataset/train_test_network.csv`:
```powershell
python -m ml_detection.network_train
```

Evaluate model benchmarks:
```powershell
python -m ml_detection.evaluate_model
```

---

## 9. Running Tests

Execute the comprehensive 34-test suite:
```powershell
python -m pytest -q
```

All 34 tests across simulation, Modbus, MQTT, BB84, QBER, AES-GCM encryption, ML pipelines, database, and dashboard routes will execute and pass in ~4 seconds.

---

## 10. Starting the Application

Launch the end-to-end SCADA system and web dashboard:
```powershell
python main.py
```

Console Output:
```text
===========================================================================
  SCADA INTRUSION DETECTION & QUANTUM-SECURE COMMUNICATION SYSTEM
===========================================================================
2026-10-25 18:57:33 [INFO] RTU loaded 200 sensor records from dataset\scada_sensor_dataset_200_rows.csv
2026-10-25 18:57:33 [INFO] Database initialized successfully at data\scada_security.db
2026-10-25 18:57:34 [INFO] Loaded network intrusion pipeline from models\network_intrusion_pipeline.joblib
2026-10-25 18:57:34 [INFO] Loaded sensor anomaly pipeline from models\sensor_anomaly_pipeline.joblib
2026-10-25 18:57:34 [INFO] Establishing baseline BB84 Quantum Key Distribution session...
2026-10-25 18:57:34 [INFO] BB84 Session bb84_5bd025803f2f: ACCEPTED | QBER=0.00% (threshold=11.00%) | Sifted=131 | Final Key Bits=88 | Eve=False | Noise=0.00
2026-10-25 18:57:34 [INFO] New AES-256-GCM session key successfully established from BB84 session bb84_5bd025803f2f
2026-10-25 18:57:34 [INFO] Starting Modbus TCP server on 127.0.0.1:5020 (Slave 1)
2026-10-25 18:57:34 [INFO] Modbus client connected to 127.0.0.1:5020
2026-10-25 18:57:35 [INFO] Background industrial telemetry loop started (Interval: 1.0s)

[+] Dashboard URL: http://127.0.0.1:5000
[+] Press Ctrl+C to stop the application.
===========================================================================
```

Open your browser and navigate to:
**[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 11. Dashboard Pages & Live Demonstration

### Page 1: System Overview (`/` or `/overview`)
- **Metric Cards**: Online/Offline device counts, total processed messages, detected attack count, active quantum session status, and latest QBER.
- **Live Telemetry Chart (Chart.js)**: Continuous real-time graph of Tank Water Level (mm), Temperature (°C), Discharge Flow Rate (L/min), and Line Pressure (bar).
- **Actuators Panel**: Live Feed Pump status (1750 RPM), Safety Valve position, and PLC safety rule state.
- **Recent Alerts Table**: Real-time list of intercepted attack alerts with severity badges and recommended mitigations.

### Page 2: Network Monitor (`/network-monitor`)
- Real-time observation stream of all Modbus TCP and MQTT packets.
- Displays Event ID, Timestamp, Source Node, Destination Node, Protocol, Packet Rate, Payload Bytes, Modbus Function Code, ML Classification, and Model Confidence.
- Interactive Search Bar and Protocol/Classification filters.

### Page 3: Attack Detection & Scenario Controller (`/attack-alerts`)
Contains separate **Start** and **Stop** controls for 4 harmless local attack scenarios:
1. **Replay Attack**: Injects previously recorded valid packets with stale timestamps and duplicate markers. The ML model flags them as `REPLAY`.
2. **False Data Injection**: Injects anomalous sensor values (e.g., 90°C temp, 1400mm water level) or unauthorized write function codes (FC 6 / 16). The ML model flags them as `INJECTION`.
3. **MITM Tampering**: In-memory interception flipping pump control commands or modifying payload bytes. The ML model flags them as `MITM`.
4. **DoS Flood**: Bursts high-frequency probe requests (50–120 pkt/s). The ML model detects the abnormal rate and flags them as `DOS`.
- Includes a **Stop All Attacks** emergency button.

### Page 4: Quantum Security & BB84 Simulator (`/quantum-security`)
- Visual display of Alice (MTU) and Bob (RTU) quantum session parameters.
- Displays Raw Bits Count, Sifted Bits Count (~50% basis match), Disclosed Test Sample (33%), and Final Candidate Key Bits.
- **Interactive BB84 Execution Form**:
  - Configure raw bits (128, 256, 512).
  - Adjust environmental optical channel noise (0% to 30%).
  - Toggle **Simulate Eavesdropper (Eve)**.
  - When Eve intercepts, QBER rises to ~18%–26% (> 11% threshold), automatically rejecting the session and wiping session keys.
  - When Eve is absent and noise is low, QBER remains < 11%, deriving a fresh 256-bit AES key via HKDF.
- **QBER History Chart**: Visualizes past error rates with a red dotted line at the 11% security bound.

### Page 5: ML Models & Dataset Status (`/model-metrics`)
- Summary inspection cards for `dataset/train_test_network.csv` and `dataset/scada_sensor_dataset_200_rows.csv`.
- Tabbed view displaying:
  1. **Network Intrusion Model**: Random Forest accuracy (98.47%), weighted precision (98.50%), recall (98.47%), F1-score (98.48%), and per-class classification breakdown.
  2. **Sensor Anomaly Model**: Isolation Forest contamination (5%), decision boundary (< 0.00 = anomaly), and min/mean/max operating statistics.
  3. **BB84 Security Bounds**: Theoretical Shor-Preskill limits, basis selection, and HKDF parameters.
  4. **Protocol Mappings**: Modbus register map (holding registers 0..6) and MQTT topic hierarchy.

---

## 12. Modbus Register Map & MQTT Topics

### Modbus TCP Holding Registers (Port 5020, Slave ID 1)
| Register Address | Variable | Engineering Unit | Scale Factor | Example Raw Value | Decoded Value |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **0** | Core Temperature | °C | 100 | `2811` | 28.11 °C |
| **1** | Line Pressure | bar | 1000 | `2603` | 2.603 bar |
| **2** | Water Tank Level | mm | 10 | `9314` | 931.4 mm |
| **3** | Discharge Flow Rate | L/min | 100 | `3404` | 34.04 L/min |
| **4** | Feed Pump State | Binary | 1 | `1` (ON) / `0` (OFF) | Pump ON |
| **5** | Safety Valve State| Binary | 1 | `0` (CLOSED) / `1` (OPEN)| Valve CLOSED |
| **6** | Status Code | Enum | 1 | `1`=NORMAL, `2`=WARN, `3`=ALARM, `4`=ATTACK | NORMAL |

### MQTT Topics (Port 1883)
- `scada/rtu1/telemetry`: Periodic sensor readings and actuator states.
- `scada/rtu1/status`: RTU heartbeat and connection health.
- `scada/plc1/status`: Automated ladder logic rule actions.
- `scada/security/alerts`: Real-time intrusion alarms and classifications.
- `scada/quantum/status`: BB84 session key exchange outcomes and QBER values.

---

## 13. REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /api/status` | GET | System health, online device counts, quantum status. |
| `GET /api/devices` | GET | List of all registered SCADA devices and online status. |
| `GET /api/telemetry` | GET | Latest sensor readings and chronological time-series. |
| `GET /api/traffic` | GET | Recent network traffic events with optional `protocol` filter. |
| `GET /api/alerts` | GET | Security intrusion alerts list. |
| `GET /api/quantum/status`| GET | Active BB84 session metadata and QBER history. |
| `GET /api/model/metrics` | GET | Model evaluation metrics and dataset status. |
| `POST /api/quantum/run` | POST | Execute simulated BB84 exchange (`raw_bits`, `noise_level`, `eavesdropper`). |
| `POST /api/attacks/start`| POST | Start a safe attack simulation (`attack_name`: replay, injection, mitm, dos). |
| `POST /api/attacks/stop` | POST | Stop an active attack simulation (`attack_name`: replay, injection, mitm, dos, all). |

*(Note: Control endpoints enforce localhost origin verification for safety.)*

---

## 14. Academic & Security Limitations

1. **Simulated vs Physical Quantum Key Distribution**:
   - This project implements a **classical, algorithmic simulation** of the BB84 protocol. It simulates single-photon state generation and basis measurement mathematically using pseudo-random number generators.
   - It does **not** employ physical single-photon lasers, avalanche photodiode (APD) single-photon detectors, optical fiber dark channels, or polarization splitters.
   - A simulated QKD exchange running over TCP/IP does **not** provide quantum physical protection against physical eavesdropping on standard network cables.
2. **Missing Components for Full Production QKD**:
   - A complete physical QKD deployment requires:
     - **Authenticated Classical Channel**: Prevents classical man-in-the-middle attacks on the basis announcement phase (typically using Wegman-Carter polynomial MACs).
     - **Quantum Information Error Correction**: Reconciliation protocols (e.g., Cascade or LDPC) to correct transmission errors between Alice and Bob's sifted keys without revealing key material to Eve.
     - **Privacy Amplification**: Universal hash functions (e.g., 2-universal hash family) to shrink the corrected key, eliminating any partial Shannon information Eve might have gained.
3. **Machine Learning Model Boundaries**:
   - Model confidence values represent statistical decision surface proximity, not mathematical guarantees of an attack.
   - Anomaly detection uses unsupervised learning on baseline normal operations; out-of-distribution values flag anomalous deviations rather than confirmed intentional attacks.

---

## 15. Troubleshooting

- **Port 5000 Already in Use**:
  Change `FLASK_PORT=5001` in `.env` or run:
  `$env:FLASK_PORT="5001"; python main.py`
- **Modbus Port 5020 Conflict**:
  If another process uses port 5020, change `MODBUS_PORT=5025` in `.env`.
- **Mosquitto Connection Warning**:
  The dashboard displays `MQTT Broker: Standby` if Mosquitto is offline. This is expected behavior and does not affect the Modbus simulator or ML pipeline. To enable MQTT, install and start Mosquitto on port 1883.
- **Model File Missing Error**:
  Run `python -m ml_detection.network_train` and `python -m ml_detection.sensor_train` to regenerate the model artifacts under `models/`.

---

## 16. License

This educational research prototype is developed for academic laboratory demonstration and industrial cybersecurity evaluation.
