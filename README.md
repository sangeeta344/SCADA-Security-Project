# Quantum-Enhanced SCADA Cybersecurity & Intrusion Detection System
### Multi-Laptop Industrial Security Laboratory with Attacker & Defender Portals, Machine Learning Detection, Quantum BB84 Key Distribution, and Real-Time Alerting

A comprehensive, dual-portal industrial control cybersecurity and quantum communication laboratory prototype designed for critical infrastructure SCADA systems.

---

## 1. Project Overview

Industrial Control Systems (ICS) and Supervisory Control and Data Acquisition (SCADA) networks monitor and automate physical industrial operations including power generation, water purification plants, manufacturing pipelines, and oil refineries. Modern industrial digitization has interconnected operational technology (OT) networks with corporate IT networks and the Internet, exposing critical infrastructure to sophisticated cyber threats.

This project delivers a working, end-to-end industrial cybersecurity simulation featuring two separate portals connected to a single unified backend, shared SQLite database, and ML detection engine:

1. **User / Defender Website (Port 5000)**:
   - Real-time operational monitoring of physical SCADA processes (water level, temperature, pressure, flow rate).
   - Live network traffic inspector for Modbus TCP and MQTT protocols.
   - Real-time **Attack Detection** console streaming security incidents via **Server-Sent Events (SSE)** with 2-second polling fallback.
   - Comprehensive 11-column incident table distinguishing between **Machine Learning (Random Forest & Isolation Forest)** and **Rule Guards**.
   - Interactive **Quantum BB84 Simulation** and **QBER Threshold Monitor**.
   - Model metrics & dataset evaluation views.
   - Global **Emergency Simulation Halt** button to restore physical baselines.

2. **Attacker Portal (Port 5000 `/attacker` or Independent Port 5050)**:
   - Dedicated adversary simulation console for authorized laboratory testing.
   - **5 Bounded Attack Scenarios**:
     1. **False Data Injection (FDI)** (Out-of-bounds sensor spoofing & Modbus FC-16 register write tampering) with 1-click physical telemetry restoration.
     2. **Replay Attack** (Replaying captured Modbus frames with stale timestamps and duplicate markers).
     3. **Man-In-The-Middle (MITM)** (In-flight command hijacking and payload modification).
     4. **DoS Flood** (High-rate packet bursts with live `IDLE`, `STARTING`, `RUNNING`, `STOPPED`, and `FAILED` state transitions).
     5. **Brute-Force Login Simulation** (Bounded credential stuffing against dedicated demo account `demo_operator@scada.local` triggering defensive lockout).
   - Terminal activity log displaying synthetic payload traces, detector execution latency, and database confirmation.
   - Dynamic Target Backend API URL pill supporting multi-laptop LAN testing.

3. **Multi-Laptop LAN & Network Architecture**:
   - Backend binds to `0.0.0.0` with automatic LAN IP detection (`http://<LAN_IP>:5000`).
   - Frontend dynamic API base resolution: Automatically routes requests to the hosting laptop and prevents remote laptops from attempting to connect to `127.0.0.1`.
   - Comprehensive CORS configuration and security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`).

4. **Quantum-Safe BB84 & Authenticated AES-256-GCM Encryption**:
   - Single-photon polarization simulation (+ and x bases) between Alice (MTU) and Bob (RTU).
   - Key sifting, environmental noise modeling, and Eve intercept-resend attack simulator.
   - Quantum Bit Error Rate (QBER) calculation against the 11% Shor-Preskill security bound.
   - HKDF-SHA256 session key derivation deriving 256-bit symmetric keys for authenticated AES-256-GCM encryption with unique 96-bit nonces and AAD.

5. **Automated Centralized Email Security Alerts**:
   - SMTP notification engine dispatching structured alerts upon incident detection.
   - Built-in duplicate alert suppression, DoS aggregation, and sensitive account masking.
   - Graceful fallback: Safely queues or skips notifications when SMTP is unconfigured without disrupting simulations.

---

## 2. System Architecture

```text
+----------------------------------------------------------------------------------------------------+
|                                    LOCAL AREA NETWORK (LAN)                                         |
|                                                                                                    |
|   LAPTOP 1: DEFENDER & SERVER (HOST)                      LAPTOP 2: ATTACKER PORTAL                |
|   IP: e.g. 192.168.29.212                                 IP: Any Authorized Device                |
|                                                                                                    |
|   +------------------------------------+                  +------------------------------------+   |
|   |   User Dashboard (Port 5000)       |                  |   Attacker Portal (Port 5050 /     |   |
|   |   - System Overview                |                  |                    /attacker)      |   |
|   |   - Network Monitor                |                  |   - FDI, Replay, MITM, DoS,        |   |
|   |   - Attack Alerts (Live SSE)       |                  |     Brute-Force Simulations        |   |
|   |   - Quantum BB84 & QBER            |                  |   - Fictional Researcher Logins    |   |
|   |   - ML & Datasets                  |                  |   - Dynamic API Target URL Pill    |   |
|   +-----------------+------------------+                  |   - Emergency Halt Trigger         |   |
|                     |                                     +-----------------+------------------+   |
|                     v                                                       |                      |
|   +------------------------------------+                                    |                      |
|   |     Unified Flask Backend API      |<===================================+                      |
|   |   (0.0.0.0:5000 / CORS Enabled)    |         REST API + Credentials Include                    |
|   |   - API Key & CIDR Authorization   |                                                           |
|   |   - Server-Side Validation         |                                                           |
|   |   - Random Forest & IsoForest ML   |                                                           |
|   |   - Freshness & Auth Rate Guards   |                                                           |
|   |   - SSE Stream (/api/alerts/stream)|                                                           |
|   |   - Emergency Stop Orchestrator    |                                                           |
|   +-----------------+------------------+                                                           |
|                     |                                                                              |
|                     v                                                                              |
|   +------------------------------------+                  +------------------------------------+   |
|   |   Shared SQLite Database           |                  |   SMTP Email Alert Engine          |   |
|   |   data/scada_security.db           |                  |   - Masked Account Details         |   |
|   |   - Shared Incidents & Telemetry   |                  |   - Duplicate Suppression          |   |
|   |   - Demo Operator Accounts         |                  |   - DoS Burst Aggregation          |   |
|   +------------------------------------+                  +------------------------------------+   |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Technologies Used

- **Python**: 3.11 / 3.12 / 3.13
- **Web Framework**: Flask 3.1 (Application Factory, Blueprints, SSE Streaming, CORS, Jinja2)
- **Machine Learning**: Scikit-Learn 1.9, Pandas 3.1, NumPy 2.5, Joblib 1.6
  - *Network Intrusion Classifier*: Random Forest Classifier (TON_IoT dataset, 10 classes)
  - *Sensor Anomaly Detector*: Unsupervised Isolation Forest (physical process telemetry)
- **Industrial Protocols**: PyModbus 3.16 (Modbus TCP Client & Server on port 5020), Paho MQTT 2.1
- **Cryptographic Security**: Python `cryptography` (AES-256-GCM, HKDF-SHA256, HMAC-SHA256)
- **Database**: SQLite 3 (WAL mode, parameterized queries, relational schema)
- **Frontend**: HTML5, CSS3, Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4, Server-Sent Events (SSE)
- **Testing**: Pytest 9.1 (64 automated unit & integration tests)

---

## 4. Folder Structure

```text
SCADA_Security_Project/
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
|   |-- settings.py                       # System-wide configuration loader (Network, CORS, SMTP)
|   |-- logging_config.py                 # Centralized rotating logger with secret redaction
|   |-- protocol_config.py                # Modbus register maps and MQTT topics
|
|-- simulation/
|   |-- sensor_simulator.py               # Temperature, Pressure, Water Level, Flow Rate sensors
|   |-- actuator_simulator.py             # Pump and Valve states and controls
|   |-- rtu_simulator.py                  # Remote Terminal Unit Modbus register encoding
|   |-- plc_simulator.py                  # PLC safety ladder logic & automated cutoffs
|   |-- mtu_simulator.py                  # Master Terminal Unit telemetry receiver & decoder
|   |-- industrial_process.py             # Coupled mass/heat balance physical simulation
|
|-- protocols/
|   |-- modbus_server.py                  # PyModbus TCP server on port 5020
|   |-- modbus_client.py                  # PyModbus TCP polling client
|   |-- mqtt_publisher.py                 # Paho MQTT publisher with disconnected reporting
|   |-- mqtt_subscriber.py                # Paho MQTT subscriber with payload validation
|   |-- protocol_adapter.py               # Protocol coordinator with automatic fallback
|
|-- security/
|   |-- bb84_protocol.py                  # BB84 Quantum Key Distribution simulator
|   |-- key_sifting.py                    # Classical basis reconciliation & test sampling
|   |-- qber_calculator.py                # Quantum Bit Error Rate calculation & thresholding
|   |-- key_manager.py                    # HKDF-SHA256 key derivation & session lifecycle
|   |-- encryption.py                     # Authenticated AES-256-GCM with unique nonces & AAD
|   |-- integrity_check.py                # HMAC-SHA256 payload integrity verifier
|   |-- email_notifier.py                 # Centralized SMTP alert dispatch & rate limiter
|   |-- login_monitor.py                  # Server-side brute-force monitor & account lockout
|
|-- attack_simulation/
|   |-- normal_traffic.py                 # Baseline normal telemetry generator
|   |-- replay_attack.py                  # Replay packet simulator with stale timestamps
|   |-- data_injection.py                 # Out-of-bounds sensor injection & write spoofing
|   |-- mitm_simulation.py                # In-memory packet interceptor & payload tamperer
|   |-- dos_simulation.py                 # Rate-anomaly flood burst simulator
|   |-- attack_controller.py              # Safe local attack controller & scenario manager
|
|-- attacker_portal/                      # Dedicated Attacker Portal subsystem
|   |-- routes.py                         # Attacker console routes, authentication, API endpoints
|   |-- simulation_service.py             # Multi-scenario engine, state manager, background workers
|   |-- runner.py                         # Standalone runner for independent port 5050
|   |-- templates/
|   |   |-- attacker_base.html            # Attacker layout with dynamic API resolution
|   |   |-- attacker_login.html           # Adversary login with fictional credentials
|   |   |-- attacker_console.html         # Attacker console with 5 attack cards & terminal
|   |-- static/
|       |-- css/attacker_style.css        # Hacker-terminal neon styling & state badges
|       |-- js/attacker_console.js        # Simulation dispatch, lifecycle states, live logs
|
|-- dataset/                              # Industrial network and SCADA datasets
|   |-- train_test_network.csv            # TON_IoT dataset (211,043 rows, 44 columns)
|   |-- scada_sensor_dataset_200_rows.csv # SCADA sensor readings (200 rows, 4 variables)
|
|-- ml_detection/
|   |-- dataset_inspector.py              # Discovers and reports schema & class distributions
|   |-- network_dataset_loader.py         # TON_IoT loader with stratified sampling
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
|   |-- db.py                             # SQLite connection context & baseline account seeder
|   |-- models.py                         # Dataclasses for Devices, Readings, Events, Alerts
|   |-- repository.py                     # Parameterized query repository with WAL mode
|   |-- schema.sql                        # SQL table definitions and performance indexes
|
|-- dashboard/                            # User / Defender Dashboard subsystem
|   |-- app.py                            # Flask application factory with CORS & context
|   |-- routes.py                         # Defender views, SSE stream (/api/alerts/stream)
|   |-- templates/
|   |   |-- base.html                     # Responsive dark navy theme layout
|   |   |-- index.html                    # Page 1: System Overview & Live Telemetry
|   |   |-- network_monitor.html          # Page 2: Live Network Traffic Stream
|   |   |-- attack_alerts.html            # Page 3: Intrusion Alerts (11 attributes, SSE)
|   |   |-- quantum_security.html         # Page 4: BB84 Simulator & QBER Chart
|   |   |-- model_metrics.html            # Page 5: ML Benchmarks & Dataset Inspection
|   |-- static/
|       |-- css/style.css                 # Industrial cybersecurity dark theme CSS
|       |-- js/dashboard.js               # SSE listener, fallback polling, Chart.js graphs
|
|-- tests/
|   |-- test_simulation.py                # Sensor, actuator, PLC logic tests
|   |-- test_modbus.py                    # Register scaling, server datastore, offline handling
|   |-- test_mqtt.py                      # JSON serialization, offline publisher handling
|   |-- test_bb84.py                      # Bases matching, state transmission, sifting
|   |-- test_qber.py                      # QBER error computation, noise, Eve rejection
|   |-- test_encryption.py                # AES-256-GCM, unique nonces, tamper rejection
|   |-- test_ml_detection.py              # Dataset discovery, feature pipelines, inference
|   |-- test_database.py                  # SQLite CRUD, indexes, parameterized queries
|   |-- test_dashboard.py                 # View routes, REST API, login checks
|   |-- test_attacker_portal.py           # 27 integration tests for portal, CORS, SSE, lifecycle
```

---

## 5. Quick Start & Execution Guide

### Prerequisites
- Python 3.11, 3.12, or 3.13 installed on Windows, macOS, or Linux.
- Windows PowerShell (recommended for Windows users).

```powershell
# 1. Clone repository
git clone https://github.com/sangeeta344/SCADA-Security-Project.git
cd SCADA-Security-Project

# 2. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install required packages
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Option A: Single-Laptop Demo (Localhost)

Run the unified application on port 5000:

```powershell
.venv\Scripts\python main.py
```

Console startup banner:
```text
===========================================================================
  SCADA INTRUSION DETECTION & QUANTUM-SECURE COMMUNICATION SYSTEM
===========================================================================
[+] Local Operator URL:      http://127.0.0.1:5000
[+] Local Attacker Portal:   http://127.0.0.1:5000/attacker
[+] Cross-Laptop Operator:   http://<YOUR_LAN_IP>:5000
[+] Cross-Laptop Attacker:   http://<YOUR_LAN_IP>:5000/attacker
===========================================================================
```

#### Accessing the Websites:
1. **User / Defender Website**:
   - **URL**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
   - **Email**: `admin@scada.local`
   - **Password**: `AdminPass123!`
   - Navigate to **Attack Detection** in the sidebar.

2. **Attacker Portal**:
   - **URL**: [http://127.0.0.1:5000/attacker](http://127.0.0.1:5000/attacker)
   - **Email**: `researcher@scada-lab.local`
   - **Password**: `LabResearch2026!`
   - *(Alternative account: `redteam_lead@scada-lab.local` / `Adversary2026!`)*

---

### Option B: Two-Laptop Demonstration (Cross-Laptop LAN)

#### On Laptop 1 (Host & Defender):
1. **Firewall Access**: Allow port 5000 through Windows Firewall (run once as Administrator if needed):
   ```powershell
   Start-Process powershell -Verb RunAs -ArgumentList '-Command', 'New-NetFirewallRule -DisplayName "SCADA Lab 5000" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow'
   ```
2. **Start the application**:
   ```powershell
   .venv\Scripts\python main.py
   ```
   *Note the **Cross-Laptop URL** displayed in the banner (for example, `http://192.168.29.212:5000`).*
3. Open browser on Laptop 1 to `http://127.0.0.1:5000`, log in as `admin@scada.local`, and go to **Attack Detection**.

#### On Laptop 2 (Attacker):
1. Connect Laptop 2 to the same Wi-Fi / local network.
2. Open any browser (Chrome, Edge, Firefox) and navigate to:
   ```text
   http://<LAPTOP_1_IP>:5000/attacker
   ```
   *(e.g., `http://192.168.29.212:5000/attacker`)*
3. Log in with `researcher@scada-lab.local` / `LabResearch2026!`.
4. Select **DoS Flood Simulation** (or False Data Injection, Replay, MITM, Brute-Force) and click **Start DoS** or **Launch Simulation**.
5. **Observe Laptop 1**: The new security alert appears **in real time (<1s)** on Laptop 1's Attack Detection table with detection outcome, ML model label, confidence score, and severity rating.

---

### Option C: Independent Dual-Port Setup (Port 5000 + Port 5050)

If you prefer running the Attacker Portal as a completely independent process on its own port:

- **Terminal 1 (Defender Backend & Dashboard)**:
  ```powershell
  .venv\Scripts\python main.py
  ```
- **Terminal 2 (Attacker Portal)**:
  ```powershell
  .venv\Scripts\python attacker_portal/runner.py
  ```
  Attacker Portal is accessible at `http://127.0.0.1:5050` or `http://<LAPTOP_1_IP>:5050`.

---

## 6. The Five Authorized Lab Simulation Scenarios

| # | Scenario | Mechanism & Parameter Controls | Detection Module | Recorded Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **False Data Injection (FDI)** | Spoofs temperature (50–115°C), pressure (4–10 bar), or water level (1150–1600mm) via Modbus FC-16. Includes 1-click **Restore Original Sensor Reading**. | **Isolation Forest** (Unsupervised Anomaly ML) + FC-16 Guard | Classified as `ANOMALY` / `INJECTION`, anomaly score $\ge 0.55$, severity `HIGH`. |
| **2** | **Replay Attack** | Injects previously recorded valid frames with stale timestamps (300–7,200s delta) and duplicate sequence numbers. | **Protocol Freshness & Monotonic Sequence Guard** (Rule) | Rejected: stale sequence / duplicate Modbus frame, severity `MEDIUM`. |
| **3** | **MITM Simulation** | Intercepts in-transit commands between RTU and PLC, modifying actuator commands (e.g. `FORCED_EMERGENCY_SHUTDOWN_OVERRIDE`). | **Random Forest Classifier** (Network ML) + Cryptographic Guard | Classified as `MITM`, confidence $\ge 85\%$, severity `CRITICAL`. |
| **4** | **DoS Flood** | High-rate packet bursts (45–120 pkt/s) against synthetic Modbus ports. Supports live lifecycle states (`IDLE`, `STARTING`, `RUNNING`, `STOPPED`, `FAILED`). | **Random Forest Classifier** (Network ML) + Rate Surge Guard (>40 pkt/s) | Classified as `DOS`, confidence $\ge 94\%$, severity `HIGH`. |
| **5** | **Brute-Force Login** | Bounded failed login attempts (up to 5) simulated against dedicated demo account `demo_operator@scada.local`. | **Authentication Rate Guard** (Rule Guard) | Account lockout triggered, generic error returned, zero passwords/hashes logged. |

---

## 7. Running Automated Tests

Run the complete 64-test suite with pytest:

```powershell
.venv\Scripts\pytest -v
```

Execution Summary:
```text
============================= test session starts =============================
platform win32 -- Python 3.13.3, pytest-9.1.1, pluggy-1.7.0
rootdir: D:\Desktop\SCADA_Security_Project
configfile: pytest.ini
collected 64 items

tests/test_attacker_portal.py ...........................               [ 42%]
tests/test_bb84.py ...                                                  [ 46%]
tests/test_dashboard.py .......                                         [ 57%]
tests/test_database.py ...                                              [ 62%]
tests/test_encryption.py .....                                          [ 70%]
tests/test_ml_detection.py ....                                         [ 76%]
tests/test_modbus.py ...                                                [ 81%]
tests/test_mqtt.py ...                                                  [ 85%]
tests/test_qber.py ....                                                 [ 92%]
tests/test_simulation.py .....                                          [100%]

============================= 64 passed in 26.71s =============================
```

---

## 8. Centralized Email Alert Configuration (Optional)

The system includes an automatic email notification engine for critical incidents and brute-force lockouts. Configure `.env`:

```ini
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-alert-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM_EMAIL=alerts@scada-defense.local
SCADA_ALERT_EMAIL=security-team@yourorg.com
```

- **Duplicate Alert Suppression**: Suppresses duplicate notifications for identical incidents within a configurable window.
- **DoS Aggregation**: Rate-limits repeated flood alerts to prevent inbox saturation.
- **Graceful Offline Fallback**: If SMTP credentials are not configured, notifications are safely recorded with status `skipped` in the SQLite database without causing errors or stopping simulations.

---

## 9. How to Push Changes to GitHub

To push your latest work and the updated README to your GitHub repository:

### Step 1: Check Git Status
```powershell
git status
```

### Step 2: Stage All Changes
```powershell
git add .
```

### Step 3: Commit Changes with a Clear Message
```powershell
git commit -m "feat: Add Attacker Portal, multi-laptop monitoring, real-time alerts, DoS lifecycle, and updated documentation"
```

### Step 4: Push to GitHub
```powershell
git push origin main
```

*(If prompted for GitHub credentials, enter your GitHub username and use a **Personal Access Token (classic)** with `repo` scope as your password).*

---

## 10. Academic & Security Limitations

1. **Simulated vs Physical Quantum Key Distribution**:
   - This project implements a **classical, algorithmic simulation** of the BB84 single-photon protocol using pseudo-random generation.
   - It does **not** employ physical single-photon lasers, avalanche photodiode (APD) detectors, optical fiber dark channels, or polarization splitters.
2. **Synthetic Attack Bounding**:
   - All attack simulations execute exclusively against synthetic target data and dedicated mock endpoints on localhost/LAN.
   - Real passwords, session tokens, and operational production devices are never targeted, logged, or exposed.
3. **Machine Learning Model Boundaries**:
   - Model confidence values represent statistical proximity within the TON_IoT training distribution.
   - Anomaly detection identifies out-of-distribution physical values relative to baseline normal telemetry.

---

## 11. License

This educational research prototype is developed for academic laboratory demonstration, multi-device cybersecurity training, and critical infrastructure evaluation. [LICENSE.md](LICENSE.md)
