-- SQLite Database Schema for SCADA Security & Quantum System

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL,  -- RTU, PLC, MTU, SENSOR, ACTUATOR
    protocol TEXT NOT NULL,     -- MODBUS_TCP, MQTT, INTERNAL
    ip_address TEXT,
    port INTEGER,
    status TEXT NOT NULL DEFAULT 'OFFLINE',  -- ONLINE, OFFLINE, DEGRADED, ALARM
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sensor_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sensor_id TEXT NOT NULL,
    rtu_id TEXT NOT NULL,
    temperature_c REAL NOT NULL,
    pressure_bar REAL NOT NULL,
    water_level_mm REAL NOT NULL,
    flow_rate_lpm REAL NOT NULL,
    operating_status TEXT NOT NULL DEFAULT 'NORMAL',
    is_anomaly INTEGER NOT NULL DEFAULT 0,  -- 0=Normal, 1=Anomalous
    anomaly_score REAL DEFAULT 0.0,
    source TEXT NOT NULL DEFAULT 'SIMULATED' -- SIMULATED, CSV_DATASET, LIVE_POLL
);

CREATE TABLE IF NOT EXISTS network_traffic_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_device TEXT NOT NULL,
    dst_device TEXT NOT NULL,
    protocol TEXT NOT NULL,     -- MODBUS_TCP, MQTT, TCP
    packet_rate REAL DEFAULT 0.0,
    payload_length INTEGER DEFAULT 0,
    function_code INTEGER,
    is_write INTEGER DEFAULT 0,
    register_count INTEGER DEFAULT 0,
    is_duplicate INTEGER DEFAULT 0,
    anomaly_flag INTEGER DEFAULT 0,
    predicted_class TEXT DEFAULT 'normal',
    confidence REAL DEFAULT 1.0,
    attack_category TEXT DEFAULT 'normal',
    expected_label TEXT DEFAULT 'normal',
    status TEXT DEFAULT 'PROCESSED'
);

CREATE TABLE IF NOT EXISTS attack_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_type TEXT NOT NULL,       -- replay, injection, mitm, dos
    source_device TEXT NOT NULL,
    severity TEXT NOT NULL,          -- LOW, MEDIUM, HIGH, CRITICAL
    predicted_label TEXT NOT NULL,
    confidence REAL NOT NULL,
    details TEXT,
    mitigation_action TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS quantum_sessions (
    session_id TEXT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alice_id TEXT NOT NULL,
    bob_id TEXT NOT NULL,
    raw_bits_count INTEGER NOT NULL,
    sifted_bits_count INTEGER NOT NULL,
    disclosed_sample_count INTEGER NOT NULL,
    final_key_bits_count INTEGER NOT NULL,
    qber REAL NOT NULL,
    qber_threshold REAL NOT NULL,
    status TEXT NOT NULL,           -- ACCEPTED, REJECTED
    eavesdropper_present INTEGER NOT NULL DEFAULT 0,
    noise_level REAL NOT NULL DEFAULT 0.0,
    rejection_reason TEXT
);

CREATE TABLE IF NOT EXISTS qber_measurements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    qber REAL NOT NULL,
    sample_size INTEGER NOT NULL,
    errors_detected INTEGER NOT NULL,
    noise_level REAL NOT NULL,
    eavesdropper_present INTEGER NOT NULL,
    threshold REAL NOT NULL,
    passed INTEGER NOT NULL,
    FOREIGN KEY(session_id) REFERENCES quantum_sessions(session_id)
);

CREATE TABLE IF NOT EXISTS model_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,       -- network_classifier, sensor_anomaly_detector
    model_type TEXT NOT NULL,       -- RandomForest, IsolationForest
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dataset_name TEXT NOT NULL,
    train_samples INTEGER NOT NULL,
    test_samples INTEGER NOT NULL,
    accuracy REAL,
    precision REAL,
    recall REAL,
    f1_score REAL,
    metrics_json TEXT NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_sensor_ts ON sensor_readings(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON network_traffic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_pred ON network_traffic_events(predicted_class);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON attack_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON attack_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_quantum_ts ON quantum_sessions(timestamp);

-- User Authentication & Access Control
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Operator',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

