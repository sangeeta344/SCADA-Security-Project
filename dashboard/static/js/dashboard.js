/**
 * SCADA Security & Quantum Dashboard Frontend Script
 */

let telemetryChartInstance = null;
let qberChartInstance = null;
let autoRefreshTimer = null;

// Dynamic API Base URL resolution for multi-laptop testing
function getApiBaseUrl() {
    if (window.SCADA_CONFIG && window.SCADA_CONFIG.apiBase && window.SCADA_CONFIG.apiBase.trim()) {
        const base = window.SCADA_CONFIG.apiBase.trim().replace(/\/+$/, "");
        // If the browser is accessing via a LAN IP or domain, but apiBase was default localhost/127.0.0.1,
        // do not route to localhost (which would erroneously target the client laptop)
        if (window.location.hostname !== "127.0.0.1" && window.location.hostname !== "localhost") {
            if (base.includes("127.0.0.1") || base.includes("localhost")) {
                return window.location.origin;
            }
        }
        return base;
    }
    return window.location.origin;
}

// Update live clock
function updateLiveClock() {
    const clockEl = document.getElementById("live-clock");
    if (clockEl) {
        const now = new Date();
        clockEl.innerText = now.toTimeString().split(" ")[0];
    }
}
setInterval(updateLiveClock, 1000);
updateLiveClock();

// =========================================================================
// TELEMETRY CHART (Overview Page)
// =========================================================================

function initTelemetryChart() {
    const ctx = document.getElementById("telemetryChart");
    if (!ctx) return;

    telemetryChartInstance = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Water Level (mm)",
                    data: [],
                    borderColor: "#00d2ff",
                    backgroundColor: "rgba(0, 210, 255, 0.1)",
                    borderWidth: 2,
                    tension: 0.3,
                    yAxisID: "yLevel",
                },
                {
                    label: "Temperature (°C)",
                    data: [],
                    borderColor: "#ff0054",
                    backgroundColor: "transparent",
                    borderWidth: 2,
                    tension: 0.3,
                    yAxisID: "yOther",
                },
                {
                    label: "Flow Rate (L/min)",
                    data: [],
                    borderColor: "#00f5d4",
                    backgroundColor: "transparent",
                    borderWidth: 2,
                    tension: 0.3,
                    yAxisID: "yOther",
                },
                {
                    label: "Pressure (bar x10)",
                    data: [],
                    borderColor: "#ffbe0b",
                    backgroundColor: "transparent",
                    borderWidth: 2,
                    tension: 0.3,
                    yAxisID: "yOther",
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: "index",
                intersect: false,
            },
            plugins: {
                legend: {
                    labels: { color: "#9cb1d6", font: { size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(36, 54, 102, 0.4)" },
                    ticks: { color: "#6278a3", maxRotation: 0 }
                },
                yLevel: {
                    type: "linear",
                    position: "left",
                    min: 700,
                    max: 1200,
                    grid: { color: "rgba(36, 54, 102, 0.4)" },
                    ticks: { color: "#00d2ff" },
                    title: { display: true, text: "Water Level (mm)", color: "#00d2ff" }
                },
                yOther: {
                    type: "linear",
                    position: "right",
                    min: 0,
                    max: 60,
                    grid: { drawOnChartArea: false },
                    ticks: { color: "#9cb1d6" },
                    title: { display: true, text: "Temp / Flow / Press(x10)", color: "#9cb1d6" }
                }
            }
        }
    });

    fetchTelemetryData();
}

function fetchTelemetryData() {
    fetch("/api/telemetry?limit=25")
        .then(res => res.json())
        .then(data => {
            if (!telemetryChartInstance || !data.series) return;

            const labels = [];
            const levels = [];
            const temps = [];
            const flows = [];
            const pressures = [];

            data.series.forEach(item => {
                const timeStr = item.timestamp ? item.timestamp.split(" ")[1] : "";
                labels.push(timeStr);
                levels.push(item.water_level_mm);
                temps.push(item.temperature_c);
                flows.push(item.flow_rate_lpm);
                pressures.push(item.pressure_bar * 10);
            });

            telemetryChartInstance.data.labels = labels;
            telemetryChartInstance.data.datasets[0].data = levels;
            telemetryChartInstance.data.datasets[1].data = temps;
            telemetryChartInstance.data.datasets[2].data = flows;
            telemetryChartInstance.data.datasets[3].data = pressures;
            telemetryChartInstance.update();

            // Update stats cards if present
            if (data.latest) {
                const lat = data.latest;
                const pumpEl = document.getElementById("val-pump-state");
                if (pumpEl && lat.pump_state) pumpEl.innerText = lat.pump_state;
            }
        })
        .catch(err => console.warn("Error fetching telemetry:", err));
}

// =========================================================================
// QBER CHART (Quantum Security Page)
// =========================================================================

function initQberChart() {
    const ctx = document.getElementById("qberChart");
    if (!ctx) return;

    qberChartInstance = new Chart(ctx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                {
                    label: "Measured QBER (%)",
                    data: [],
                    borderColor: "#00d2ff",
                    backgroundColor: "rgba(0, 210, 255, 0.15)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.2,
                    pointRadius: 4,
                },
                {
                    label: "Security Threshold (11%)",
                    data: [],
                    borderColor: "#ff0054",
                    borderWidth: 2,
                    borderDash: [6, 4],
                    pointRadius: 0,
                    fill: false,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: "#9cb1d6" }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(36, 54, 102, 0.4)" },
                    ticks: { color: "#6278a3" }
                },
                y: {
                    min: 0,
                    max: 35,
                    grid: { color: "rgba(36, 54, 102, 0.4)" },
                    ticks: {
                        color: "#9cb1d6",
                        callback: val => val + "%"
                    },
                    title: { display: true, text: "Quantum Bit Error Rate (QBER)", color: "#9cb1d6" }
                }
            }
        }
    });

    fetchQberData();
}

function fetchQberData() {
    fetch("/api/quantum/status")
        .then(res => res.json())
        .then(data => {
            if (!qberChartInstance || !data.qber_history) return;

            const labels = [];
            const qberVals = [];
            const thresholds = [];

            data.qber_history.forEach(item => {
                const timeStr = item.timestamp ? item.timestamp.split(" ")[1] : `#${item.id}`;
                labels.push(timeStr);
                qberVals.push(item.qber * 100);
                thresholds.push(item.threshold * 100);
            });

            qberChartInstance.data.labels = labels;
            qberChartInstance.data.datasets[0].data = qberVals;
            qberChartInstance.data.datasets[1].data = thresholds;
            qberChartInstance.update();
        })
        .catch(err => console.warn("Error fetching QBER history:", err));
}

// =========================================================================
// BB84 SIMULATOR EXECUTION
// =========================================================================

function runBB84() {
    const rawBits = parseInt(document.getElementById("bb84-raw-bits").value, 10);
    const noiseLevel = parseFloat(document.getElementById("bb84-noise").value);
    const eavesdropper = document.getElementById("bb84-eavesdropper").checked;
    const btn = document.getElementById("btn-run-bb84");

    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Simulating Quantum Channel...`;

    fetch("/api/quantum/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            raw_bits: rawBits,
            noise_level: noiseLevel,
            eavesdropper: eavesdropper
        })
    })
    .then(res => res.json())
    .then(data => {
        btn.disabled = false;
        btn.innerHTML = `<i class="bi bi-lightning-charge-fill"></i> Execute BB84 Exchange`;

        if (data.success && data.result) {
            const res = data.result.latest_bb84 || {};
            const resBox = document.getElementById("bb84-result-box");
            if (resBox) {
                resBox.style.display = "block";
                const passed = data.result.is_encrypted;
                const outcomeEl = document.getElementById("res-outcome");
                outcomeEl.className = passed ? "badge bg-success" : "badge bg-danger";
                outcomeEl.innerText = passed ? "ACCEPTED (KEY DERIVED)" : "REJECTED (INSECURE)";

                document.getElementById("res-sifted").innerText = `${res.raw_bits_count} raw -> ${res.sifted_bits_count} sifted (${res.basis_match_percentage}%)`;
                document.getElementById("res-sample").innerText = `${res.disclosed_sample_count} bits evaluated`;
                
                const qberEl = document.getElementById("res-qber");
                qberEl.innerText = `${res.qber_percentage}% (Limit: 11%)`;
                qberEl.style.color = res.qber <= 0.11 ? "#00f5d4" : "#ff0054";

                document.getElementById("res-final-bits").innerText = `${res.final_key_bits_count} bits -> AES-256-GCM Session Key`;
            }

            // Update top cards
            const sessionEl = document.getElementById("q-session-id");
            if (sessionEl) sessionEl.innerText = data.result.active_session_id || "Rejected";
            const qberTop = document.getElementById("q-latest-qber");
            if (qberTop) qberTop.innerText = `${res.qber_percentage}%`;

            fetchQberData();
        } else {
            alert("BB84 Error: " + (data.error || "Simulation failed"));
        }
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerHTML = `<i class="bi bi-lightning-charge-fill"></i> Execute BB84 Exchange`;
        alert("Request error: " + err);
    });
}

// =========================================================================
// ATTACK SIMULATION CONTROLLER
// =========================================================================

function startAttack(attackName) {
    fetch("/api/attacks/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_name: attackName })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateAttackBadges(data.active_attacks || [attackName]);
        } else {
            alert("Error: " + (data.error || "Could not start attack"));
        }
    });
}

function stopAttack(attackName) {
    fetch("/api/attacks/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_name: attackName })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            updateAttackBadges(data.active_attacks || []);
        }
    });
}

function updateAttackBadges(activeList) {
    ["replay", "injection", "mitm", "dos"].forEach(att => {
        const badge = document.getElementById(`status-badge-${att}`);
        if (badge) {
            const isActive = activeList.includes(att);
            badge.className = isActive ? "badge bg-danger" : "badge bg-secondary";
            badge.innerText = isActive ? "ACTIVE" : "IDLE";
        }
    });
}

// =========================================================================
// TRAFFIC FILTERING & MONITOR
// =========================================================================

function applyTrafficFilter() {
    const searchInput = document.getElementById("traffic-search-input");
    const protoFilter = document.getElementById("protocol-filter");
    const classFilter = document.getElementById("class-filter");

    const q = (searchInput ? searchInput.value : "").trim().toLowerCase();
    const p = protoFilter ? protoFilter.value : "";
    const c = classFilter ? classFilter.value.trim().toLowerCase() : "";

    const rows = document.querySelectorAll("#traffic-tbody tr");
    let visibleCount = 0;

    rows.forEach(r => {
        // Skip empty placeholder row if present
        if (r.cells.length <= 1) return;

        const text = r.innerText.toLowerCase();
        const proto = (r.getAttribute("data-proto") || "").toUpperCase();
        const pred = (r.getAttribute("data-pred") || "").toLowerCase();

        const matchQ = !q || text.includes(q);
        const matchP = !p || proto === p.toUpperCase();
        const matchC = !c || pred === c;

        if (matchQ && matchP && matchC) {
            r.style.display = "";
            visibleCount++;
        } else {
            r.style.display = "none";
        }
    });

    const countEl = document.getElementById("traffic-table-count");
    if (countEl) {
        countEl.innerText = `Showing ${visibleCount} filtered events`;
    }
}

function initTrafficFiltering() {
    const searchInput = document.getElementById("traffic-search-input");
    const protoFilter = document.getElementById("protocol-filter");
    const classFilter = document.getElementById("class-filter");

    if (searchInput) searchInput.addEventListener("input", applyTrafficFilter);
    if (protoFilter) protoFilter.addEventListener("change", applyTrafficFilter);
    if (classFilter) classFilter.addEventListener("change", applyTrafficFilter);

    // Initial filter run on page load
    applyTrafficFilter();
}

function fetchTrafficEvents() {
    fetch("/api/traffic?limit=50")
        .then(res => res.json())
        .then(data => {
            const tbody = document.getElementById("traffic-tbody");
            if (!tbody || !data.events) return;

            let html = "";
            data.events.forEach(ev => {
                const isNorm = ev.predicted_class === "normal";
                html += `
                <tr data-proto="${ev.protocol}" data-pred="${ev.predicted_class}">
                    <td class="mono-text text-info">${ev.event_id}</td>
                    <td class="mono-text" style="color: #cbd5e1;">${ev.timestamp}</td>
                    <td class="mono-text text-light">${ev.src_device}</td>
                    <td class="mono-text text-light">${ev.dst_device}</td>
                    <td><span class="badge ${ev.protocol === 'MODBUS_TCP' ? 'bg-primary' : 'bg-info text-dark'}">${ev.protocol}</span></td>
                    <td class="mono-text text-light">${ev.packet_rate} pkt/s</td>
                    <td class="mono-text text-light">${ev.payload_length} B</td>
                    <td class="mono-text text-warning">${ev.function_code || '-'}</td>
                    <td><span class="badge ${isNorm ? 'bg-success' : 'bg-danger'}">${ev.predicted_class.toUpperCase()}</span></td>
                    <td class="mono-text text-light">${(ev.confidence * 100).toFixed(1)}%</td>
                    <td>${isNorm ? '<span class="status-pill pill-success"><i class="bi bi-check"></i> Passed</span>' : '<span class="status-pill pill-danger"><i class="bi bi-exclamation"></i> Flagged</span>'}</td>
                </tr>`;
            });
            tbody.innerHTML = html;
            // Re-apply filter on new rows
            applyTrafficFilter();
        });
}

const ATTACK_MITIGATIONS = {
    "dos": "Apply rate-limiting / Drop incoming burst packets / Enable SYN-flood guard on Modbus port 5020",
    "ddos": "Activate distributed traffic scrubbing / Blacklist botnet subnet / Failover to isolated SCADA ring",
    "injection": "Reject out-of-boundary register write / Cross-verify against physical process model / Re-authenticate sender",
    "mitm": "Drop intercepted packet / Invalidate active session key / Trigger emergency BB84 re-keying & verify AAD",
    "replay": "Reject duplicate sequence / Enforce monotonic packet counter / Discard stale timestamp (>30s window)",
    "backdoor": "Block unauthorized management port / Terminate anomalous socket / Audit PLC firmware integrity",
    "scanning": "Block reconnaissance IP probe / Conceal Modbus unit IDs / Log network discovery attempt in SIEM",
    "password": "Lock out remote client after repeated handshakes / Require certificate-based client auth",
    "ransomware": "Isolate affected network segment immediately / Engage air-gapped backup PLC controller",
    "xss": "Sanitize web HMI input fields / Enforce strict Content Security Policy (CSP)",
};

function getMitigationText(attackType, fallbackAction) {
    const key = (attackType || "").toLowerCase().trim();
    return ATTACK_MITIGATIONS[key] || fallbackAction || "Isolate anomalous client socket / Re-verify cryptographic session";
}

function renderAlertsTable(alerts) {
    const tbody = document.getElementById("detailed-alerts-tbody");
    if (!tbody || !alerts) return;

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr id="no-alerts-row">
            <td colspan="11" class="text-center text-muted py-4">No active attack alerts logged. All industrial communication within safe parameters.</td>
        </tr>`;
        return;
    }

    let html = "";
    alerts.forEach(a => {
        const specificMitigation = getMitigationText(a.attack_type, a.mitigation_action);
        const target = a.target || a.target_display || (a.source_device && a.source_device.includes("->") ? a.source_device.split("->").pop().trim() : "SCADA_ASSET");
        const method = a.detection_method || a.detection_method_display || (a.details && a.details.includes("IsolationForest") ? "Isolation Forest (ML)" : (a.details && a.details.includes("RandomForest") ? "Random Forest (ML)" : "Hybrid SCADA Guard"));
        const isML = method.includes("ML");
        const status = a.incident_status || a.status_display || (a.attack_type && a.attack_type.toLowerCase() === "password" ? "LOCKOUT ACTIVE" : "RECORDED");
        const isLockout = status.includes("LOCKOUT");

        html += `
        <tr>
            <td class="mono-text text-info">${a.alert_id}</td>
            <td class="mono-text" style="color: #cbd5e1; font-size: 0.8rem;">${a.timestamp}</td>
            <td><span class="badge bg-danger">${(a.attack_type || "").toUpperCase()}</span></td>
            <td class="mono-text text-light" style="font-size: 0.8rem;">${a.source_device}</td>
            <td class="mono-text text-warning" style="font-size: 0.8rem;">${target}</td>
            <td>
                <span class="badge ${a.severity === 'HIGH' || a.severity === 'CRITICAL' ? 'bg-danger' : 'bg-warning text-dark'}">
                    ${a.severity}
                </span>
            </td>
            <td>
                <span class="badge ${isML ? 'bg-primary' : 'bg-secondary'}" style="font-size: 0.72rem;">
                    ${method}
                </span>
            </td>
            <td class="text-light fw-bold mono-text">${(a.predicted_label || "").toUpperCase()}</td>
            <td>
                <span class="badge ${isLockout ? 'bg-danger' : 'bg-success'}" style="font-size: 0.7rem;">
                    ${status}
                </span>
            </td>
            <td class="text-light" style="font-size: 0.8rem;">${a.details}</td>
            <td class="text-info" style="font-size: 0.8rem;">${specificMitigation}</td>
        </tr>`;
    });
    tbody.innerHTML = html;
}

function fetchAlerts() {
    const url = `${getApiBaseUrl()}/api/alerts?limit=50`;
    fetch(url, { credentials: "include" })
        .then(res => res.json())
        .then(data => {
            if (data && data.alerts) {
                renderAlertsTable(data.alerts);
            }
        })
        .catch(err => console.debug("Alerts fetch error:", err));
}

let sseEventSource = null;

function startAlertsLiveStream() {
    // Initial fetch
    fetchAlerts();

    const badge = document.getElementById("live-indicator-badge");

    // Connect to Server-Sent Events for instant cross-laptop push updates
    if (window.EventSource) {
        try {
            const streamUrl = `${getApiBaseUrl()}/api/alerts/stream`;
            sseEventSource = new EventSource(streamUrl);

            sseEventSource.addEventListener("connected", function() {
                if (badge) {
                    badge.className = "badge bg-success ms-2";
                    badge.innerHTML = '<i class="bi bi-broadcast"></i> LIVE STREAM';
                }
            });

            sseEventSource.addEventListener("alerts_update", function(e) {
                try {
                    const alerts = JSON.parse(e.data);
                    renderAlertsTable(alerts);
                } catch (err) {
                    console.error("SSE parse error", err);
                }
            });

            sseEventSource.onerror = function() {
                if (badge) {
                    badge.className = "badge bg-warning text-dark ms-2";
                    badge.innerHTML = '<i class="bi bi-arrow-repeat"></i> POLLING (FALLBACK)';
                }
            };
        } catch (e) {
            console.warn("SSE init error, using polling", e);
        }
    }

    // Resilient periodic polling interval (every 2 seconds) as guaranteed cross-laptop fallback
    setInterval(() => {
        fetchAlerts();
    }, 2000);
}

function executeEmergencyStop() {
    if (!confirm("EMERGENCY SYSTEM HALT:\n\nTerminate all active attack simulations and restore nominal physical process baselines?")) {
        return;
    }

    const url = `${getApiBaseUrl()}/api/emergency-stop`;
    fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include"
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            alert(`✔ ${data.message}\n\nTimestamp: ${data.timestamp}\nTriggered by: ${data.triggered_by}`);
            fetchAlerts();
        } else {
            alert("Emergency stop failed: " + (data.error || "Unknown error"));
        }
    })
    .catch(err => alert("Emergency stop request error: " + err));
}

// Auto-refresh loops
function startAutoRefresh(intervalMs) {
    setInterval(() => {
        fetchTelemetryData();
    }, intervalMs);
}

function startTrafficAutoRefresh(intervalMs) {
    setInterval(() => {
        fetchTrafficEvents();
    }, intervalMs);
}

function startAlertsAutoRefresh(intervalMs) {
    startAlertsLiveStream();
}
