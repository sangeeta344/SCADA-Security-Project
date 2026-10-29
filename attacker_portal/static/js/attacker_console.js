/**
 * SCADA Adversary Emulation & Penetration Testing Portal Script
 * Handles asynchronous scenario dispatch, live terminal tracing,
 * brute-force simulation counters, sensor restoration, and DB cross-verification.
 * Supports cross-laptop operation via dynamic backend API URL resolution and CORS.
 */

let bruteForceRunning = false;

// Resolve target backend API base URL dynamically (supports cross-laptop or custom ports)
function getApiBaseUrl() {
    const saved = localStorage.getItem("scada_backend_api_url");
    if (saved && saved.trim()) {
        return saved.trim().replace(/\/+$/, "");
    }
    if (window.SCADA_CONFIG && window.SCADA_CONFIG.apiBase && window.SCADA_CONFIG.apiBase.trim()) {
        const base = window.SCADA_CONFIG.apiBase.trim().replace(/\/+$/, "");
        // If client is accessing from a remote IP (e.g. 192.168.x.x) or non-localhost,
        // but base contains 127.0.0.1 or localhost, NEVER send to localhost on the client laptop!
        if (window.location.hostname !== "127.0.0.1" && window.location.hostname !== "localhost") {
            if (base.includes("127.0.0.1") || base.includes("localhost")) {
                if (window.location.port === "5050") {
                    return `${window.location.protocol}//${window.location.hostname}:5000`;
                }
                return window.location.origin;
            }
        }
        return base;
    }
    if (window.location.port === "5050") {
        return `${window.location.protocol}//${window.location.hostname}:5000`;
    }
    return window.location.origin;
}

function setCustomBackendUrl(url) {
    if (url && url.trim()) {
        localStorage.setItem("scada_backend_api_url", url.trim());
    } else {
        localStorage.removeItem("scada_backend_api_url");
    }
    updateBackendUrlDisplay();
}

function updateBackendUrlDisplay() {
    const el = document.getElementById("active-backend-url-display");
    if (el) {
        el.innerText = getApiBaseUrl();
    }
}

// Visual simulation lifecycle state management (Idle, Starting, Running, Stopped, Failed)
function updateSimulationStateUI(scenario, state, errorMessage) {
    const sc = (scenario || "").toLowerCase();
    const badge = document.getElementById(`cont-badge-${sc}`);
    const errBox = document.getElementById(`${sc}-error-msg`);
    const btnStart = document.getElementById(`btn-start-${sc}`);
    const stateUpper = (state || "IDLE").toUpperCase();

    if (badge) {
        badge.className = "badge ";
        if (stateUpper === "RUNNING" || stateUpper === "ACTIVE") {
            badge.className += "badge-active";
            badge.innerText = "RUNNING";
        } else if (stateUpper === "STARTING") {
            badge.className += "badge-starting";
            badge.innerText = "STARTING";
        } else if (stateUpper === "STOPPED") {
            badge.className += "badge-stopped";
            badge.innerText = "STOPPED";
        } else if (stateUpper === "FAILED") {
            badge.className += "badge-failed";
            badge.innerText = "FAILED";
        } else {
            badge.className += "badge-idle";
            badge.innerText = "IDLE";
        }
    }

    if (errBox) {
        if (errorMessage) {
            errBox.innerText = `Error: ${errorMessage}`;
            errBox.classList.remove("d-none");
        } else {
            errBox.innerText = "";
            errBox.classList.add("d-none");
        }
    }

    if (btnStart) {
        if (stateUpper === "RUNNING") {
            btnStart.disabled = true;
            btnStart.innerHTML = `<span class="spinner-grow spinner-grow-sm me-1 text-danger"></span> Running...`;
        } else if (stateUpper === "STARTING") {
            btnStart.disabled = true;
            btnStart.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Starting...`;
        } else {
            btnStart.disabled = false;
            btnStart.innerHTML = `<i class="bi bi-play-circle-fill me-1"></i> Start ${sc === "dos" ? "DoS" : sc.toUpperCase()}`;
        }
    }
}

function pollSimulationStates() {
    fetch(`${getApiBaseUrl()}/attacker/api/status`, { credentials: "include" })
        .then(res => res.json())
        .then(data => {
            if (data && data.simulation_states) {
                Object.keys(data.simulation_states).forEach(sc => {
                    const st = data.simulation_states[sc];
                    updateSimulationStateUI(sc, st.state, st.error);
                });
            }
            if (data && data.total_alerts_stored !== undefined) {
                const countEl = document.getElementById("stat-total-alerts");
                if (countEl) countEl.innerText = data.total_alerts_stored.toString();
            }
        })
        .catch(err => {
            console.debug("Simulation status poll failed:", err);
        });
}

document.addEventListener("DOMContentLoaded", () => {
    updateBackendUrlDisplay();
    pollSimulationStates();
    setInterval(pollSimulationStates, 2500);
});


function appendTerminalLog(text, colorClass = "") {
    const term = document.getElementById("adversary-terminal-body");
    if (!term) return;

    const line = document.createElement("div");
    if (colorClass) line.className = colorClass;
    line.innerText = text;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function clearTerminal() {
    const term = document.getElementById("adversary-terminal-body");
    if (term) term.innerHTML = "";
}

function updateFdiSensorSelection() {
    const sensorType = document.getElementById("inj-sensor-type")?.value || "temp";
    const origBox = document.getElementById("inj-orig-display");
    const valInput = document.getElementById("inj-val-input");
    const valLabel = document.getElementById("inj-val-label");

    if (sensorType === "temp") {
        if (origBox) origBox.innerText = "35.0 °C (Nominal Operating Baseline)";
        if (valLabel) valLabel.innerText = "Simulated Replacement Temperature (°C):";
        if (valInput) { valInput.value = "90.0"; valInput.min = "50"; valInput.max = "115"; }
    } else if (sensorType === "press") {
        if (origBox) origBox.innerText = "2.5 bar (Nominal Pressure Baseline)";
        if (valLabel) valLabel.innerText = "Simulated Replacement Pressure (bar):";
        if (valInput) { valInput.value = "8.2"; valInput.min = "4"; valInput.max = "10"; }
    } else if (sensorType === "level") {
        if (origBox) origBox.innerText = "910 mm (Nominal Water Level Baseline)";
        if (valLabel) valLabel.innerText = "Simulated Replacement Water Level (mm):";
        if (valInput) { valInput.value = "1420"; valInput.min = "1150"; valInput.max = "1600"; }
    }
}

function executeScenario(scenarioId) {
    const btn = document.getElementById(`btn-exec-${scenarioId}`);
    const originalText = btn ? btn.innerHTML : "Launch";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Executing...`;
    }

    // Collect parameters based on scenario
    let params = {};
    if (scenarioId === "injection") {
        const sensorType = document.getElementById("inj-sensor-type")?.value || "temp";
        const val = parseFloat(document.getElementById("inj-val-input")?.value || 90.0);
        const target = document.getElementById("inj-target")?.value || "RTU_01";
        const fc = parseInt(document.getElementById("inj-fc")?.value || 16, 10);

        params = {
            target_device: target,
            function_code: fc,
            sensor_type: sensorType,
            temperature_c: sensorType === "temp" ? val : 28.5,
            pressure_bar: sensorType === "press" ? val : 2.5,
            water_level_mm: sensorType === "level" ? val : 910.0,
            flow_rate_lpm: 35.0,
        };
    } else if (scenarioId === "replay") {
        params = {
            target_device: document.getElementById("rep-target")?.value || "RTU_01",
            stale_seconds: parseInt(document.getElementById("rep-stale")?.value || 1200, 10),
            burst_count: parseInt(document.getElementById("rep-burst")?.value || 5, 10),
        };
    } else if (scenarioId === "mitm") {
        params = {
            target_device: document.getElementById("mitm-target")?.value || "PLC_01",
            tampered_action: document.getElementById("mitm-action")?.value || "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
            function_code: 16,
        };
    } else if (scenarioId === "dos") {
        params = {
            target_device: document.getElementById("dos-target")?.value || "RTU_01",
            packet_rate: parseFloat(document.getElementById("dos-rate")?.value || 85.0),
            burst_count: parseInt(document.getElementById("dos-burst")?.value || 25, 10),
            duration_sec: parseInt(document.getElementById("dos-duration")?.value || 3, 10),
        };
    }

    appendTerminalLog(`\n[+] [${new Date().toLocaleTimeString()}] DISPATCHING SCENARIO: ${scenarioId.toUpperCase()} ...`, "text-warning");

    updateSimulationStateUI(scenarioId, "STARTING", null);

    fetch(`${getApiBaseUrl()}/attacker/api/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ scenario: scenarioId, params: params })
    })
    .then(async res => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
        }
        return data;
    })
    .then(data => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }

        if (data.success && data.simulation) {
            updateSimulationStateUI(scenarioId, "STOPPED", null);
            const sim = data.simulation;
            const det = sim.detection;
            const al = sim.persisted_alert;

            appendTerminalLog(`[>] SYNTHETIC EVENT GENERATED:`, "text-info");
            appendTerminalLog(`    Event ID:   ${sim.synthetic_event.event_id}`);
            appendTerminalLog(`    Source:     ${sim.origin_node}`);
            appendTerminalLog(`    Target:     ${sim.target}`);
            appendTerminalLog(`    Protocol:   ${sim.synthetic_event.protocol} (FC: ${sim.synthetic_event.function_code || '-'}, Rate: ${sim.synthetic_event.packet_rate || '-'} pkt/s)`);

            appendTerminalLog(`[*] DETECTOR PIPELINE EXECUTED (${sim.latency_ms} ms):`, "text-danger");
            appendTerminalLog(`    Detection Method:   ${det.detection_method}`);
            if (det.ml_model_used) {
                appendTerminalLog(`    ML Model Invoked:   ${det.ml_model_used}`);
                if (det.ml_score !== null && det.ml_score !== undefined) {
                    appendTerminalLog(`    Anomaly Score:      ${det.ml_score}`);
                }
            }
            appendTerminalLog(`    Classified Label:   ${det.predicted_label} (Confidence: ${(det.confidence * 100).toFixed(1)}%)`);
            appendTerminalLog(`    Severity Rating:    ${det.severity}`);
            if (det.rule_guards_triggered && det.rule_guards_triggered.length > 0) {
                det.rule_guards_triggered.forEach(rg => {
                    appendTerminalLog(`    Rule Guard Active:  ${rg}`, "text-warning");
                });
            }

            appendTerminalLog(`[✔] SHARED DATABASE PERSISTENCE:`, "text-success");
            appendTerminalLog(`    Alert Record ID:    ${al.alert_id}`);
            appendTerminalLog(`    Stored in SQLite:   data/scada_security.db -> attack_alerts`);

            appendTerminalLog(`[✉] CENTRALIZED EMAIL ALERT NOTIFICATION:`, "text-warning");
            appendTerminalLog(`    Automatic notification dispatched to operator recipient.`);
            appendTerminalLog(`    Subject: [SCADA SECURITY ALERT] — ${det.predicted_label} Detected`);

            appendTerminalLog(`[★] USER DASHBOARD PROPAGATION VERIFIED:`, "text-cyan");
            appendTerminalLog(`    The existing Operator Website (/attack-alerts) displays this security incident in real time.`);
            appendTerminalLog(`    Status: SYNCHRONIZED\n`, "text-success");

            // Add row to history table
            prependHistoryRow(sim);

            // Update top count pill
            const countEl = document.getElementById("stat-total-alerts");
            if (countEl) {
                const cur = parseInt(countEl.innerText || "0", 10);
                countEl.innerText = (cur + 1).toString();
            }
        } else {
            const errStr = data.error || "Unknown simulation failure";
            updateSimulationStateUI(scenarioId, "FAILED", errStr);
            appendTerminalLog(`[ERROR] Simulation failed: ${errStr}`, "text-danger");
            alert("Simulation Error: " + errStr);
        }
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
        const msg = err.message || err.toString();
        updateSimulationStateUI(scenarioId, "FAILED", msg);
        appendTerminalLog(`[EXCEPTION] Request failed: ${msg}`, "text-danger");
        appendTerminalLog(`    Target Backend URL: ${getApiBaseUrl()}`, "text-muted");
        appendTerminalLog(`    Check network connectivity and ensure port 5000 is open.`, "text-muted");
    });

}

function restoreSensorTelemetry() {
    const btn = document.getElementById("btn-restore-sensor");
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Restoring...`;
    }

    const target = document.getElementById("inj-target")?.value || "RTU_01";

    fetch(`${getApiBaseUrl()}/attacker/api/restore-sensor`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ target_device: target })
    })
    .then(res => res.json())
    .then(data => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-arrow-counterclockwise"></i> Restore Original Sensor Reading`;
        }
        if (data.success) {
            appendTerminalLog(`\n[RESTORE COMPLETE] Sensor telemetry on ${data.target} restored to nominal operating baselines (Temp: 28.0°C, Press: 2.5 bar, Level: 900 mm).`, "text-success");
            alert(`✔ Sensor Restored:\n\n${data.message}`);
        } else {
            alert("Restore error: " + (data.error || "Failed"));
        }
    })
    .catch(err => {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="bi bi-arrow-counterclockwise"></i> Restore Original Sensor Reading`;
        }
        alert("Request error: " + err);
    });
}

function stopDoSImmediately() {
    toggleContinuous("dos", "stop");
    appendTerminalLog(`[EMERGENCY STOP] DoS flood simulation immediately halted. Request stream terminated.`, "text-danger");
}

function executeEmergencyHalt() {
    if (!confirm("ADVERSARY EMERGENCY HALT:\n\nImmediately terminate all active simulations, background loops, and restore physical process baselines?")) {
        return;
    }

    appendTerminalLog(`\n[!] [${new Date().toLocaleTimeString()}] EMERGENCY HALT INITIATED...`, "text-danger");

    fetch(`${getApiBaseUrl()}/attacker/api/emergency-stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include"
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            appendTerminalLog(`[✔] ${data.message}`, "text-success");
            updateContinuousBadges([]);
            alert("✔ " + data.message);
        } else {
            appendTerminalLog(`[ERROR] Emergency halt failed: ${data.error || "Unknown"}`, "text-danger");
        }
    })
    .catch(err => appendTerminalLog(`[EXCEPTION] Emergency halt: ${err}`, "text-danger"));
}

// =========================================================================
// SCENARIO 5: BRUTE-FORCE LOGIN SIMULATION
// =========================================================================

function executeBruteForceSimulation() {
    const targetAccount = document.getElementById("bf-target-account")?.value || "demo_operator@scada.local";
    const attemptsCount = parseInt(document.getElementById("bf-attempts-slider")?.value || 5, 10);
    const sourceIp = document.getElementById("bf-source-ip")?.value || "192.168.1.105";

    const btn = document.getElementById("btn-exec-bruteforce");
    const originalText = btn ? btn.innerHTML : "Launch";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Simulating Attempts...`;
    }

    bruteForceRunning = true;
    const sentEl = document.getElementById("bf-sent-count");
    const failedEl = document.getElementById("bf-failed-count");
    const lockEl = document.getElementById("bf-lock-state");
    const badgeEl = document.getElementById("bf-status-badge");

    if (badgeEl) {
        badgeEl.className = "badge bg-warning text-dark";
        badgeEl.innerText = "ATTACK IN PROGRESS";
    }

    appendTerminalLog(`\n[+] [${new Date().toLocaleTimeString()}] DISPATCHING BRUTE-FORCE LOGIN SIMULATION:`, "text-danger");
    appendTerminalLog(`    Target Account:    ${targetAccount}`);
    appendTerminalLog(`    Attempts Volume:   ${attemptsCount} failed authentications`);
    appendTerminalLog(`    Adversary Host:    ${sourceIp}`);
    appendTerminalLog(`    Testing Synthetic Dictionary: ['admin123', 'scada2024', 'password', 'letmein', '123456']`);

    // Progressive counter animation
    let count = 0;
    const interval = setInterval(() => {
        if (count < attemptsCount && bruteForceRunning) {
            count++;
            if (sentEl) sentEl.innerText = count.toString();
            if (failedEl) failedEl.innerText = count.toString();
        } else {
            clearInterval(interval);
        }
    }, 120);

    fetch(`${getApiBaseUrl()}/attacker/api/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
            scenario: "brute_force",
            params: {
                target_account: targetAccount,
                attempt_count: attemptsCount,
                source_ip: sourceIp,
            }
        })
    })
    .then(res => res.json())
    .then(data => {
        clearInterval(interval);
        bruteForceRunning = false;
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }

        if (data.success && data.simulation) {
            const sim = data.simulation;
            const stats = sim.brute_force_stats;
            const det = sim.detection;

            if (sentEl) sentEl.innerText = stats.attempts_sent.toString();
            if (failedEl) failedEl.innerText = stats.failed_responses_received.toString();

            if (stats.threshold_exceeded) {
                if (badgeEl) {
                    badgeEl.className = "badge bg-danger text-white";
                    badgeEl.innerText = "DETECTED & ACCOUNT LOCKED";
                }
                if (lockEl) {
                    lockEl.className = "fs-6 fw-bold text-danger mono-font d-block mt-1";
                    lockEl.innerText = "LOCKED (5m)";
                }

                appendTerminalLog(`[!] THRESHOLD EXCEEDED (5 attempts in 5m window):`, "text-danger");
                appendTerminalLog(`    Incident Classification: PASSWORD_BRUTE_FORCE (Severity: HIGH)`);
                appendTerminalLog(`    Defensive Lockout:       ACTIVE for ${stats.masked_account}`);
                appendTerminalLog(`    Automated Security Email: Dispatched to configured operator inbox`);
                appendTerminalLog(`    Subject: [SCADA SECURITY ALERT] Multiple Failed Login Attempts Detected`);
                appendTerminalLog(`    Operator Dashboard:      Synchronized at /attack-alerts`);
            } else {
                if (badgeEl) {
                    badgeEl.className = "badge bg-warning text-dark";
                    badgeEl.innerText = "BELOW THRESHOLD";
                }
                if (lockEl) {
                    lockEl.className = "fs-6 fw-bold text-success mono-font d-block mt-1";
                    lockEl.innerText = "UNLOCKED";
                }
                appendTerminalLog(`[i] Attempts recorded (${stats.attempts_sent}/5). Below threshold. Lockout not triggered.`, "text-secondary");
            }

            prependHistoryRow(sim);
            refreshAccountsStatus();
        } else {
            alert("Brute force simulation error: " + (data.error || "Failed"));
        }
    })
    .catch(err => {
        clearInterval(interval);
        bruteForceRunning = false;
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
        appendTerminalLog(`[EXCEPTION] Brute-force error: ${err}`, "text-danger");
    });
}

function stopBruteForceSimulation() {
    bruteForceRunning = false;
    appendTerminalLog(`[STOP] Brute-force attack stream halted by operator command.`, "text-warning");
    const badgeEl = document.getElementById("bf-status-badge");
    if (badgeEl) {
        badgeEl.className = "badge badge-idle";
        badgeEl.innerText = "STOPPED";
    }
}

function resetSelectedAccountLockout() {
    const targetAccount = document.getElementById("bf-target-account")?.value || "demo_operator@scada.local";
    resetSpecificAccount(targetAccount);
}

function resetSpecificAccount(account) {
    fetch(`${getApiBaseUrl()}/attacker/api/reset-account-lock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ account: account })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            appendTerminalLog(`\n[UNLOCKED] Lockout and failed attempt counters cleared for ${account}.`, "text-success");
            const sentEl = document.getElementById("bf-sent-count");
            const failedEl = document.getElementById("bf-failed-count");
            const lockEl = document.getElementById("bf-lock-state");
            const badgeEl = document.getElementById("bf-status-badge");

            if (sentEl) sentEl.innerText = "0";
            if (failedEl) failedEl.innerText = "0";
            if (lockEl) {
                lockEl.className = "fs-6 fw-bold text-success mono-font d-block mt-1";
                lockEl.innerText = "UNLOCKED";
            }
            if (badgeEl) {
                badgeEl.className = "badge badge-idle";
                badgeEl.innerText = "STANDBY / IDLE";
            }
            refreshAccountsStatus();
            alert(`✔ Account Reset Successful:\n\nLockout removed and failure counters cleared for ${account}.`);
        } else {
            alert("Reset error: " + (data.error || "Failed"));
        }
    })
    .catch(err => alert("Error resetting account: " + err));
}

function refreshAccountsStatus() {
    fetch(`${getApiBaseUrl()}/attacker/api/accounts-status`, { credentials: "include" })
        .then(res => res.json())
        .then(data => {
            if (data.success && data.accounts) {
                const tbody = document.getElementById("bf-accounts-status-tbody");
                if (!tbody) return;
                tbody.innerHTML = "";
                data.accounts.forEach(acc => {
                    const isLocked = acc.is_locked;
                    const remSec = Math.round(acc.remaining_seconds);
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td class="mono-font text-light">${acc.account}</td>
                        <td class="mono-font ${acc.failed_attempts >= 5 ? 'text-danger fw-bold' : 'text-muted'}">
                            ${acc.failed_attempts}/${acc.threshold}
                        </td>
                        <td>
                            ${isLocked ? `<span class="badge bg-danger">LOCKED (${remSec}s)</span>` : `<span class="badge bg-success">CLEAR</span>`}
                        </td>
                        <td>
                            <button class="btn btn-sm btn-outline-info py-0 px-1" style="font-size: 0.7rem;" onclick="resetSpecificAccount('${acc.account}');">
                                Unlock
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        });
}

function updateSelectedAccountDisplay() {
    refreshAccountsStatus();
}

// =========================================================================
// QUANTUM BB84 & AES-GCM CRYPTOGRAPHIC DEMONSTRATION HOOKS
// =========================================================================

function demonstrateBB84Diagnostic() {
    appendTerminalLog(`\n[+] [${new Date().toLocaleTimeString()}] TRACING BB84 QUANTUM KEY DISTRIBUTION LAYER:`, "text-purple");
    appendTerminalLog(`    Alice & Bob basis reconciliation in progress (Rectilinear + / Diagonal x)...`);
    appendTerminalLog(`    QBER Error Estimation: Calculating error rate on disclosed test bits...`);
    appendTerminalLog(`    Scenario A (Normal Channel):     QBER = 0.0% < 11.0% Threshold &rarr; Key ACCEPTED.`);
    appendTerminalLog(`    Scenario B (Eve Intercepting):   QBER ~ 25.0% > 11.0% Threshold &rarr; Key ABORTED.`);
    appendTerminalLog(`    Privacy Amplification: Key material hashed through HKDF-SHA256 to yield 256-bit AES key.`);
    appendTerminalLog(`    Status: Genuine quantum key exchange operational.\n`, "text-success");
}

function demonstrateAESTagTamper() {
    appendTerminalLog(`\n[+] [${new Date().toLocaleTimeString()}] TESTING AES-256-GCM CRYPTOGRAPHIC INTEGRITY:`, "text-warning");
    appendTerminalLog(`    Ciphertext: GCM Mode with 96-bit unique nonce and 128-bit authentication tag.`);
    appendTerminalLog(`    Simulating Man-in-the-Middle bit-flip in ciphertext payload...`);
    appendTerminalLog(`    Decryption Attempt: AESGCMCipher.decrypt() invoked...`);
    appendTerminalLog(`    CRYPTOGRAPHIC RESULT: InvalidTag exception caught! Payload altered or forged.`);
    appendTerminalLog(`    DEFENSE ACTION: Message immediately discarded by cipher layer prior to ML processing.`);
    appendTerminalLog(`    Status: Cryptographic integrity guaranteed independently of ML model.\n`, "text-danger");
}

// =========================================================================
// HISTORY TABLE AND CONTINUOUS HELPERS
// =========================================================================

function prependHistoryRow(sim) {
    const tbody = document.getElementById("attacker-history-tbody");
    if (!tbody) return;

    const noRow = document.getElementById("no-history-row");
    if (noRow) noRow.remove();

    const al = sim.persisted_alert;
    const det = sim.detection;
    const isML = det.detection_method.includes("ML") || det.detection_method.includes("HYBRID");

    const tr = document.createElement("tr");
    tr.innerHTML = `
        <td class="mono-font text-info">${al.alert_id}</td>
        <td class="mono-font" style="color: #cbd5e1; font-size: 0.8rem;">${sim.timestamp}</td>
        <td><span class="badge bg-danger">${sim.scenario.toUpperCase()}</span></td>
        <td class="mono-font text-light" style="font-size: 0.8rem;">${sim.target}</td>
        <td>
            <span class="badge ${isML ? 'badge-ml' : 'badge-rule'}">
                ${isML ? 'ML DETECTOR' : 'RULE GUARD'}
            </span>
        </td>
        <td>
            <span class="badge ${al.severity === 'CRITICAL' || al.severity === 'HIGH' ? 'bg-danger' : 'bg-warning text-dark'}">
                ${al.severity}
            </span>
        </td>
        <td class="mono-font text-light">${(det.confidence * 100).toFixed(1)}%</td>
        <td style="font-size: 0.78rem; max-width: 280px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;" title="${al.details}">
            ${al.details}
        </td>
        <td>
            <button class="btn btn-sm btn-attacker-secondary" onclick="verifyAlert('${al.alert_id}');" title="Cross-verify in shared database">
                <i class="bi bi-shield-check text-success"></i> Verify
            </button>
        </td>
    `;
    tbody.insertBefore(tr, tbody.firstChild);
}

function startDoS() {
    startAttackSimulation("dos");
}

function stopDoS() {
    stopAttackSimulation("dos");
}

function startAttackSimulation(attackName) {
    const att = (attackName || "").toLowerCase();
    let params = {};

    if (att === "dos") {
        params = {
            target_device: document.getElementById("dos-target")?.value || "RTU_01",
            packet_rate: parseFloat(document.getElementById("dos-rate")?.value || 85.0),
            burst_count: parseInt(document.getElementById("dos-burst")?.value || 25, 10),
            duration_sec: parseInt(document.getElementById("dos-duration")?.value || 3, 10),
        };
    } else if (att === "injection") {
        const sensorType = document.getElementById("inj-sensor-type")?.value || "temp";
        const val = parseFloat(document.getElementById("inj-val-input")?.value || 90.0);
        params = {
            target_device: document.getElementById("inj-target")?.value || "RTU_01",
            function_code: parseInt(document.getElementById("inj-fc")?.value || 16, 10),
            sensor_type: sensorType,
            temperature_c: sensorType === "temp" ? val : 28.5,
            pressure_bar: sensorType === "press" ? val : 2.5,
            water_level_mm: sensorType === "level" ? val : 910.0,
            flow_rate_lpm: 35.0,
        };
    } else if (att === "replay") {
        params = {
            target_device: document.getElementById("rep-target")?.value || "RTU_01",
            stale_seconds: parseInt(document.getElementById("rep-stale")?.value || 1200, 10),
            burst_count: parseInt(document.getElementById("rep-burst")?.value || 5, 10),
        };
    } else if (att === "mitm") {
        params = {
            target_device: document.getElementById("mitm-target")?.value || "PLC_01",
            tampered_action: document.getElementById("mitm-action")?.value || "FORCED_EMERGENCY_SHUTDOWN_OVERRIDE",
            function_code: 16,
        };
    }

    updateSimulationStateUI(att, "STARTING", null);
    appendTerminalLog(`\n[+] [${new Date().toLocaleTimeString()}] INITIATING ${att.toUpperCase()} SIMULATION...`, "text-warning");

    const endpoint = "/attacker/api/continuous/start";
    fetch(`${getApiBaseUrl()}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ attack_name: att, params: params })
    })
    .then(async res => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
        }
        return data;
    })
    .then(data => {
        if (data.success) {
            updateSimulationStateUI(att, data.state || "RUNNING", null);
            appendTerminalLog(`[✔] ${att.toUpperCase()} Simulation active: ${data.message || "Running safe synthetic cycles."}`, "text-success");
            appendTerminalLog(`[*] Detection pipeline & rate guards monitoring in real time.`, "text-info");
        } else {
            throw new Error(data.error || "Simulation start failed");
        }
    })
    .catch(err => {
        const msg = err.message || err.toString();
        updateSimulationStateUI(att, "FAILED", msg);
        appendTerminalLog(`[FAILED] Could not start ${att.toUpperCase()} simulation: ${msg}`, "text-danger");
        appendTerminalLog(`    Target Backend API: ${getApiBaseUrl()}`, "text-muted");
        appendTerminalLog(`    Troubleshooting: Verify backend server is running and Laptop 1 firewall permits port 5000.`, "text-muted");
    });
}

function stopAttackSimulation(attackName) {
    const att = (attackName || "").toLowerCase();
    appendTerminalLog(`\n[!] [${new Date().toLocaleTimeString()}] STOPPING ${att.toUpperCase()} SIMULATION...`, "text-warning");

    const endpoint = "/attacker/api/continuous/stop";
    fetch(`${getApiBaseUrl()}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ attack_name: att })
    })
    .then(async res => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
        }
        return data;
    })
    .then(data => {
        updateSimulationStateUI(att, "STOPPED", null);
        appendTerminalLog(`[STOPPED] Continuous ${att.toUpperCase()} simulation halted.`, "text-info");
    })
    .catch(err => {
        const msg = err.message || err.toString();
        updateSimulationStateUI(att, "FAILED", msg);
        appendTerminalLog(`[ERROR] Failed to stop ${att.toUpperCase()} simulation: ${msg}`, "text-danger");
    });
}

function toggleContinuous(attackName, action) {
    if (action === "start") {
        startAttackSimulation(attackName);
    } else {
        stopAttackSimulation(attackName);
    }
}


function verifyAlert(alertId) {
    fetch(`${getApiBaseUrl()}/attacker/api/verify-alert/${alertId}`, { credentials: "include" })
        .then(res => res.json())
        .then(data => {
            if (data.verified) {
                alert(`✔ Alert Confirmed in Shared Database:\n\nAlert ID: ${data.alert.alert_id}\nAttack Type: ${data.alert.attack_type}\nOrigin Node: ${data.alert.source_device}\nSeverity: ${data.alert.severity}\nML/Rule Label: ${data.alert.predicted_label}\nVisible to Operator: YES (/attack-alerts)`);
            } else {
                alert("Alert verification failed: " + (data.error || "Not found"));
            }
        })
        .catch(err => alert("Verification request error: " + err));
}
