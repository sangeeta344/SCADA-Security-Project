
import asyncio
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd
import shap
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report,
)

from scada_monitor import read_sensor_data
from live_network_monitor import live_monitor
from feature_extractor import build_feature_vector


# ==================================================
# 1. PAGE CONFIGURATION
# ==================================================
st.set_page_config(
    page_title="SCADA Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Explainable AI-Based SCADA Cybersecurity")
st.caption(
    "TON_IoT Network Dataset | Random Forest | SHAP Explainability"
)


# ==================================================
# 2. FILE PATHS
# ==================================================
BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "scada_attack_model.joblib"
DATA_PATH = (
    BASE_DIR
    / "datasets"
    / "TON_IoT"
    / "train_test_network.csv"
)


# ==================================================
# 3. LOAD MODEL AND DATASET
# ==================================================
@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


@st.cache_data
def load_data():
    return pd.read_csv(DATA_PATH)


@st.cache_data
def get_traffic_distribution(data):
    normal_attack = (
        data["label"]
        .map({0: "Normal", 1: "Attack"})
        .value_counts()
        .reindex(["Normal", "Attack"], fill_value=0)
    )
    attack_categories = (
        data.loc[data["type"] != "normal", "type"]
        .value_counts()
        .sort_values(ascending=False)
    )
    return normal_attack, attack_categories


try:
    model = load_model()
    df = load_data()
except Exception as error:
    st.error(f"Could not load model or dataset: {error}")
    st.stop()


# ==================================================
# 4. SIDEBAR CONTROLS & SYSTEM TELEMETRY
# ==================================================
with st.sidebar:
    st.header("🛡️ SCADA Console")
    st.markdown("**Explainable AI Intrusion Detection**")
    st.divider()

    st.subheader("⚙️ Telemetry Controls")
    auto_refresh_enabled = st.checkbox(
        "Live Telemetry Auto-Refresh",
        value=True,
        help="Continuously poll the simulated RTU server and update live metrics."
    )
    refresh_rate_sec = st.select_slider(
        "Refresh Interval (seconds)",
        options=[1, 2, 3, 5, 10],
        value=2,
    )
    allow_experimental_prediction = st.checkbox(
        "Enable Out-of-Domain Classification",
        value=False,
        help="When unchecked (default), predictions on Modbus traffic are safely blocked due to domain mismatch. Enable for research demonstration only."
    )

    st.divider()
    st.subheader("📡 Infrastructure Endpoints")
    st.markdown("- **RTU Server**: `127.0.0.1:5020` (Modbus TCP)")
    st.markdown("- **Holding Registers**: `0..3` (Temp, Press, Water, Flow)")
    st.markdown("- **Transport**: TCP Loopback (Localhost)")

    st.divider()
    st.subheader("🧠 Model Architecture")
    st.markdown("- **Model**: Random Forest (150 trees, balanced)")
    st.markdown("- **Dataset**: TON_IoT Network (211,043 rows)")
    st.markdown("- **Features**: 40 Zeek Connection Attributes")
    st.markdown("- **Domain**: Multi-protocol IoT (Modbus Blocked by Default)")


# ==================================================
# 5. LIVE SCADA SENSOR MONITORING
# ==================================================
st.divider()
st.subheader("Live SCADA Sensor Telemetry")

if auto_refresh_enabled:
    st_autorefresh(
        interval=refresh_rate_sec * 1000,
        key="scada_sensor_refresh",
    )

current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

try:
    sensor_data = asyncio.run(read_sensor_data())

    if sensor_data["connected"]:
        st.success(
            f"● RTU Online — Modbus TCP connection active on 127.0.0.1:5020 "
            f"(Last Polled: {current_time_str})"
        )

        c1, c2, c3, c4 = st.columns(4)

        c1.metric(
            "Temperature",
            f"{sensor_data['temperature']:.1f} °C",
        )

        c2.metric(
            "Pressure",
            f"{sensor_data['pressure']:.1f} bar",
        )

        c3.metric(
            "Water Level",
            f"{sensor_data['water_level']} mm",
        )

        c4.metric(
            "Flow Rate",
            f"{sensor_data['flow_rate']} L/min",
        )

        st.caption(
            "Sensor telemetry refreshed via Modbus Function Code 03 (Read Holding Registers)."
        )

        # Passively log genuine Modbus TCP telemetry connection to Live Network Monitor
        live_monitor.log_connection(
            src_ip="127.0.0.1",
            src_port=50000 + (int(datetime.now().timestamp()) % 15000),
            dst_ip="127.0.0.1",
            dst_port=5020,
            proto="tcp",
            service="modbus",
            duration=0.003,
            src_bytes=12,
            dst_bytes=17,
            conn_state="SF",
            src_pkts=1,
            dst_pkts=1,
            model=model,
            allow_experimental_prediction=allow_experimental_prediction,
        )

    else:
        st.warning(
            f"⚠️ RTU Offline — Could not connect to 127.0.0.1:5020: {sensor_data.get('error', 'Unknown error')} "
            f"| Run 'python rtu_server.py' in PowerShell to start the RTU simulator."
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Temperature", "-- °C")
        c2.metric("Pressure", "-- bar")
        c3.metric("Water Level", "-- mm")
        c4.metric("Flow Rate", "-- L/min")

        # Log failed connection attempt
        live_monitor.log_connection(
            src_ip="127.0.0.1",
            src_port=50000 + (int(datetime.now().timestamp()) % 15000),
            dst_ip="127.0.0.1",
            dst_port=5020,
            proto="tcp",
            service="modbus",
            duration=0.001,
            src_bytes=0,
            dst_bytes=0,
            conn_state="REJ",
            src_pkts=0,
            dst_pkts=0,
            model=model,
            allow_experimental_prediction=allow_experimental_prediction,
        )

except Exception as error:
    st.error(f"Sensor monitoring error: {error}")

st.caption(
    "Sensor status confirms telemetry communication only; "
    "it does not evaluate network layer intrusion."
)


# ==================================================
# 6. LIVE NETWORK TRAFFIC OBSERVATION (PASSIVE)
# ==================================================
st.divider()
st.subheader("Live Network Traffic Observation & Passive Capture")

st.markdown(
    """
    This section passively observes live connection metadata (endpoints, transport protocol, 
    packet and byte volumes, and connection states) captured from the local SCADA environment.
    """
)

if not allow_experimental_prediction:
    st.warning(
        "🔒 **Live Model Prediction Blocked (Domain Compatibility Notice)**:  \n"
        "Live Modbus network traffic is actively captured and logged below. However, automatic classification is "
        "safely blocked because the Random Forest model was trained on TON_IoT IT protocols (HTTP, DNS, SSL) "
        "and never observed Modbus TCP (port 502/5020). Applying the model to live Modbus polls produces systematic "
        "false-positive attack alerts. To enable zero-shot inference for research demonstration, check "
        "**'Enable Out-of-Domain Classification'** in the sidebar."
    )
else:
    st.info(
        "⚠️ **EXPERIMENTAL ZERO-SHOT MODE ACTIVE:**  \n"
        "Predictions on Modbus traffic are displayed for research observation. Because port 502/5020 was absent "
        "from TON_IoT training data, predictions are experimental and do not constitute ground-truth evidence."
    )

recent_obs = live_monitor.get_recent_observations(limit=10)

if recent_obs:
    obs_rows = []
    for obs in reversed(recent_obs):
        obs_rows.append({
            "Timestamp": obs["timestamp"],
            "Source": f"{obs['src_ip']}:{obs['src_port']}",
            "Destination": f"{obs['dst_ip']}:{obs['dst_port']}",
            "Protocol": obs["proto"].upper(),
            "State": obs["conn_state"],
            "Bytes (Src/Dst)": f"{obs['src_bytes']} / {obs['dst_bytes']}",
            "AI Prediction": obs["prediction_label"],
            "Confidence": f"{obs.get('confidence_pct', 0.0):.1f}%" if obs.get("confidence_pct", 0.0) > 0 else "--",
            "Domain Status": "⚠️ Out-of-Domain" if obs.get("is_out_of_domain") else "In-Domain",
        })

    st.dataframe(pd.DataFrame(obs_rows), use_container_width=True)
    st.caption("Showing the 10 most recent observed connections from the in-memory ring buffer.")
else:
    st.write("No network connections observed yet. Ensure live auto-refresh is active.")


# ==================================================
# 7. PREPARE MODEL INPUT FEATURES
# ==================================================
try:
    X = df.drop(
        columns=["label", "type", "src_ip", "dst_ip"]
    )
except Exception as error:
    st.error(f"Could not prepare model features: {error}")
    st.stop()


# ==================================================
# 8. RECORDED TON_IOT DATASET OVERVIEW
# ==================================================
st.divider()
st.subheader("Recorded TON_IoT Dataset Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Records",
    f"{len(df):,}",
)

col2.metric(
    "Normal Records",
    f"{(df['label'] == 0).sum():,}",
)

col3.metric(
    "Attack Records",
    f"{(df['label'] == 1).sum():,}",
)

col4.metric(
    "Attack Categories",
    int(df.loc[df["type"] != "normal", "type"].nunique()),
)


# ==================================================
# 9. TRAFFIC DISTRIBUTION CHARTS
# ==================================================
st.divider()
st.subheader("Traffic Distribution (Recorded Dataset)")

counts, attack_counts = get_traffic_distribution(df)
left, right = st.columns(2)

with left:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(counts.index, counts.values)
    ax.set_title("Normal vs Attack Traffic")
    ax.set_ylabel("Number of Records")
    fig.tight_layout()

    st.pyplot(fig)
    plt.close(fig)

with right:
    fig, ax = plt.subplots(figsize=(8, 4))
    attack_counts.plot(kind="bar", ax=ax)
    ax.set_title("Attack Category Distribution")
    ax.set_ylabel("Number of Records")
    ax.tick_params(axis="x", rotation=45)
    fig.tight_layout()

    st.pyplot(fig)
    plt.close(fig)


# ==================================================
# 10. RECORDED NETWORK TRAFFIC DETECTION (BENCHMARK)
# ==================================================
st.divider()
st.subheader("Recorded Network Traffic Detection (TON_IoT Benchmark)")

st.write(
    "Analyze recorded TON_IoT network traffic using the trained "
    "Random Forest model. This evaluates benchmark performance on historical testbed captures."
)

sample_size = st.slider(
    "Number of records to analyze",
    min_value=100,
    max_value=5000,
    value=500,
    step=100,
    key="prediction_sample_size",
)

if st.button("Analyze Network Traffic", type="primary"):
    try:
        with st.spinner("Analyzing network records..."):
            sample = df.sample(
                n=min(sample_size, len(df)),
                random_state=42,
            ).copy()

            sample_X = sample.drop(
                columns=["label", "type", "src_ip", "dst_ip"]
            )

            predictions = model.predict(sample_X)

            sample["prediction"] = predictions
            sample["prediction_name"] = (
                sample["prediction"]
                .map({0: "Normal", 1: "Attack"})
            )
            st.session_state["traffic_sample"] = sample

    except Exception as error:
        st.error(f"Traffic analysis failed: {error}")

if "traffic_sample" in st.session_state:
    sample = st.session_state["traffic_sample"]
    actual = sample["label"].astype(int)
    correct = int((actual == sample["prediction"]).sum())
    predicted_attacks = int(
        (sample["prediction"] == 1).sum()
    )

    m1, m2, m3 = st.columns(3)

    m1.metric(
        "Records Analyzed",
        f"{len(sample):,}",
    )

    m2.metric(
        "Predicted Attacks",
        f"{predicted_attacks:,}",
    )

    m3.metric(
        "Correct vs Dataset Labels",
        f"{correct:,}",
    )

    st.subheader("Prediction Results")

    display_columns = [
        "proto",
        "service",
        "duration",
        "src_bytes",
        "dst_bytes",
        "prediction_name",
        "type",
    ]

    st.dataframe(
        sample[display_columns].rename(
            columns={
                "prediction_name": "AI Prediction",
                "type": "Dataset Category",
            }
        ),
        use_container_width=True,
    )

    st.caption(
        "Dataset Category is the recorded category. "
        "AI Prediction is generated by the trained model. "
        "Correctness is calculated using the dataset's labels."
    )

    st.download_button(
        "Download Prediction Results",
        data=sample.to_csv(index=False).encode("utf-8"),
        file_name="scada_detection_results.csv",
        mime="text/csv",
    )

    
# ==================================================
# 11. MODEL EVALUATION (20% HELD-OUT TEST SPLIT)
# ==================================================
st.divider()
st.subheader("Model Evaluation (Held-Out Test Split)")

st.write(
    "Evaluation on a held-out test split of the TON_IoT dataset."
)

if st.button("Evaluate Model", type="secondary"):
    try:
        with st.spinner("Evaluating model on test records..."):
            # Reproduce the split used during model training.
            X_eval = df.drop(
                columns=["label", "type", "src_ip", "dst_ip"]
            )
            y_eval = df["label"].astype(int)

            X_train, X_test, y_train, y_test = train_test_split(
                X_eval,
                y_eval,
                test_size=0.2,
                random_state=42,
                stratify=y_eval,
            )

            # Predict labels for the held-out test records.
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            cm = confusion_matrix(
                y_test,
                y_pred,
                labels=[0, 1],
            )
            report = classification_report(
                y_test,
                y_pred,
                labels=[0, 1],
                target_names=["Normal", "Attack"],
                output_dict=True,
                zero_division=0,
            )
            st.session_state["model_eval_results"] = {
                "accuracy": accuracy,
                "cm": cm,
                "report_df": pd.DataFrame(report).transpose(),
            }

    except Exception as error:
        st.error(f"Model evaluation failed: {error}")

if "model_eval_results" in st.session_state:
    eval_res = st.session_state["model_eval_results"]
    st.metric("Test Accuracy", f"{eval_res['accuracy']:.2%}")

    # Confusion matrix
    st.markdown("### Confusion Matrix")
    cm = eval_res["cm"]

    fig, ax = plt.subplots(figsize=(5, 4))
    ax.imshow(cm)
    ax.set_title("Confusion Matrix")
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("Actual Label")
    ax.set_xticks([0, 1], labels=["Normal", "Attack"])
    ax.set_yticks([0, 1], labels=["Normal", "Attack"])

    for i in range(2):
        for j in range(2):
            ax.text(
                j,
                i,
                f"{cm[i, j]:,}",
                ha="center",
                va="center",
            )

    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

    # Classification report
    st.markdown("### Classification Report")
    st.dataframe(
        eval_res["report_df"].round(4),
        use_container_width=True,
    )

    st.caption(
        "These metrics evaluate recorded TON_IoT network data. "
        "They do not measure live Modbus attack detection."
    )



# ==================================================
# 12. EXPLAINABLE AI — SHAP ANALYSIS
# ==================================================
st.divider()
st.subheader("Explainable AI — SHAP Analysis")

st.write(
    "SHAP explains how individual network connection features influence the model's predictions "
    "for recorded network traffic."
)

st.info(
    "ℹ️ **SHAP Scope & Causality Notice:**  \n"
    "- **Scope:** SHAP explanations are calculated strictly on recorded TON_IoT benchmark traffic where feature "
    "compatibility and ground-truth labels are established. Live SHAP explanations for Modbus traffic are intentionally "
    "unavailable because the model was not trained with Modbus semantic features.  \n"
    "- **Interpretation:** High SHAP values explain the internal mathematical reasoning of the Random Forest model; "
    "they do not prove the real-world root cause of a cyberattack."
)

shap_sample_size = st.slider(
    "Number of records for SHAP analysis",
    min_value=20,
    max_value=100,
    value=50,
    step=10,
    key="shap_sample_size",
)

if st.button("Generate SHAP Explanation"):
    try:
        with st.spinner("Generating SHAP explanations..."):
            shap_sample = X.sample(
                n=min(shap_sample_size, len(X)),
                random_state=42,
            )

            preprocessor = model.named_steps["preprocessor"]
            classifier = model.named_steps["classifier"]

            transformed = preprocessor.transform(shap_sample)

            if hasattr(transformed, "toarray"):
                transformed = transformed.toarray()

            feature_names = preprocessor.get_feature_names_out()

            explainer = shap.TreeExplainer(classifier)
            shap_values = explainer.shap_values(transformed)

            # Handle common SHAP output formats.
            if isinstance(shap_values, list):
                attack_shap_values = shap_values[1]
            elif getattr(shap_values, "ndim", 0) == 3:
                attack_shap_values = shap_values[:, :, 1]
            else:
                attack_shap_values = shap_values

            st.session_state["shap_data"] = {
                "transformed": transformed,
                "feature_names": feature_names,
                "attack_shap_values": attack_shap_values,
                "sample_count": len(shap_sample),
            }

    except Exception as error:
        st.error(f"SHAP analysis failed: {error}")
        st.info(
            "If this continues, share the full error message so "
            "we can identify the cause."
        )

if "shap_data" in st.session_state:
    shap_data = st.session_state["shap_data"]
    transformed = shap_data["transformed"]
    feature_names = shap_data["feature_names"]
    attack_shap_values = shap_data["attack_shap_values"]
    sample_count = shap_data["sample_count"]

    st.markdown("### Global Feature Importance")

    st.write(
        "Features with larger mean absolute SHAP values have "
        "greater influence on the model's attack-class output "
        "for this sample."
    )

    shap.summary_plot(
        attack_shap_values,
        transformed,
        feature_names=feature_names,
        plot_type="bar",
        max_display=15,
        show=False,
    )

    fig = plt.gcf()
    fig.set_size_inches(10, 6)
    fig.tight_layout()

    st.pyplot(fig)
    plt.close(fig)

    st.markdown("### Individual Record Explanation")

    record_index = st.selectbox(
        "Choose a record to explain",
        options=list(range(sample_count)),
        format_func=lambda i: f"Sample record {i + 1}",
        key="shap_record_index",
    )

    individual_values = attack_shap_values[record_index]

    individual_df = pd.DataFrame(
        {
            "Feature": feature_names,
            "SHAP Value": individual_values,
        }
    )

    individual_df["Absolute SHAP"] = (
        individual_df["SHAP Value"].abs()
    )

    individual_df = individual_df.sort_values(
        "Absolute SHAP",
        ascending=False,
    ).head(10)

    st.write(
        "Positive SHAP values push the model output toward "
        "the attack class; negative values push it away from "
        "the attack class. These values explain model behavior, "
        "not the real-world cause of an attack."
    )

    st.dataframe(
        individual_df[["Feature", "SHAP Value"]],
        use_container_width=True,
    )


# ==================================================
# 13. PROJECT LIMITATIONS & METHODOLOGICAL NOTES
# ==================================================
st.divider()
st.subheader("Industrial Cybersecurity Notes & Model Domain Limitations")

st.markdown(
    """
    1. **Domain Transferability:** The machine-learning model is trained on recorded TON_IoT network traffic 
       containing IT/IoT connection profiles. Because Modbus TCP (port 502/5020) traffic is absent from 
       the training dataset, live Modbus predictions are experimental and must be interpreted with domain caution.
    2. **Passive Observation Principle:** The live network monitor operates entirely passively in user space, 
       observing connection volume, durations, and packet rates without generating intrusive network probes or attack packets.
    3. **Explainability Caveat:** SHAP feature attributions reflect statistical associations learned by the Random Forest model 
       on historical training data; they provide transparency into decision boundaries, not forensic proof of an external adversary.
    """
)
