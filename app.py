
import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="SCADA RTU-MTU Simulation",
    page_icon="🏭",
    layout="wide"
)

st.title("SCADA Monitoring System")
st.write("RTU-to-MTU Communication Simulation")

# Load sensor dataset
dataset_path = (
    Path(__file__).parent
    / "datasets"
    / "scada_sensor_dataset_200_rows.csv"
)

if not dataset_path.exists():
    st.error(f"Dataset not found: {dataset_path}")
    st.stop()

df = pd.read_csv(dataset_path)
df["timestamp"] = pd.to_datetime(df["timestamp"])

# RTU: Read one record from the sensor dataset
def rtu_read_sensor(row):
    return {
        "timestamp": str(row["timestamp"]),
        "temperature_c": float(row["temperature_c"]),
        "pressure_bar": float(row["pressure_bar"]),
        "water_level_mm": float(row["water_level_mm"]),
        "flow_rate_lpm": float(row["flow_rate_lpm"]),
        "rtu_id": str(row["rtu_id"])
    }

# MTU: Receive the data sent by the RTU
def mtu_receive_data(message):
    return message

# Store simulation progress
if "reading_index" not in st.session_state:
    st.session_state.reading_index = 0

if "received_data" not in st.session_state:
    st.session_state.received_data = None

st.subheader("Communication Status")

col1, col2 = st.columns(2)
col1.metric("RTU Status", "Ready")
col2.metric(
    "MTU Status",
    "Data received" if st.session_state.received_data
    else "Waiting"
)

st.info(
    "Simulation mode: RTU reads a CSV record "
    "and passes it to the MTU inside this application."
)

# Send the next reading
if st.button("Send Next Reading: RTU → MTU"):
    index = st.session_state.reading_index

    # RTU reads sensor data
    message = rtu_read_sensor(df.iloc[index])

    # MTU receives the simulated message
    st.session_state.received_data = mtu_receive_data(message)

    # Move to the next CSV record
    st.session_state.reading_index = (index + 1) % len(df)

# Display the received message
data = st.session_state.received_data

if data is not None:
    st.subheader("MTU: Received Sensor Data")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Temperature", f"{data['temperature_c']} °C")
    col2.metric("Pressure", f"{data['pressure_bar']} bar")
    col3.metric("Water Level", f"{data['water_level_mm']} mm")
    col4.metric("Flow Rate", f"{data['flow_rate_lpm']} L/min")

    st.write("Timestamp:", data["timestamp"])
    st.write("Received from RTU:", data["rtu_id"])

    st.success("MTU received the simulated sensor message.")

    with st.expander("View complete received message"):
        st.json(data)
else:
    st.warning("Click the button to send the first reading.")

st.caption(
    "This is a software simulation, not real network communication."
)
